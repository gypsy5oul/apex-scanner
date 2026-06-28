"""Scan data-access repository.

Phase 0: wraps the existing Redis access verbatim (no behaviour change) so
callers stop touching ``redis_client`` directly. Later phases swap the
internals for Postgres without changing any caller.
"""
from typing import List, Optional, Dict, Any

from app.config import get_redis_client
from app.trends import scan_redis_keys
from app import ownership


class ScanRepository:
    """All read access to scan records goes through here."""

    def __init__(self, redis_client=None):
        self.r = redis_client if redis_client is not None else get_redis_client()

    # ---- single scan -------------------------------------------------
    def get(self, scan_id: str) -> Dict[str, Any]:
        """Return the scan hash, or an empty dict if it doesn't exist."""
        return self.r.hgetall(scan_id)

    def exists(self, scan_id: str) -> bool:
        return bool(self.r.exists(scan_id))

    def get_many(self, scan_ids: List[str]) -> List[Dict[str, Any]]:
        """Batch-fetch scan hashes for the given ids (parallel to scan_ids,
        empty dict for any that are missing)."""
        if not scan_ids:
            return []
        pipe = self.r.pipeline()
        for sid in scan_ids:
            pipe.hgetall(sid)
        return pipe.execute()

    # ---- recent / visibility (per-user tenancy) ----------------------
    def recent_ids(self, limit: int = 100) -> List[str]:
        """Global recent scan ids (admin view), newest-first.

        Wraps the prior ``get_recent_scan_ids``: sorted-set first, falling
        back to scanning ``history:*`` keys when the set isn't populated.
        """
        recent = self.r.zrevrange("recent_scans", 0, limit - 1)
        if recent:
            return recent
        ids: List[str] = []
        for key in scan_redis_keys(self.r, "history:*", count=200)[: limit * 2]:
            ids.extend(self.r.lrange(key, 0, 2))
        return ids

    def user_ids(self, username: str, limit: Optional[int] = None) -> List[str]:
        """Scan ids owned by ``username`` (per-user index), newest-first."""
        return ownership.user_scan_ids(self.r, username, limit)

    def owned_id_set(self, username: str) -> set:
        """Set of scan ids owned by ``username`` (for membership checks)."""
        return set(ownership.user_scan_ids(self.r, username))

    def all_recent_history_ids(self) -> List[str]:
        """Admin 'recent scans' source: the 3 newest ids from every
        ``history:*`` list, flattened (verbatim wrap of the prior admin path)."""
        ids: List[str] = []
        for key in scan_redis_keys(self.r, "history:*", count=200):
            ids.extend(self.r.lrange(key, 0, 2))
        return ids

    def visible_ids(self, user, limit: int = 100) -> List[str]:
        """Scan ids visible to ``user`` — admin sees global recent, others
        see only their own (the Phase-1 tenancy rule)."""
        if getattr(user, "role", None) == "admin":
            return self.recent_ids(limit)
        return self.user_ids(user.username, limit * 3)

    # ---- history -----------------------------------------------------
    def image_history_ids(self, image_name: str, limit: int = 50) -> List[str]:
        return self.r.lrange(f"history:{image_name}", 0, limit - 1)

    # ---- stats -------------------------------------------------------
    def unique_image_count(self) -> int:
        """Number of distinct images scanned (one ``history:*`` key each)."""
        return len(scan_redis_keys(self.r, "history:*", count=200))

    def get_status(self, scan_id: str) -> Optional[str]:
        return self.r.hget(scan_id, "status")

    # ---- writes ------------------------------------------------------
    def create(self, scan_id: str, mapping: Dict[str, Any], ttl: Optional[int] = None) -> None:
        """Write a scan record (hash) and optionally set its TTL."""
        self.r.hset(scan_id, mapping=mapping)
        if ttl is not None:
            self.r.expire(scan_id, ttl)

    def save(self, scan_id: str, mapping: Dict[str, Any]) -> None:
        """Merge fields into an existing scan record (hash), leaving TTL intact."""
        self.r.hset(scan_id, mapping=mapping)

    def set_status(self, scan_id: str, status: str, error: Optional[str] = None) -> None:
        """Set a scan's status (and optional error) — used for failure markers."""
        mapping: Dict[str, Any] = {"status": status}
        if error is not None:
            mapping["error"] = error
        self.r.hset(scan_id, mapping=mapping)

    def record_owner(self, scan_id: str, username: str, ts: Optional[float] = None) -> None:
        """Add the scan to the owner's per-user index (tenancy)."""
        ownership.record_scan_owner(self.r, scan_id, username, ts)

    def add_to_history(self, image_name: str, scan_id: str, max_len: int, ttl: int) -> None:
        """Push the scan onto the image's history list (capped + TTL'd)."""
        key = f"history:{image_name}"
        self.r.lpush(key, scan_id)
        self.r.ltrim(key, 0, max_len - 1)
        self.r.expire(key, ttl)

    # ---- stats helpers ----------------------------------------------
    def image_names_for(self, scan_ids: List[str]) -> List[str]:
        """Batch-fetch ``image_name`` for the given scan ids (skips missing)."""
        if not scan_ids:
            return []
        pipe = self.r.pipeline()
        for sid in scan_ids:
            pipe.hget(sid, "image_name")
        return [name for name in pipe.execute() if name]
