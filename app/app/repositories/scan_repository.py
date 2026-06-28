"""Scan data-access repository.

Phase 0: wraps the existing Redis access verbatim (no behaviour change) so
callers stop touching ``redis_client`` directly. Later phases swap the
internals for Postgres without changing any caller.
"""
from typing import List, Optional, Dict, Any

from app.config import get_redis_client, settings
from app.trends import scan_redis_keys
from app import ownership
from app.db.dual_write import upsert_scan


class ScanRepository:
    """All read access to scan records goes through here."""

    def __init__(self, redis_client=None):
        self.r = redis_client if redis_client is not None else get_redis_client()

    def _pg(self) -> bool:
        """Phase 3: read from Postgres (with Redis fallback) when enabled."""
        return bool(settings.DATABASE_URL and settings.READ_FROM_POSTGRES)

    # ---- single scan -------------------------------------------------
    def get(self, scan_id: str) -> Dict[str, Any]:
        """Return the scan hash, or an empty dict if it doesn't exist.

        Phase 3: when READ_FROM_POSTGRES is on, read from Postgres (the dual-write
        mirror) and fall back to Redis on a miss. Redis stays the safety net."""
        if self._pg():
            from app.db.read_pg import read_scan_detail
            detail = read_scan_detail(scan_id)
            if detail:
                return detail
        return self.r.hgetall(scan_id)

    def exists(self, scan_id: str) -> bool:
        if self._pg():
            from app.db.read_pg import read_scan_exists
            e = read_scan_exists(scan_id)
            if e is not None:
                return e
        return bool(self.r.exists(scan_id))

    def get_many(self, scan_ids: List[str]) -> List[Dict[str, Any]]:
        """Batch-fetch scan hashes for the given ids (parallel to scan_ids,
        empty dict for any that are missing)."""
        if not scan_ids:
            return []
        if self._pg():
            from app.db.read_pg import read_scans_details
            m = read_scans_details(scan_ids)
            if m is not None:
                return [m.get(sid, {}) for sid in scan_ids]
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
        if self._pg():
            from app.db.read_pg import read_recent_scan_ids
            ids = read_recent_scan_ids(limit)
            if ids is not None:
                return ids
        recent = self.r.zrevrange("recent_scans", 0, limit - 1)
        if recent:
            return recent
        ids: List[str] = []
        for key in scan_redis_keys(self.r, "history:*", count=200)[: limit * 2]:
            ids.extend(self.r.lrange(key, 0, 2))
        return ids

    def user_ids(self, username: str, limit: Optional[int] = None) -> List[str]:
        """Scan ids owned by ``username`` (per-user index), newest-first."""
        if self._pg():
            from app.db.read_pg import read_user_scan_ids
            ids = read_user_scan_ids(username, limit)
            if ids is not None:
                return ids
        return ownership.user_scan_ids(self.r, username, limit)

    def owned_id_set(self, username: str) -> set:
        """Set of scan ids owned by ``username`` (for membership checks)."""
        if self._pg():
            from app.db.read_pg import read_user_scan_id_set
            ids = read_user_scan_id_set(username)
            if ids is not None:
                return ids
        return set(ownership.user_scan_ids(self.r, username))

    def all_recent_history_ids(self) -> List[str]:
        """Admin 'recent scans' source: the 3 newest ids from every
        ``history:*`` list, flattened (verbatim wrap of the prior admin path)."""
        if self._pg():
            from app.db.read_pg import read_recent_per_image_ids
            ids = read_recent_per_image_ids()
            if ids is not None:
                return ids
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
        if self._pg():
            from app.db.read_pg import read_image_history_ids
            ids = read_image_history_ids(image_name, limit)
            if ids is not None:
                return ids
        return self.r.lrange(f"history:{image_name}", 0, limit - 1)

    # ---- stats -------------------------------------------------------
    def unique_image_count(self) -> int:
        """Number of distinct images scanned (one ``history:*`` key each)."""
        if self._pg():
            from app.db.read_pg import read_unique_image_count
            n = read_unique_image_count()
            if n is not None:
                return n
        return len(scan_redis_keys(self.r, "history:*", count=200))

    def get_status(self, scan_id: str) -> Optional[str]:
        if self._pg():
            from app.db.read_pg import read_scan_status
            st = read_scan_status(scan_id)
            if st is not None:
                return st
        return self.r.hget(scan_id, "status")

    # ---- writes ------------------------------------------------------
    @staticmethod
    def _write_redis() -> bool:
        """Phase 4: when false, durable data is written to Postgres only."""
        return settings.WRITE_TO_REDIS

    @staticmethod
    def _strshape(mapping: Dict[str, Any]) -> Dict[str, Any]:
        """Coerce to the all-string shape Redis hgetall would return, so the PG
        ``detail`` mirror is identical whether written via Redis or PG-only."""
        return {k: ("" if v is None else str(v)) for k, v in mapping.items()}

    def create(self, scan_id: str, mapping: Dict[str, Any], ttl: Optional[int] = None) -> None:
        """Write a scan record (hash) and optionally set its TTL."""
        if self._write_redis():
            self.r.hset(scan_id, mapping=mapping)
            if ttl is not None:
                self.r.expire(scan_id, ttl)
        self._persist(scan_id, mapping, full=True)

    def save(self, scan_id: str, mapping: Dict[str, Any]) -> None:
        """Merge fields into an existing scan record (hash), leaving TTL intact."""
        if self._write_redis():
            self.r.hset(scan_id, mapping=mapping)
        self._persist(scan_id, mapping, full=False)

    def set_status(self, scan_id: str, status: str, error: Optional[str] = None) -> None:
        """Set a scan's status (and optional error) — used for failure markers."""
        mapping: Dict[str, Any] = {"status": status}
        if error is not None:
            mapping["error"] = error
        if self._write_redis():
            self.r.hset(scan_id, mapping=mapping)
        self._persist(scan_id, mapping, full=False)

    def _persist(self, scan_id: str, mapping: Dict[str, Any], full: bool) -> None:
        """Mirror the scan into Postgres. In dual-write mode the merged state is
        read back from Redis (authoritative); in PG-only mode it's merged against
        the existing PG row so partial updates don't lose fields."""
        if not settings.DATABASE_URL:
            return
        if self._write_redis():
            upsert_scan(scan_id, self.r.hgetall(scan_id))
        elif full:
            upsert_scan(scan_id, self._strshape(mapping))
        else:
            from app.db.read_pg import read_scan_detail
            existing = read_scan_detail(scan_id) or {}
            upsert_scan(scan_id, {**existing, **self._strshape(mapping)})

    def record_owner(self, scan_id: str, username: str, ts: Optional[float] = None) -> None:
        """Add the scan to the owner's per-user index (tenancy).

        PG-only mode skips this — ``created_by`` lives on the scan record and the
        per-user view is a SQL ``WHERE created_by=`` query."""
        if self._write_redis():
            ownership.record_scan_owner(self.r, scan_id, username, ts)

    def add_to_history(self, image_name: str, scan_id: str, max_len: int,
                       ttl: Optional[int] = None) -> None:
        """Push the scan onto the image's history list (capped; TTL optional).

        PG-only mode skips this — history is a SQL ``WHERE image_name=`` query."""
        if not self._write_redis():
            return
        key = f"history:{image_name}"
        self.r.lpush(key, scan_id)
        self.r.ltrim(key, 0, max_len - 1)
        if ttl is not None:
            self.r.expire(key, ttl)

    # ---- stats helpers ----------------------------------------------
    def image_names_for(self, scan_ids: List[str]) -> List[str]:
        """Batch-fetch ``image_name`` for the given scan ids (skips missing)."""
        if not scan_ids:
            return []
        if self._pg():
            from app.db.read_pg import read_image_names_for
            names = read_image_names_for(scan_ids)
            if names is not None:
                return names
        pipe = self.r.pipeline()
        for sid in scan_ids:
            pipe.hget(sid, "image_name")
        return [name for name in pipe.execute() if name]
