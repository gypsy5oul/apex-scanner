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

    def image_names_for(self, scan_ids: List[str]) -> List[str]:
        """Batch-fetch ``image_name`` for the given scan ids (skips missing)."""
        if not scan_ids:
            return []
        pipe = self.r.pipeline()
        for sid in scan_ids:
            pipe.hget(sid, "image_name")
        return [name for name in pipe.execute() if name]
