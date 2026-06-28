"""Batch data-access repository.

Phase 0: wraps the existing Redis access for ``batch:*`` hashes, the global
``recent_batches`` sorted set, and the per-user batch index — verbatim, no
behaviour change. Later phases swap the internals for Postgres.
"""
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any

from app.config import get_redis_client, settings
from app import ownership
from app.db.dual_write import upsert_batch

RECENT_BATCHES_KEY = "recent_batches"
MAX_RECENT_BATCHES = 2000


class BatchRepository:
    """All access to batch records goes through here."""

    def __init__(self, redis_client=None):
        self.r = redis_client if redis_client is not None else get_redis_client()

    @staticmethod
    def _key(batch_id: str) -> str:
        return f"batch:{batch_id}"

    # ---- reads -------------------------------------------------------
    def get(self, batch_id: str) -> Dict[str, Any]:
        """Return the batch hash, or an empty dict if it doesn't exist."""
        return self.r.hgetall(self._key(batch_id))

    def recent_ids(self, limit: Optional[int] = None) -> List[str]:
        """Global recent batch ids (admin view), newest-first."""
        end = (limit - 1) if limit else -1
        return self.r.zrevrange(RECENT_BATCHES_KEY, 0, end)

    def user_ids(self, username: str, limit: Optional[int] = None) -> List[str]:
        """Batch ids owned by ``username`` (per-user index), newest-first."""
        return ownership.user_batch_ids(self.r, username, limit)

    def visible_ids(self, user, limit: Optional[int] = None) -> List[str]:
        """Batch ids visible to ``user`` — admin sees global recent, others
        see only their own (the Phase-1 tenancy rule)."""
        if getattr(user, "role", None) == "admin":
            return self.recent_ids(limit)
        return self.user_ids(user.username, limit)

    # ---- writes ------------------------------------------------------
    def create(self, batch_id: str, mapping: Dict[str, Any], ttl: Optional[int] = None) -> None:
        """Write a batch record (hash) and optionally set its TTL."""
        self.r.hset(self._key(batch_id), mapping=mapping)
        if ttl is not None:
            self.r.expire(self._key(batch_id), ttl)
        self._dual_write(batch_id)

    def save(self, batch_id: str, mapping: Dict[str, Any]) -> None:
        """Merge fields into an existing batch record, leaving TTL intact."""
        self.r.hset(self._key(batch_id), mapping=mapping)
        self._dual_write(batch_id)

    def _dual_write(self, batch_id: str) -> None:
        """Phase 2: mirror the full current batch record into Postgres (best-effort).

        Reads the source straight from Redis (NOT self.get(), which may now read
        from Postgres) — Redis is authoritative and is what we're mirroring."""
        if settings.DATABASE_URL:
            upsert_batch(batch_id, self.r.hgetall(self._key(batch_id)))

    def record_owner(self, batch_id: str, username: str, ts: Optional[float] = None) -> None:
        """Add the batch to the owner's per-user index (tenancy)."""
        ownership.record_batch_owner(self.r, batch_id, username, ts)

    def mark_recent(self, batch_id: str, ts: Optional[float] = None,
                    cap: int = MAX_RECENT_BATCHES) -> None:
        """Add the batch to the global recent set, capped to the newest ``cap``."""
        if ts is None:
            ts = datetime.now(timezone.utc).timestamp()
        self.r.zadd(RECENT_BATCHES_KEY, {batch_id: ts})
        self.r.zremrangebyrank(RECENT_BATCHES_KEY, 0, -(cap + 1))
