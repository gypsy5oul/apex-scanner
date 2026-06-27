"""Per-user scan ownership — tagging + per-user indexes for tenancy.

A regular user sees only scans they created; admins see everything. Scans are
stamped with ``created_by`` and added to a per-user sorted-set index so listing
a user's scans is O(their scans) rather than a full keyspace scan.
"""
import time
from typing import List, Optional

from app.config import settings

OWNER_FIELD = "created_by"
USER_SCANS_PREFIX = "user_scans:"
USER_BATCHES_PREFIX = "user_batches:"
MAX_PER_USER = 2000


def _record(redis_client, prefix: str, member: str, username: str, ts: Optional[float]) -> None:
    if not username:
        return
    score = ts if ts is not None else time.time()
    key = f"{prefix}{username}"
    pipe = redis_client.pipeline()
    pipe.zadd(key, {member: score})
    pipe.zremrangebyrank(key, 0, -(MAX_PER_USER + 1))
    pipe.expire(key, settings.SCAN_RESULT_TTL)
    pipe.execute()


def _list(redis_client, prefix: str, username: str, limit: Optional[int]) -> List[str]:
    if not username:
        return []
    end = (limit - 1) if limit else -1
    return redis_client.zrevrange(f"{prefix}{username}", 0, end)


def record_scan_owner(redis_client, scan_id: str, username: str, ts: Optional[float] = None) -> None:
    """Add a scan to its owner's per-user index."""
    _record(redis_client, USER_SCANS_PREFIX, scan_id, username, ts)


def record_batch_owner(redis_client, batch_id: str, username: str, ts: Optional[float] = None) -> None:
    """Add a batch to its owner's per-user index."""
    _record(redis_client, USER_BATCHES_PREFIX, batch_id, username, ts)


def user_scan_ids(redis_client, username: str, limit: Optional[int] = None) -> List[str]:
    """Scan IDs owned by ``username``, newest first."""
    return _list(redis_client, USER_SCANS_PREFIX, username, limit)


def user_batch_ids(redis_client, username: str, limit: Optional[int] = None) -> List[str]:
    """Batch IDs owned by ``username``, newest first."""
    return _list(redis_client, USER_BATCHES_PREFIX, username, limit)
