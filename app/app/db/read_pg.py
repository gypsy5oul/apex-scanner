"""Phase 3 reads — fetch records back from Postgres (sync, best-effort).

Returns the ``detail`` JSONB, which the dual-write stored as the *exact* Redis
hash (all string values), so callers get the same shape as ``hgetall``. Returns
None on miss/error so the repository can fall back to Redis during the flip.
"""
from typing import Optional, Dict, Any

from app.config import settings
from app.logging_config import get_logger

logger = get_logger(__name__)


def read_scan_detail(scan_id: str) -> Optional[Dict[str, Any]]:
    if not settings.DATABASE_URL:
        return None
    try:
        from sqlalchemy import select
        from app.db.sync_engine import get_sync_session
        from app.db.models import Scan
        Session = get_sync_session()
        if Session is None:
            return None
        with Session() as s:
            return s.execute(select(Scan.detail).where(Scan.id == scan_id)).scalar_one_or_none()
    except Exception as e:
        logger.debug("PG read (scan) failed", scan_id=scan_id, error=str(e))
        return None
