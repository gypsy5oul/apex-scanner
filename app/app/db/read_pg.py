"""Phase 3 reads — fetch records back from Postgres (sync, best-effort).

Returns the ``detail`` JSONB, which the dual-write stored as the *exact* Redis
hash (all string values), so callers get the same shape as ``hgetall``. Returns
None on miss/error so the repository can fall back to Redis during the flip.
"""
from typing import Optional, Dict, Any, List

from app.config import settings
from app.logging_config import get_logger

logger = get_logger(__name__)


def _run(fn):
    """Run ``fn(session)`` against Postgres; return None if unavailable/error.

    None means 'fall back to Redis'. An empty list/dict returned by ``fn`` is a
    valid result (e.g. a user with no scans) and is NOT treated as a fallback.
    """
    if not settings.DATABASE_URL:
        return None
    try:
        from app.db.sync_engine import get_sync_session
        Session = get_sync_session()
        if Session is None:
            return None
        with Session() as s:
            return fn(s)
    except Exception as e:
        logger.debug("PG read failed", error=str(e))
        return None


# ---- scans ------------------------------------------------------------
def read_scan_detail(scan_id: str) -> Optional[Dict[str, Any]]:
    def q(s):
        from sqlalchemy import select
        from app.db.models import Scan
        return s.execute(select(Scan.detail).where(Scan.id == scan_id)).scalar_one_or_none()
    return _run(q)


def read_scans_details(scan_ids) -> Optional[Dict[str, Dict[str, Any]]]:
    """Map scan_id -> detail for the given ids (missing ids simply absent)."""
    ids = list(scan_ids)
    if not ids:
        return {}
    def q(s):
        from sqlalchemy import select
        from app.db.models import Scan
        rows = s.execute(select(Scan.id, Scan.detail).where(Scan.id.in_(ids))).all()
        return {r[0]: r[1] for r in rows}
    return _run(q)


def _order_recent():
    from sqlalchemy import func
    from app.db.models import Scan
    return func.coalesce(Scan.scan_timestamp, Scan.created_at).desc().nullslast()


def read_recent_scan_ids(limit: int) -> Optional[List[str]]:
    def q(s):
        from sqlalchemy import select
        from app.db.models import Scan
        return [r[0] for r in s.execute(select(Scan.id).order_by(_order_recent()).limit(limit)).all()]
    return _run(q)


def read_user_scan_ids(username: str, limit: Optional[int]) -> Optional[List[str]]:
    def q(s):
        from sqlalchemy import select
        from app.db.models import Scan
        stmt = select(Scan.id).where(Scan.created_by == username).order_by(_order_recent())
        if limit:
            stmt = stmt.limit(limit)
        return [r[0] for r in s.execute(stmt).all()]
    return _run(q)


def read_user_scan_id_set(username: str) -> Optional[set]:
    ids = read_user_scan_ids(username, None)
    return set(ids) if ids is not None else None


def read_recent_per_image_ids() -> Optional[List[str]]:
    """The 3 newest scan ids per image (admin recent-scans source)."""
    def q(s):
        from sqlalchemy import select, func
        from app.db.models import Scan
        rn = func.row_number().over(
            partition_by=Scan.image_name, order_by=_order_recent()
        ).label("rn")
        sub = select(Scan.id, rn).subquery()
        return [r[0] for r in s.execute(select(sub.c.id).where(sub.c.rn <= 3)).all()]
    return _run(q)


def read_image_history_ids(image_name: str, limit: int) -> Optional[List[str]]:
    def q(s):
        from sqlalchemy import select
        from app.db.models import Scan
        stmt = select(Scan.id).where(Scan.image_name == image_name).order_by(_order_recent()).limit(limit)
        return [r[0] for r in s.execute(stmt).all()]
    return _run(q)


def read_unique_image_count() -> Optional[int]:
    def q(s):
        from sqlalchemy import select, func
        from app.db.models import Scan
        return s.execute(select(func.count(func.distinct(Scan.image_name)))).scalar_one()
    return _run(q)


def read_image_names_for(scan_ids) -> Optional[List[str]]:
    ids = list(scan_ids)
    if not ids:
        return []
    def q(s):
        from sqlalchemy import select
        from app.db.models import Scan
        rows = s.execute(select(Scan.image_name).where(Scan.id.in_(ids), Scan.image_name.isnot(None))).all()
        return [r[0] for r in rows]
    return _run(q)


# ---- vulnerabilities --------------------------------------------------
def read_vulns_list(scan_id: str) -> Optional[List[Dict[str, Any]]]:
    """Reconstruct the original vuln list from the normalized rows (in order)."""
    def q(s):
        from sqlalchemy import select
        from app.db.models import Vulnerability
        rows = s.execute(
            select(Vulnerability.data).where(Vulnerability.scan_id == scan_id).order_by(Vulnerability.id)
        ).all()
        return [r[0] for r in rows]
    return _run(q)


def read_cve_scan_ids(cve_id: str) -> Optional[set]:
    def q(s):
        from sqlalchemy import select
        from app.db.models import Vulnerability
        rows = s.execute(
            select(Vulnerability.scan_id).where(Vulnerability.cve_id == cve_id.upper()).distinct()
        ).all()
        return {r[0] for r in rows}
    return _run(q)


def read_all_vuln_scan_ids() -> Optional[List[str]]:
    def q(s):
        from sqlalchemy import select
        from app.db.models import Vulnerability
        rows = s.execute(select(Vulnerability.scan_id).distinct()).all()
        return [r[0] for r in rows]
    return _run(q)


# ---- batches ----------------------------------------------------------
def read_batch_detail(batch_id: str) -> Optional[Dict[str, Any]]:
    def q(s):
        from sqlalchemy import select
        from app.db.models import Batch
        return s.execute(select(Batch.detail).where(Batch.id == batch_id)).scalar_one_or_none()
    return _run(q)


def _order_batch():
    from sqlalchemy.sql import desc, nullslast
    from app.db.models import Batch
    return nullslast(desc(Batch.created_at))


def read_recent_batch_ids(limit: Optional[int]) -> Optional[List[str]]:
    def q(s):
        from sqlalchemy import select
        from app.db.models import Batch
        stmt = select(Batch.id).order_by(_order_batch())
        if limit:
            stmt = stmt.limit(limit)
        return [r[0] for r in s.execute(stmt).all()]
    return _run(q)


def read_user_batch_ids(username: str, limit: Optional[int]) -> Optional[List[str]]:
    def q(s):
        from sqlalchemy import select
        from app.db.models import Batch
        stmt = select(Batch.id).where(Batch.created_by == username).order_by(_order_batch())
        if limit:
            stmt = stmt.limit(limit)
        return [r[0] for r in s.execute(stmt).all()]
    return _run(q)


# ---- licenses ---------------------------------------------------------
def read_license_data(scan_id: str) -> Optional[Dict[str, Any]]:
    def q(s):
        from sqlalchemy import select
        from app.db.models import License
        return s.execute(select(License.data).where(License.scan_id == scan_id)).scalar_one_or_none()
    return _run(q)
