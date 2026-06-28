"""Phase 2 dual-write: mirror Redis writes into Postgres (best-effort).

Redis stays authoritative in Phase 2 — every function here is a no-op when
``DATABASE_URL`` is unset, and any failure is swallowed (logged at debug) so a
Postgres hiccup can never break the live Redis-backed write path. The mappers
(``*_row``) are pure and unit-tested; the ``upsert_*`` functions do the I/O.
"""
import json
from datetime import datetime
from typing import Optional, Dict, Any, List

from app.config import settings
from app.logging_config import get_logger

logger = get_logger(__name__)


# ---- coercion helpers -------------------------------------------------
def _int(v, default: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _float(v) -> Optional[float]:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _bool(v) -> bool:
    return str(v).lower() in ("1", "true", "yes")


def _dt(v) -> Optional[datetime]:
    if not v:
        return None
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError:
        return None


def _json(v, default):
    if v is None:
        return default
    if isinstance(v, (list, dict)):
        return v
    try:
        return json.loads(v)
    except (TypeError, ValueError):
        return default


# ---- pure mappers (Redis shape -> table columns) ----------------------
def scan_row(scan_id: str, h: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": scan_id,
        "image_name": h.get("image_name"),
        "status": h.get("status"),
        "created_by": h.get("created_by"),
        "created_at": _dt(h.get("created_at")),
        "scan_timestamp": _dt(h.get("scan_timestamp")),
        "critical": _int(h.get("critical")),
        "high": _int(h.get("high")),
        "medium": _int(h.get("medium")),
        "low": _int(h.get("low")),
        "negligible": _int(h.get("negligible")),
        "unknown": _int(h.get("unknown")),
        "total_packages": _int(h.get("total_packages")),
        "total_secrets": _int(h.get("total_secrets")),
        "report_url": h.get("report_url") or None,
        "sbom_report_url": h.get("sbom_report_url") or None,
        "image_digest": h.get("image_digest"),
        "scan_quality": h.get("scan_quality"),
        "batch_id": h.get("batch_id"),
        "detail": h,
    }


def batch_row(batch_id: str, h: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": batch_id,
        "created_by": h.get("created_by"),
        "created_at": _dt(h.get("created_at")),
        "total_images": _int(h.get("total_images")),
        "status": h.get("status"),
        "image_list": _json(h.get("images"), []),
    }


def license_row(scan_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "scan_id": scan_id,
        "status": data.get("status"),
        "data": data,
    }


def vuln_row(scan_id: str, v: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "scan_id": scan_id,
        "cve_id": (v.get("id") or v.get("cve_id") or None),
        "severity": v.get("severity"),
        "package_name": v.get("package_name") or v.get("package"),
        "package_version": v.get("package_version") or v.get("version"),
        "cvss_score": _float(v.get("cvss_score")),
        "epss_score": _float(v.get("epss_score") or v.get("epss")),
        "in_kev": _bool(v.get("in_kev") or v.get("kev")),
        # fixed_version is a version string — its presence means a fix exists.
        "fix_available": _bool(v.get("fix_available")) or bool(v.get("fixed_version")),
        "data": v,
    }


# ---- best-effort upserts ----------------------------------------------
def _session():
    """Return a sync Session class, or None if DB unavailable/unconfigured."""
    if not settings.DATABASE_URL:
        return None
    from app.db.sync_engine import get_sync_session
    return get_sync_session()


def upsert_scan(scan_id: str, h: Optional[Dict[str, Any]]) -> None:
    if not settings.DATABASE_URL or not h:
        return
    try:
        from app.db.models import Scan
        from sqlalchemy.dialects.postgresql import insert
        Session = _session()
        if Session is None:
            return
        row = scan_row(scan_id, h)
        stmt = insert(Scan).values(**row)
        stmt = stmt.on_conflict_do_update(
            index_elements=["id"],
            set_={k: stmt.excluded[k] for k in row if k != "id"},
        )
        with Session() as s:
            s.execute(stmt)
            s.commit()
    except Exception as e:
        logger.debug("PG dual-write (scan) skipped/failed", scan_id=scan_id, error=str(e))


def upsert_batch(batch_id: str, h: Optional[Dict[str, Any]]) -> None:
    if not settings.DATABASE_URL or not h:
        return
    try:
        from app.db.models import Batch
        from sqlalchemy.dialects.postgresql import insert
        Session = _session()
        if Session is None:
            return
        row = batch_row(batch_id, h)
        stmt = insert(Batch).values(**row)
        stmt = stmt.on_conflict_do_update(
            index_elements=["id"],
            set_={k: stmt.excluded[k] for k in row if k != "id"},
        )
        with Session() as s:
            s.execute(stmt)
            s.commit()
    except Exception as e:
        logger.debug("PG dual-write (batch) skipped/failed", batch_id=batch_id, error=str(e))


def upsert_license(scan_id: str, data: Optional[Dict[str, Any]]) -> None:
    if not settings.DATABASE_URL or not data:
        return
    try:
        from app.db.models import License
        from sqlalchemy.dialects.postgresql import insert
        Session = _session()
        if Session is None:
            return
        row = license_row(scan_id, data)
        stmt = insert(License).values(**row)
        stmt = stmt.on_conflict_do_update(
            index_elements=["scan_id"],
            set_={k: stmt.excluded[k] for k in row if k != "scan_id"},
        )
        with Session() as s:
            s.execute(stmt)
            s.commit()
    except Exception as e:
        logger.debug("PG dual-write (license) skipped/failed", scan_id=scan_id, error=str(e))


def upsert_vulns(scan_id: str, vulns: Optional[List[Dict[str, Any]]]) -> None:
    """Replace the scan's vulnerability rows (delete + bulk insert)."""
    if not settings.DATABASE_URL or vulns is None:
        return
    try:
        from app.db.models import Vulnerability
        from sqlalchemy import delete
        Session = _session()
        if Session is None:
            return
        rows = [vuln_row(scan_id, v) for v in vulns if isinstance(v, dict)]
        with Session() as s:
            s.execute(delete(Vulnerability).where(Vulnerability.scan_id == scan_id))
            if rows:
                s.execute(Vulnerability.__table__.insert(), rows)
            s.commit()
    except Exception as e:
        logger.debug("PG dual-write (vulns) skipped/failed", scan_id=scan_id, error=str(e))
