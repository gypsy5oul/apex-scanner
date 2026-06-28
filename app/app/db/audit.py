"""Audit log (Phase 4) — append-only record of who did what.

Writes to the Postgres ``audit_log`` table (there is no Redis equivalent — this
is a new durable capability the migration unlocks). Best-effort: a DB hiccup is
logged at debug and never breaks the action being audited.
"""
from datetime import datetime, timezone
from typing import Optional, Dict, Any

from app.config import settings
from app.logging_config import get_logger

logger = get_logger(__name__)


def record_audit(actor: Optional[str], action: str, target: Optional[str] = None,
                 detail: Optional[Dict[str, Any]] = None, ip: Optional[str] = None) -> None:
    if not settings.DATABASE_URL:
        return
    try:
        from app.db.sync_engine import get_sync_session
        from app.db.models import AuditLog
        Session = get_sync_session()
        if Session is None:
            return
        with Session() as s:
            s.add(AuditLog(
                ts=datetime.now(timezone.utc),
                actor=actor, action=action, target=target,
                ip=ip, detail=detail or {},
            ))
            s.commit()
    except Exception as e:
        logger.debug("audit write failed", action=action, error=str(e))


def client_ip(request) -> Optional[str]:
    """Best-effort client IP from a FastAPI/Starlette request (edge-aware)."""
    try:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()
        return request.client.host if request.client else None
    except Exception:
        return None
