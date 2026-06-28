"""License-compliance data-access repository.

Phase 0: wraps the per-scan ``licenses:<scan_id>`` JSON blob access (write in
the worker, read in the API) — verbatim, no behaviour change.
"""
import json
from typing import Optional, Dict, Any

from app.config import get_redis_client, settings
from app.db.dual_write import upsert_license


class LicenseRepository:
    """All access to per-scan license-compliance blobs goes through here."""

    def __init__(self, redis_client=None):
        self.r = redis_client if redis_client is not None else get_redis_client()

    @staticmethod
    def _key(scan_id: str) -> str:
        return f"licenses:{scan_id}"

    def get_raw(self, scan_id: str) -> Optional[str]:
        """The raw JSON string for a scan's license result (or None)."""
        return self.r.get(self._key(scan_id))

    def get(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """The parsed license result for a scan (None if absent).

        Phase 3: read the data JSONB from Postgres when enabled, fall back to
        Redis on a miss."""
        if settings.DATABASE_URL and settings.READ_FROM_POSTGRES:
            from app.db.read_pg import read_license_data
            data = read_license_data(scan_id)
            if data:
                return data
        raw = self.get_raw(scan_id)
        return json.loads(raw) if raw else None

    def save(self, scan_id: str, data: Dict[str, Any], ttl: int) -> None:
        """Persist a scan's license result (JSON-encoded) with a TTL."""
        if settings.WRITE_TO_REDIS:
            self.r.set(self._key(scan_id), json.dumps(data), ex=ttl)
        if settings.DATABASE_URL:
            upsert_license(scan_id, data)
