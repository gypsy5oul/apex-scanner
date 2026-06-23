"""
Approved Base Images — GitLab catalog feed.

Fetches a catalog.json published in a GitLab repo (the hardened/approved base
images, refreshed daily by image-watch), normalizes the per-image report links
to this app's public edge URL, and caches the result in Redis so we don't hit
GitLab on every page load and can survive GitLab being unreachable.
"""
from typing import Any, Dict
from urllib.parse import urlparse
import json

import httpx

from app.config import settings, get_redis_client
from app.logging_config import get_logger
from app.time_utils import now_iso

logger = get_logger(__name__)

CACHE_KEY = "approved_base_images:catalog"          # served copy (has TTL)
LAST_GOOD_KEY = "approved_base_images:last_good"     # fallback copy (no TTL)


def _raw_url() -> str:
    base = settings.GITLAB_BASE_URL.rstrip("/")
    path = settings.GITLAB_CATALOG_PATH.lstrip("/")
    return (
        f"{base}/api/v4/projects/{settings.GITLAB_PROJECT_ID}"
        f"/repository/files/{path}/raw?ref={settings.GITLAB_CATALOG_REF}"
    )


def _normalize_report_url(url: str) -> str:
    """Rewrite a report link to this app's edge origin.

    The catalog stores report_urls that point back at this very app, but with a
    mix of the new edge host and the old (now firewalled) http://<ip>:7070 form.
    Keep the path, swap the origin to SERVER_HOST so the link always opens.
    """
    if not url:
        return url
    try:
        parsed = urlparse(url)
        if parsed.path:
            return settings.SERVER_HOST.rstrip("/") + parsed.path
    except Exception:
        pass
    return url


def _normalize_catalog(data: Dict[str, Any]) -> Dict[str, Any]:
    images = data.get("images") or []
    for img in images:
        if isinstance(img, dict) and img.get("report_url"):
            img["report_url"] = _normalize_report_url(img["report_url"])
    data["images"] = images
    return data


def _fetch_live() -> Dict[str, Any]:
    """Fetch + parse the catalog directly from GitLab (pinned-cert TLS)."""
    verify = settings.GITLAB_CA_CERT or True
    headers = {"PRIVATE-TOKEN": settings.GITLAB_TOKEN}
    with httpx.Client(timeout=20.0, verify=verify) as client:
        resp = client.get(_raw_url(), headers=headers)
        resp.raise_for_status()
        data = resp.json()
    if not isinstance(data, dict) or "images" not in data:
        raise ValueError("catalog.json did not contain the expected shape")
    return _normalize_catalog(data)


def get_catalog(force_refresh: bool = False) -> Dict[str, Any]:
    """Return the catalog with a `meta` block describing freshness.

    Order: served cache (unless force_refresh) -> live GitLab -> last-good
    fallback. Raises only if there is no cache AND the live fetch fails.
    """
    if not settings.GITLAB_CATALOG_ENABLED:
        raise RuntimeError("The Approved Base Images catalog is not configured")

    r = get_redis_client()

    if not force_refresh:
        cached = r.get(CACHE_KEY)
        if cached:
            payload = json.loads(cached)
            payload["meta"] = {"source": "cache", "fetched_at": payload.get("_fetched_at")}
            return payload

    try:
        data = _fetch_live()
        data["_fetched_at"] = now_iso()
        serialized = json.dumps(data)
        r.setex(CACHE_KEY, settings.GITLAB_CATALOG_TTL, serialized)
        r.set(LAST_GOOD_KEY, serialized)
        data["meta"] = {"source": "live", "fetched_at": data["_fetched_at"]}
        logger.info("Fetched approved base images catalog", count=data.get("count"))
        return data
    except Exception as exc:
        logger.warning("Live catalog fetch failed; trying last-good", error=str(exc))
        last_good = r.get(LAST_GOOD_KEY)
        if last_good:
            payload = json.loads(last_good)
            payload["meta"] = {
                "source": "stale",
                "fetched_at": payload.get("_fetched_at"),
                "error": str(exc),
            }
            return payload
        raise
