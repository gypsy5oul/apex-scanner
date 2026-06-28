"""One-time backfill of existing Redis data into Postgres (Phase 2).

Idempotent (everything upserts). Reads stay on Redis; this just primes the
Postgres mirror so dual-write doesn't start from an empty DB. Run inside the
api/worker container:

    docker exec -w /app fastapi_scanner python -m app.db.backfill
"""
import json
import re

from app.config import get_redis_client, settings
from app.db.dual_write import upsert_scan, upsert_batch, upsert_license, upsert_vulns
from app.logging_config import get_logger

logger = get_logger(__name__)

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def run() -> dict:
    if not settings.DATABASE_URL:
        print("DATABASE_URL not set — nothing to back up.")
        return {}
    r = get_redis_client()
    counts = {"scans": 0, "vulns": 0, "licenses": 0, "batches": 0}

    # Scans are hashes keyed by a bare UUID — scan the keyspace and filter.
    for key in r.scan_iter(count=500):
        if not _UUID_RE.match(key):
            continue
        try:
            if r.type(key) != "hash":
                continue
            h = r.hgetall(key)
            if h.get("image_name") or h.get("status"):
                upsert_scan(key, h)
                counts["scans"] += 1
        except Exception as e:
            logger.debug("backfill scan skipped", key=key, error=str(e))

    for key in r.scan_iter(match="vulns:*", count=500):
        sid = key.split("vulns:", 1)[1]
        raw = r.get(key)
        if raw:
            try:
                upsert_vulns(sid, json.loads(raw))
                counts["vulns"] += 1
            except Exception as e:
                logger.debug("backfill vulns skipped", scan_id=sid, error=str(e))

    for key in r.scan_iter(match="licenses:*", count=500):
        sid = key.split("licenses:", 1)[1]
        raw = r.get(key)
        if raw:
            try:
                upsert_license(sid, json.loads(raw))
                counts["licenses"] += 1
            except Exception as e:
                logger.debug("backfill licenses skipped", scan_id=sid, error=str(e))

    for key in r.scan_iter(match="batch:*", count=500):
        bid = key.split("batch:", 1)[1]
        h = r.hgetall(key)
        if h:
            upsert_batch(bid, h)
            counts["batches"] += 1

    print("Backfill complete:", counts)
    logger.info("Backfill complete", **counts)
    return counts


if __name__ == "__main__":
    run()
