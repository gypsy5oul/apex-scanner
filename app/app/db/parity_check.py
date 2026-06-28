"""Phase 3 parity check — sample scans and compare Redis vs Postgres.

Run before flipping reads to Postgres:

    docker exec -w /app fastapi_scanner python -m app.db.parity_check

Compares each sampled scan's Redis ``hgetall`` against the PG ``detail`` JSONB
(which should be identical, since dual-write stores the full hash). Reports
match / mismatch / pg-missing counts and a few sample diffs.
"""
import re

from app.config import get_redis_client, settings
from app.db.read_pg import read_scan_detail

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def run(sample: int = 300) -> dict:
    if not settings.DATABASE_URL:
        print("DATABASE_URL not set — cannot compare.")
        return {}
    r = get_redis_client()
    checked = match = mismatch = pg_missing = 0
    diffs = []

    for key in r.scan_iter(count=500):
        if not _UUID_RE.match(key):
            continue
        try:
            if r.type(key) != "hash":
                continue
        except Exception:
            continue
        h = r.hgetall(key)
        if not (h.get("image_name") or h.get("status")):
            continue
        checked += 1
        pg = read_scan_detail(key)
        if pg is None:
            pg_missing += 1
        elif pg == h:
            match += 1
        else:
            mismatch += 1
            if len(diffs) < 5:
                keys = set(h) | set(pg)
                diffs.append((key, {k: (h.get(k), pg.get(k)) for k in keys if h.get(k) != pg.get(k)}))
        if checked >= sample:
            break

    result = {"checked": checked, "match": match, "mismatch": mismatch, "pg_missing": pg_missing}
    print("Parity:", result)
    for sid, dk in diffs:
        print("  mismatch", sid, dk)
    return result


if __name__ == "__main__":
    run()
