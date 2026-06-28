"""Phase 3/4 parity check — compare Redis vs Postgres across all domains.

Run before flipping reads or before Phase 4 (stop Redis writes):

    docker exec -w /app fastapi_scanner python -m app.db.parity_check

Each domain compares the Redis source against what Postgres reconstructs:
- scans    : Redis hgetall      vs PG detail JSONB
- batches  : Redis hgetall      vs PG detail JSONB
- licenses : Redis licenses blob vs PG data JSONB
- vulns    : Redis vulns list    vs PG rows rebuilt (ordered by id)

Reports match / mismatch / pg_missing per domain and a few sample diffs.
"""
import json
import re

from app.config import get_redis_client, settings
from app.db import read_pg

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _summ(name, checked, match, mismatch, pg_missing, diffs):
    print(f"  {name:9s}: checked={checked} match={match} mismatch={mismatch} pg_missing={pg_missing}")
    for ident, d in diffs[:3]:
        print(f"      diff {ident}: {d}")


def _check_scans(r, sample):
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
        pg = read_pg.read_scan_detail(key)
        if pg is None:
            pg_missing += 1
        elif pg == h:
            match += 1
        else:
            mismatch += 1
            if len(diffs) < 3:
                ks = set(h) | set(pg)
                diffs.append((key, {k: (h.get(k), pg.get(k)) for k in ks if h.get(k) != pg.get(k)}))
        if checked >= sample:
            break
    _summ("scans", checked, match, mismatch, pg_missing, diffs)
    return mismatch + pg_missing


def _check_batches(r):
    checked = match = mismatch = pg_missing = 0
    diffs = []
    for key in r.scan_iter(match="batch:*", count=200):
        bid = key.split("batch:", 1)[1]
        h = r.hgetall(key)
        if not h:
            continue
        checked += 1
        pg = read_pg.read_batch_detail(bid)
        if pg is None or pg == {}:
            pg_missing += 1
        elif pg == h:
            match += 1
        else:
            mismatch += 1
            if len(diffs) < 3:
                ks = set(h) | set(pg)
                diffs.append((bid, {k: (h.get(k), pg.get(k)) for k in ks if h.get(k) != pg.get(k)}))
    _summ("batches", checked, match, mismatch, pg_missing, diffs)
    return mismatch + pg_missing


def _check_licenses(r, sample):
    checked = match = mismatch = pg_missing = 0
    diffs = []
    for key in r.scan_iter(match="licenses:*", count=500):
        sid = key.split("licenses:", 1)[1]
        raw = r.get(key)
        if not raw:
            continue
        checked += 1
        redis_d = json.loads(raw)
        pg = read_pg.read_license_data(sid)
        if pg is None:
            pg_missing += 1
        elif pg == redis_d:
            match += 1
        else:
            mismatch += 1
            if len(diffs) < 3:
                diffs.append((sid, "data differs"))
        if checked >= sample:
            break
    _summ("licenses", checked, match, mismatch, pg_missing, diffs)
    return mismatch + pg_missing


def _check_vulns(r, sample):
    checked = match = mismatch = pg_missing = 0
    diffs = []
    for key in r.scan_iter(match="vulns:*", count=500):
        sid = key.split("vulns:", 1)[1]
        raw = r.get(key)
        if not raw:
            continue
        redis_list = json.loads(raw)
        if not redis_list:
            continue
        checked += 1
        pg_list = read_pg.read_vulns_list(sid)
        if not pg_list:
            pg_missing += 1
        elif len(pg_list) == len(redis_list) and pg_list == redis_list:
            match += 1
        else:
            mismatch += 1
            if len(diffs) < 3:
                diffs.append((sid, f"redis={len(redis_list)} pg={len(pg_list)}"))
        if checked >= sample:
            break
    _summ("vulns", checked, match, mismatch, pg_missing, diffs)
    return mismatch + pg_missing


def run(sample: int = 300) -> int:
    if not settings.DATABASE_URL:
        print("DATABASE_URL not set — cannot compare.")
        return 1
    r = get_redis_client()
    print("Extended parity check (Redis vs Postgres):")
    bad = 0
    bad += _check_scans(r, sample)
    bad += _check_batches(r)
    bad += _check_licenses(r, sample)
    bad += _check_vulns(r, min(sample, 150))
    print("RESULT:", "ALL MATCH ✓" if bad == 0 else f"{bad} mismatch/missing — investigate before Phase 4")
    return bad


if __name__ == "__main__":
    import sys
    sys.exit(0 if run() == 0 else 1)
