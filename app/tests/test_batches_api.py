import json
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.auth import create_access_token
from app import ownership
import app.routes_v2 as _routes_v2_mod


@pytest.fixture
def client(mock_redis):
    # routes_v2 captures its own get_redis_client reference at import time;
    # patch it here so the route handler sees the same fakeredis as the test.
    _routes_v2_mod.get_redis_client = lambda: mock_redis
    return TestClient(app)


def _h(u, r):
    t, _ = create_access_token(u, r)
    return {"Authorization": f"Bearer {t}"}


def _seed_batch(r, batch_id, owner, scans):
    # scans: list of (scan_id, image, status, crit, high, med, low)
    scan_ids = [s[0] for s in scans]
    for sid, img, st, c, h, m, l in scans:
        r.hset(sid, mapping={"status": st, "image_name": img, "created_by": owner,
                             "critical": c, "high": h, "medium": m, "low": l,
                             "report_url": f"https://edge/reports/{sid}.html",
                             "sbom_report_url": f"https://edge/reports/{sid}_sbom.html"})
        ownership.record_scan_owner(r, sid, owner)
    r.hset(f"batch:{batch_id}", mapping={
        "scan_ids": json.dumps(scan_ids), "images": json.dumps([s[1] for s in scans]),
        "total_images": len(scans), "status": "in_progress",
        "created_at": "2026-06-27T00:00:00+00:00", "created_by": owner})
    ownership.record_batch_owner(r, batch_id, owner)
    r.zadd("recent_batches", {batch_id: 1})


def test_batches_list_scoped_to_user(client, mock_redis):
    _seed_batch(mock_redis, "b-alice", "alice", [("sa", "img-a", "completed", 1, 2, 0, 0)])
    _seed_batch(mock_redis, "b-bob", "bob", [("sb", "img-b", "completed", 0, 0, 1, 0)])

    alice = client.get("/api/v2/batches", headers=_h("alice", "user")).json()
    ids = [b["batch_id"] for b in alice["batches"]]
    assert "b-alice" in ids and "b-bob" not in ids
    assert alice["batches"][0]["total_images"] == 1
    assert alice["batches"][0]["completed"] == 1

    admin = client.get("/api/v2/batches", headers=_h("admin", "admin")).json()
    admin_ids = [b["batch_id"] for b in admin["batches"]]
    assert "b-alice" in admin_ids and "b-bob" in admin_ids
