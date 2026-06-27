from unittest.mock import patch, MagicMock
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.auth import create_access_token
from app import ownership
import app.routes as _routes_mod


@pytest.fixture
def client(mock_redis):
    # app.routes captured its own get_redis_client reference at import time;
    # patch it here so the route handler sees the same fakeredis as the test.
    _routes_mod.get_redis_client = lambda: mock_redis
    return TestClient(app)


def _headers(username, role):
    token, _ = create_access_token(username, role)
    return {"Authorization": f"Bearer {token}"}


@patch("app.routes.scan_image")
def test_single_scan_stamps_owner(mock_task, client, mock_redis):
    mock_task.apply_async.return_value = MagicMock(id="t1")
    resp = client.post(
        "/api/v1/scan",
        json={"image_name": "nginx:1.0", "skip_cache": True},
        headers=_headers("alice", "user"),
    )
    assert resp.status_code == 202
    scan_id = resp.json()["scan_id"]
    assert mock_redis.hget(scan_id, ownership.OWNER_FIELD) == "alice"
    assert scan_id in ownership.user_scan_ids(mock_redis, "alice")
    assert scan_id not in ownership.user_scan_ids(mock_redis, "bob")


@patch("app.routes.batch_scan_images")
@patch("app.routes.scan_image")
def test_batch_scan_stamps_owner(mock_scan, mock_batch, client, mock_redis):
    mock_batch.apply_async.return_value = MagicMock(id="b1")
    resp = client.post(
        "/api/v1/scan/batch",
        json={"images": ["nginx:1.0", "redis:7"]},
        headers=_headers("alice", "user"),
    )
    assert resp.status_code == 202
    body = resp.json()
    batch_id = body["batch_id"]
    assert batch_id in ownership.user_batch_ids(mock_redis, "alice")
    assert mock_redis.hget(f"batch:{batch_id}", ownership.OWNER_FIELD) == "alice"
    for sid in body["scan_ids"]:
        assert mock_redis.hget(sid, ownership.OWNER_FIELD) == "alice"
        assert sid in ownership.user_scan_ids(mock_redis, "alice")


@patch("app.routes.scan_image")
def test_dedup_records_requesting_user(mock_task, client, mock_redis):
    # An in-progress scan already exists for this image (created by someone else).
    mock_redis.set("scan_dedup:nginx:1.0", "existing-scan")
    mock_redis.hset("existing-scan", mapping={"status": "in_progress", "image_name": "nginx:1.0"})
    mock_task.apply_async.return_value = MagicMock(id="t1")

    resp = client.post(
        "/api/v1/scan",
        json={"image_name": "nginx:1.0", "skip_cache": True},
        headers=_headers("bob", "user"),
    )
    assert resp.status_code == 202
    assert resp.json()["scan_id"] == "existing-scan"
    # bob deduped onto an existing scan, but it must appear in bob's own list:
    assert "existing-scan" in ownership.user_scan_ids(mock_redis, "bob")


def _seed_scan(r, scan_id, image, owner):
    r.hset(scan_id, mapping={
        "status": "completed", "image_name": image,
        "critical": "1", "high": "2", "medium": "0", "low": "0",
        "scan_timestamp": "2026-06-26T00:00:00+00:00",
        ownership.OWNER_FIELD: owner,
    })
    r.lpush(f"history:{image}", scan_id)
    ownership.record_scan_owner(r, scan_id, owner)


def test_recent_scans_scoped_to_user(client, mock_redis):
    _seed_scan(mock_redis, "s-alice", "img-a", "alice")
    _seed_scan(mock_redis, "s-bob", "img-b", "bob")

    alice = client.get("/api/v1/scans/recent", headers=_headers("alice", "user")).json()
    ids = [s["scan_id"] for s in alice["scans"]]
    assert "s-alice" in ids and "s-bob" not in ids

    admin = client.get("/api/v1/scans/recent", headers=_headers("admin", "admin")).json()
    admin_ids = [s["scan_id"] for s in admin["scans"]]
    assert "s-alice" in admin_ids and "s-bob" in admin_ids


def test_stats_scoped_to_user(client, mock_redis):
    _seed_scan(mock_redis, "s-alice", "img-a", "alice")
    _seed_scan(mock_redis, "s-bob", "img-b", "bob")

    alice = client.get("/api/v1/stats", headers=_headers("alice", "user")).json()
    assert alice["total_scans"] == 1
    assert alice["total_images_scanned"] == 1
