"""GET /scan/{id} must not 500 on an all-scanners-failed scan.

Regression: scanner_errors is stored as a dict-of-dicts
({scanner: {message, category, raw}}) but MultiScannerData.scanner_errors
was typed Dict[str, str], so Pydantic raised a 500 on read.
"""
import json
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.auth import create_access_token
import app.routes as _routes_mod


@pytest.fixture
def client(mock_redis):
    # app.routes captured its own get_redis_client reference at import time;
    # point it at the same fakeredis the test seeds.
    _routes_mod.get_redis_client = lambda: mock_redis
    return TestClient(app)


def _hdr(u="alice", r="user"):
    t, _ = create_access_token(u, r)
    return {"Authorization": f"Bearer {t}"}


def test_get_failed_scan_with_structured_scanner_errors(client, mock_redis):
    sid = "11111111-1111-1111-1111-111111111111"
    mock_redis.hset(sid, mapping={
        "scan_id": sid,
        "image_name": "alpine:3.18",
        "status": "failed",
        "error": "Registry rate limit hit.",
        "scanner_errors": json.dumps({
            "grype": {"message": "Registry rate limit hit.", "category": "rate_limited", "raw": "..."},
            "trivy": {"message": "Registry rate limit hit.", "category": "rate_limited", "raw": "..."},
        }),
        "critical": 0, "high": 0, "medium": 0, "low": 0,
        "negligible": 0, "unknown": 0, "total_packages": 0, "total_secrets": 0,
    })
    r = client.get(f"/api/v1/scan/{sid}", headers=_hdr())
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "failed"
    # structured per-scanner error survives serialization
    assert body["multi_scanner"]["scanner_errors"]["grype"]["category"] == "rate_limited"


def test_get_failed_scan_with_legacy_string_errors(client, mock_redis):
    # old-style plain-string scanner_errors must still work
    sid = "22222222-2222-2222-2222-222222222222"
    mock_redis.hset(sid, mapping={
        "scan_id": sid, "image_name": "x", "status": "failed",
        "scanner_errors": json.dumps({"grype": "boom"}),
        "critical": 0, "high": 0, "medium": 0, "low": 0,
        "negligible": 0, "unknown": 0, "total_packages": 0, "total_secrets": 0,
    })
    r = client.get(f"/api/v1/scan/{sid}", headers=_hdr())
    assert r.status_code == 200, r.text
