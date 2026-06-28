"""Reports/SBOMs must require authentication (any authenticated user; not public)."""
import os
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.config import settings
from app.auth import create_access_token


@pytest.fixture
def client(mock_redis):
    return TestClient(app)


def _hdr(u="alice", r="user"):
    t, _ = create_access_token(u, r)
    return {"Authorization": f"Bearer {t}"}


def _seed_report():
    os.makedirs(settings.REPORTS_DIR, exist_ok=True)
    p = os.path.join(settings.REPORTS_DIR, "auth-test.html")
    with open(p, "w") as f:
        f.write("<html>secret report</html>")
    return p


def test_report_requires_auth(client):
    _seed_report()
    # No auth, API-style request -> 401 (not public)
    r = client.get("/reports/auth-test.html", headers={"accept": "application/json"})
    assert r.status_code == 401


def test_report_served_to_any_authenticated_user(client):
    _seed_report()
    r = client.get("/reports/auth-test.html", headers=_hdr("bob", "user"))
    assert r.status_code == 200
    assert "secret report" in r.text


def test_report_browser_unauth_redirects_to_login(client):
    _seed_report()
    r = client.get("/reports/auth-test.html", headers={"accept": "text/html"}, follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"] == "/login"


def test_report_path_traversal_blocked(client):
    r = client.get("/reports/../config.py", headers=_hdr())
    assert r.status_code == 404
