"""Security regression tests for the IaC scanner (path traversal, token leak,
git protocol smuggling)."""
import os
from unittest.mock import patch, MagicMock
import pytest
from app.iac_scanner import IacScanner, _safe_join


def test_safe_join_blocks_traversal_and_absolute():
    base = "/tmp/iac_scans/abc"
    assert _safe_join(base, "Dockerfile") == "/tmp/iac_scans/abc/Dockerfile"
    assert _safe_join(base, "k8s/deploy.yaml") == "/tmp/iac_scans/abc/k8s/deploy.yaml"
    for bad in ("../../etc/passwd", "/var/www/html/reports/evil.html", "../escape"):
        with pytest.raises(ValueError):
            _safe_join(base, bad)


def test_scan_content_rejects_traversal_filename(tmp_path):
    s = IacScanner()
    res = s.scan_content("FROM scratch", filename="../../../var/www/html/reports/evil.html")
    assert res.status == "failed"
    # the malicious file must NOT have been written anywhere outside the sandbox
    assert not os.path.exists("/var/www/html/reports/evil.html")


def test_scan_git_repo_rejects_non_http_scheme():
    s = IacScanner()
    for bad in ("file:///etc/passwd", "ext::sh -c id", "ssh://x/y", "git://x/y"):
        res = s.scan_git_repo(bad)
        assert res.status == "failed"
        assert "http(s)" in (res.error or "")


@patch("app.iac_scanner.subprocess.run")
def test_scan_git_repo_never_leaks_token(mock_run):
    # git clone fails and its stderr echoes the token URL — the token must be
    # scrubbed and must never appear in source or error returned to the caller.
    token = "glpat-SECRET123"
    mock_run.return_value = MagicMock(returncode=1, stderr=f"fatal: auth for https://oauth2:{token}@h/r")
    s = IacScanner()
    res = s.scan_git_repo("https://h/r", token=token)
    assert res.status == "failed"
    assert token not in (res.source or "")
    assert token not in (res.error or "")
    assert res.source == "repo:https://h/r"  # safe_url, no credentials
