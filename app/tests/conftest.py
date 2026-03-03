"""
Shared test fixtures for the Apex Scanner test suite.
"""
import os
import pytest
import fakeredis

# Ensure test environment — set BEFORE any app module is imported
os.environ.setdefault("ADMIN_USERNAME", "admin")
os.environ.setdefault("ADMIN_PASSWORD_HASH", "$2b$12$Va32tfPLHVZGgpf1Y9ZdlerV03HtL.f8vJjUpQo7u833OMl08qrW2")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-unit-tests-only-not-production-use-abcdef1234567890")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("SERVER_HOST", "http://localhost:7070")
# Do NOT set REDIS_PASSWORD — avoids AUTH errors against local Redis
os.environ.pop("REDIS_PASSWORD", None)

# Patch get_redis_client at module level so that module-level code
# (e.g. policy_engine.py's global PolicyEngine()) uses fakeredis
# instead of trying to connect to a real Redis server.
_global_fake_server = fakeredis.FakeServer()
_global_fake_redis = fakeredis.FakeRedis(server=_global_fake_server, decode_responses=True)

import app.config as _config_module
_config_module.get_redis_client = lambda: _global_fake_redis

# All modules that do `from app.config import get_redis_client` must
# also be patched, since Python caches the reference at import time.
_MODULES_USING_REDIS = []


def _patch_redis_in_app_modules(fake_client):
    """Patch get_redis_client in all app modules that import it."""
    import app.config as config_mod
    config_mod.get_redis_client = lambda: fake_client

    # Patch modules that use `from app.config import get_redis_client`
    modules_to_patch = [
        "app.enrichment",
        "app.policy_engine",
        "app.auth",
    ]
    import sys
    for mod_name in modules_to_patch:
        mod = sys.modules.get(mod_name)
        if mod and hasattr(mod, "get_redis_client"):
            mod.get_redis_client = lambda: fake_client


@pytest.fixture
def fake_redis():
    """Provide a fresh fakeredis instance for testing without a real Redis server."""
    server = fakeredis.FakeServer()
    client = fakeredis.FakeRedis(server=server, decode_responses=True)
    return client


@pytest.fixture
def mock_redis(monkeypatch, fake_redis):
    """Patch get_redis_client in ALL app modules to return a fresh fakeredis."""
    _patch_redis_in_app_modules(fake_redis)
    yield fake_redis
    # Restore global fake redis after test
    _patch_redis_in_app_modules(_global_fake_redis)


@pytest.fixture
def sample_grype_output():
    """Sample Grype JSON output for parser testing."""
    return {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2024-1234",
                    "severity": "Critical",
                    "description": "Test vulnerability",
                    "cvss": [{"metrics": {"baseScore": 9.8}}],
                    "fix": {"versions": ["1.2.4"], "state": "fixed"},
                    "urls": ["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"]
                },
                "artifact": {
                    "name": "openssl",
                    "version": "1.1.1k",
                    "type": "deb"
                }
            },
            {
                "vulnerability": {
                    "id": "CVE-2024-5678",
                    "severity": "High",
                    "description": "Another test vulnerability",
                    "cvss": [{"metrics": {"baseScore": 7.5}}],
                    "fix": {"versions": [], "state": "not-fixed"},
                    "urls": []
                },
                "artifact": {
                    "name": "curl",
                    "version": "7.88.1",
                    "type": "deb"
                }
            },
            {
                "vulnerability": {
                    "id": "CVE-2024-9999",
                    "severity": "Low",
                    "description": "Low severity vuln",
                    "cvss": [{"metrics": {"baseScore": 3.1}}],
                    "fix": {"versions": ["2.0.0"], "state": "fixed"},
                    "urls": []
                },
                "artifact": {
                    "name": "zlib",
                    "version": "1.2.11",
                    "type": "deb"
                }
            }
        ],
        "descriptor": {"name": "grype", "version": "0.108.0"}
    }


@pytest.fixture
def sample_trivy_output():
    """Sample Trivy JSON output for parser testing."""
    return {
        "Results": [
            {
                "Target": "ubuntu:22.04 (ubuntu 22.04)",
                "Class": "os-pkgs",
                "Type": "ubuntu",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-1234",
                        "PkgName": "openssl",
                        "InstalledVersion": "1.1.1k",
                        "FixedVersion": "1.1.1l",
                        "Severity": "CRITICAL",
                        "Description": "Test vulnerability",
                        "CVSS": {
                            "nvd": {"V3Score": 9.8, "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
                        }
                    },
                    {
                        "VulnerabilityID": "CVE-2024-TRIVY-ONLY",
                        "PkgName": "libxml2",
                        "InstalledVersion": "2.9.12",
                        "Severity": "MEDIUM",
                        "Description": "Trivy-only finding",
                        "CVSS": {}
                    }
                ],
                "Secrets": [
                    {
                        "RuleID": "aws-access-key-id",
                        "Category": "AWS",
                        "Severity": "CRITICAL",
                        "Title": "AWS Access Key ID",
                        "Match": "AKIA***REDACTED",
                        "StartLine": 42
                    }
                ]
            }
        ]
    }


@pytest.fixture
def sample_enriched_vulns():
    """Sample enriched vulnerability list."""
    return [
        {
            "id": "CVE-2024-1234",
            "severity": "Critical",
            "package_name": "openssl",
            "package_version": "1.1.1k",
            "cvss_score": "9.8",
            "fix_available": True,
            "found_by": ["grype", "trivy"],
            "confidence": "high",
            "epss_score": 0.85,
            "in_kev": True,
        },
        {
            "id": "CVE-2024-5678",
            "severity": "High",
            "package_name": "curl",
            "package_version": "7.88.1",
            "cvss_score": "7.5",
            "fix_available": False,
            "found_by": ["grype"],
            "confidence": "medium",
            "epss_score": 0.12,
            "in_kev": False,
        },
    ]
