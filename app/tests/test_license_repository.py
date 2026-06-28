"""Phase 0: LicenseRepository wraps licenses:<scan_id> access verbatim."""
import json
import pytest
from app.repositories import LicenseRepository


@pytest.fixture
def repo(mock_redis):
    return LicenseRepository(mock_redis)


def test_save_get_raw_parsed_and_ttl(repo, mock_redis):
    data = {"status": "pass", "fail": 0, "warn": 2, "licenses": ["MIT", "Apache-2.0"]}
    repo.save("s1", data, ttl=3600)
    assert repo.get("s1") == data
    assert json.loads(repo.get_raw("s1")) == data
    assert mock_redis.ttl("licenses:s1") > 0
    assert repo.get("missing") is None
    assert repo.get_raw("missing") is None
