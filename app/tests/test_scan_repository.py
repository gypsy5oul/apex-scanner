"""Phase 0: ScanRepository wraps Redis scan access with no behaviour change."""
import pytest
from app.repositories import ScanRepository
from app import ownership


class _User:
    def __init__(self, username, role):
        self.username = username
        self.role = role


@pytest.fixture
def repo(mock_redis):
    return ScanRepository(mock_redis)


def _seed(r, scan_id, image="img:1", owner=None):
    r.hset(scan_id, mapping={"scan_id": scan_id, "image_name": image, "status": "completed"})
    r.lpush(f"history:{image}", scan_id)
    if owner:
        ownership.record_scan_owner(r, scan_id, owner)


def test_get_and_exists(repo, mock_redis):
    _seed(mock_redis, "s1", "img:a")
    assert repo.get("s1")["image_name"] == "img:a"
    assert repo.exists("s1") is True
    assert repo.get("missing") == {}
    assert repo.exists("missing") is False


def test_user_ids_and_visibility(repo, mock_redis):
    _seed(mock_redis, "s1", "img:a", owner="alice")
    _seed(mock_redis, "s2", "img:b", owner="bob")
    assert repo.user_ids("alice") == ["s1"]
    assert repo.user_ids("bob") == ["s2"]
    # non-admin sees only own; admin sees global recent (both)
    assert set(repo.visible_ids(_User("alice", "user"))) == {"s1"}
    assert set(repo.visible_ids(_User("admin", "admin"))) >= {"s1", "s2"}


def test_image_history_and_unique_count(repo, mock_redis):
    _seed(mock_redis, "s1", "img:a")
    _seed(mock_redis, "s2", "img:a")
    _seed(mock_redis, "s3", "img:b")
    assert set(repo.image_history_ids("img:a", 50)) == {"s1", "s2"}
    assert repo.unique_image_count() == 2  # img:a + img:b


def test_image_names_for(repo, mock_redis):
    _seed(mock_redis, "s1", "img:a")
    _seed(mock_redis, "s2", "img:b")
    assert sorted(repo.image_names_for(["s1", "s2", "missing"])) == ["img:a", "img:b"]
    assert repo.image_names_for([]) == []
