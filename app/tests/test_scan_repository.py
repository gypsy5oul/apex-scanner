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


def test_get_many_parallel_and_missing(repo, mock_redis):
    _seed(mock_redis, "s1", "img:a")
    _seed(mock_redis, "s2", "img:b")
    res = repo.get_many(["s1", "missing", "s2"])
    assert len(res) == 3
    assert res[0]["image_name"] == "img:a"
    assert res[1] == {}          # missing -> empty dict, position preserved
    assert res[2]["image_name"] == "img:b"
    assert repo.get_many([]) == []


def test_owned_id_set(repo, mock_redis):
    _seed(mock_redis, "s1", "img:a", owner="alice")
    _seed(mock_redis, "s2", "img:b", owner="alice")
    _seed(mock_redis, "s3", "img:c", owner="bob")
    assert repo.owned_id_set("alice") == {"s1", "s2"}
    assert repo.owned_id_set("nobody") == set()


def test_all_recent_history_ids(repo, mock_redis):
    for i in range(4):                      # 4 scans of img:a -> only 3 newest returned
        _seed(mock_redis, f"a{i}", "img:a")
    _seed(mock_redis, "b0", "img:b")
    ids = repo.all_recent_history_ids()
    assert "b0" in ids
    assert len([x for x in ids if x.startswith("a")]) == 3   # lrange 0,2 cap


def test_create_and_get_status_and_ttl(repo, mock_redis):
    repo.create("s1", {"status": "in_progress", "image_name": "img:a"}, ttl=3600)
    assert repo.get("s1")["status"] == "in_progress"
    assert repo.get_status("s1") == "in_progress"
    assert mock_redis.ttl("s1") > 0          # TTL applied
    assert repo.get_status("missing") is None


def test_record_owner_indexes_scan(repo, mock_redis):
    repo.create("s1", {"image_name": "img:a"})
    repo.record_owner("s1", "alice")
    assert repo.user_ids("alice") == ["s1"]


def test_add_to_history_caps_and_orders(repo, mock_redis):
    for i in range(5):
        repo.add_to_history("img:a", f"s{i}", max_len=3, ttl=3600)
    ids = repo.image_history_ids("img:a", 50)
    assert ids == ["s4", "s3", "s2"]         # newest-first, capped to 3
    assert mock_redis.ttl("history:img:a") > 0


def test_save_merges_without_touching_ttl(repo, mock_redis):
    repo.create("s1", {"status": "in_progress", "image_name": "img:a"}, ttl=3600)
    repo.save("s1", {"status": "completed", "critical": 2})
    rec = repo.get("s1")
    assert rec["status"] == "completed" and rec["image_name"] == "img:a" and rec["critical"] == "2"
    assert mock_redis.ttl("s1") > 0          # save did not clear the TTL


def test_set_status_with_and_without_error(repo, mock_redis):
    repo.create("s1", {"status": "in_progress"})
    repo.set_status("s1", "failed", "boom")
    assert repo.get("s1") == {"status": "failed", "error": "boom"}
    repo.set_status("s1", "completed")
    assert repo.get("s1")["status"] == "completed"
