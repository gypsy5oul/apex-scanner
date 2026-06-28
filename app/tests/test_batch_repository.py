"""Phase 0: BatchRepository wraps Redis batch access with no behaviour change."""
import json
import pytest
from app.repositories import BatchRepository
from app import ownership


class _User:
    def __init__(self, username, role):
        self.username = username
        self.role = role


@pytest.fixture
def repo(mock_redis):
    return BatchRepository(mock_redis)


def test_create_get_save_ttl(repo, mock_redis):
    repo.create("b1", {"status": "in_progress", "total_images": 3}, ttl=3600)
    assert repo.get("b1")["status"] == "in_progress"
    assert mock_redis.ttl("batch:b1") > 0
    repo.save("b1", {"status": "dispatched"})
    assert repo.get("b1")["status"] == "dispatched"
    assert repo.get("b1")["total_images"] == "3"      # save left other fields + TTL
    assert mock_redis.ttl("batch:b1") > 0
    assert repo.get("missing") == {}


def test_owner_index_and_visibility(repo, mock_redis):
    repo.create("b1", {"status": "x"}); repo.record_owner("b1", "alice")
    repo.create("b2", {"status": "x"}); repo.record_owner("b2", "bob")
    assert repo.user_ids("alice") == ["b1"]
    assert set(repo.visible_ids(_User("alice", "user"))) == {"b1"}


def test_mark_recent_caps_and_orders(repo, mock_redis):
    for i in range(3):
        repo.mark_recent(f"b{i}", ts=float(i))
    assert repo.recent_ids() == ["b2", "b1", "b0"]     # newest-first
    # admin visibility uses the global recent set
    assert repo.visible_ids(_User("admin", "admin")) == ["b2", "b1", "b0"]


def test_mark_recent_respects_cap(repo, mock_redis):
    for i in range(5):
        repo.mark_recent(f"b{i}", ts=float(i), cap=3)
    assert repo.recent_ids() == ["b4", "b3", "b2"]     # only newest 3 kept
