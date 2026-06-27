import fakeredis
from app import ownership


def _r():
    return fakeredis.FakeRedis(decode_responses=True)


def test_record_and_list_scan_owner_orders_newest_first():
    r = _r()
    ownership.record_scan_owner(r, "scan-a", "alice", ts=100)
    ownership.record_scan_owner(r, "scan-b", "alice", ts=200)
    ownership.record_scan_owner(r, "scan-c", "bob", ts=150)

    assert ownership.user_scan_ids(r, "alice") == ["scan-b", "scan-a"]
    assert ownership.user_scan_ids(r, "bob") == ["scan-c"]
    assert ownership.user_scan_ids(r, "carol") == []


def test_user_scan_ids_respects_limit():
    r = _r()
    for i in range(5):
        ownership.record_scan_owner(r, f"s{i}", "alice", ts=i)
    assert ownership.user_scan_ids(r, "alice", limit=2) == ["s4", "s3"]


def test_record_scan_owner_ignores_empty_username():
    r = _r()
    ownership.record_scan_owner(r, "scan-x", "", ts=1)
    assert ownership.user_scan_ids(r, "") == []


def test_record_batch_owner_separate_index():
    r = _r()
    ownership.record_batch_owner(r, "batch-1", "alice", ts=10)
    assert ownership.user_batch_ids(r, "alice") == ["batch-1"]
    assert ownership.user_scan_ids(r, "alice") == []
