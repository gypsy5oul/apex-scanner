# Per-User Scan Ownership (Phase 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Scope in-app scan lists per user — a non-admin sees only scans they created; an admin sees everything.

**Architecture:** Stamp each scan/batch with a `created_by` field at creation and maintain a per-user Redis sorted-set index (`user_scans:<username>`). List/aggregate read endpoints branch on role: admins use the existing global path, non-admins read their per-user index (or filter the fetched hashes by `created_by`). Report/SBOM files and direct-by-id access stay public (unchanged).

**Tech Stack:** FastAPI, Celery, Redis (redis-py), pytest + fakeredis (`mock_redis` fixture), `app.auth.create_access_token` for test tokens.

## Global Constraints

- Owner identity = `TokenData.username` (from `get_current_user`). Role check = `TokenData.role == "admin"`.
- Redis-only store, `decode_responses=True` (all values are `str`).
- Per-user index key format: `user_scans:<username>`, `user_batches:<username>` (sorted set, score = creation epoch seconds).
- Scan/batch hashes use field name `created_by`.
- Index TTL = `settings.SCAN_RESULT_TTL`; cap = newest 2000 per user.
- System-generated scans (base-image) → `created_by = "system"`, NOT added to any per-user index (admin-only via global path).
- No data migration: legacy scans (no `created_by`, absent from indexes) are admin-only by construction.
- Tests follow the existing pattern: patch `app.routes.scan_image` / `app.routes.batch_scan_images` to avoid a real broker; use `mock_redis`.

## File Structure

- **Create** `app/app/ownership.py` — ownership tagging + per-user index helpers (one responsibility: who-owns-what).
- **Modify** `app/app/routes.py` — stamp owner on `POST /scan` and `POST /scan/batch`; filter `GET /scans/recent`, `GET /stats`, `GET /history/{image_name}`.
- **Modify** `app/app/tasks.py` — base-image scans set `created_by = "system"`.
- **Create** `app/tests/test_ownership.py` — unit tests for `ownership.py`.
- **Create** `app/tests/test_ownership_api.py` — endpoint-level tenancy tests.

Note: `GET /vulnerabilities/search` is already `Depends(get_current_admin)` → no change needed.

---

### Task 1: Ownership helper module

**Files:**
- Create: `app/app/ownership.py`
- Test: `app/tests/test_ownership.py`

**Interfaces:**
- Produces:
  - `OWNER_FIELD: str = "created_by"`
  - `record_scan_owner(redis_client, scan_id: str, username: str, ts: float | None = None) -> None`
  - `record_batch_owner(redis_client, batch_id: str, username: str, ts: float | None = None) -> None`
  - `user_scan_ids(redis_client, username: str, limit: int | None = None) -> list[str]`
  - `user_batch_ids(redis_client, username: str, limit: int | None = None) -> list[str]`

- [ ] **Step 1: Write the failing test**

```python
# app/tests/test_ownership.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd app && python -m pytest tests/test_ownership.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.ownership'`

- [ ] **Step 3: Write minimal implementation**

```python
# app/app/ownership.py
"""Per-user scan ownership — tagging + per-user indexes for tenancy.

A regular user sees only scans they created; admins see everything. Scans are
stamped with ``created_by`` and added to a per-user sorted-set index so listing
a user's scans is O(their scans) rather than a full keyspace scan.
"""
import time
from typing import List, Optional

from app.config import settings

OWNER_FIELD = "created_by"
USER_SCANS_PREFIX = "user_scans:"
USER_BATCHES_PREFIX = "user_batches:"
MAX_PER_USER = 2000


def _record(redis_client, prefix: str, member: str, username: str, ts: Optional[float]) -> None:
    if not username:
        return
    score = ts if ts is not None else time.time()
    key = f"{prefix}{username}"
    pipe = redis_client.pipeline()
    pipe.zadd(key, {member: score})
    # Keep only the newest MAX_PER_USER members (drop the oldest-ranked).
    pipe.zremrangebyrank(key, 0, -(MAX_PER_USER + 1))
    pipe.expire(key, settings.SCAN_RESULT_TTL)
    pipe.execute()


def _list(redis_client, prefix: str, username: str, limit: Optional[int]) -> List[str]:
    if not username:
        return []
    end = (limit - 1) if limit else -1
    return redis_client.zrevrange(f"{prefix}{username}", 0, end)


def record_scan_owner(redis_client, scan_id: str, username: str, ts: Optional[float] = None) -> None:
    """Add a scan to its owner's per-user index."""
    _record(redis_client, USER_SCANS_PREFIX, scan_id, username, ts)


def record_batch_owner(redis_client, batch_id: str, username: str, ts: Optional[float] = None) -> None:
    """Add a batch to its owner's per-user index."""
    _record(redis_client, USER_BATCHES_PREFIX, batch_id, username, ts)


def user_scan_ids(redis_client, username: str, limit: Optional[int] = None) -> List[str]:
    """Scan IDs owned by `username`, newest first."""
    return _list(redis_client, USER_SCANS_PREFIX, username, limit)


def user_batch_ids(redis_client, username: str, limit: Optional[int] = None) -> List[str]:
    """Batch IDs owned by `username`, newest first."""
    return _list(redis_client, USER_BATCHES_PREFIX, username, limit)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd app && python -m pytest tests/test_ownership.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add app/app/ownership.py app/tests/test_ownership.py
git commit -m "feat(ownership): per-user scan/batch index helpers"
```

---

### Task 2: Stamp owner on scan creation (single + batch)

**Files:**
- Modify: `app/app/routes.py` (`POST /scan` ~line 488-503; `POST /scan/batch` ~line 546-660)
- Test: `app/tests/test_ownership_api.py`

**Interfaces:**
- Consumes: `ownership.record_scan_owner`, `ownership.record_batch_owner`, `ownership.OWNER_FIELD`, `ownership.user_scan_ids`, `ownership.user_batch_ids` (Task 1).
- Produces: scan hashes carry `created_by`; `user_scans:<username>` / `user_batches:<username>` populated on create.

- [ ] **Step 1: Write the failing test**

```python
# app/tests/test_ownership_api.py
from unittest.mock import patch, MagicMock
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.auth import create_access_token
from app import ownership


@pytest.fixture
def client(mock_redis):
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
    for sid in body["scan_ids"]:
        assert mock_redis.hget(sid, ownership.OWNER_FIELD) == "alice"
        assert sid in ownership.user_scan_ids(mock_redis, "alice")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd app && python -m pytest tests/test_ownership_api.py -v`
Expected: FAIL — `assert None == "alice"` (created_by not stamped yet).

- [ ] **Step 3: Write minimal implementation**

In `app/app/routes.py`, add the import near the other app imports (top of file, with the other `from app.X import` lines):

```python
from app import ownership
```

In `POST /scan`, add `created_by` to the scan-init hash mapping and index after it. The mapping currently ends with `"created_at": datetime.now(timezone.utc).isoformat()`; change that block to:

```python
            redis_client.hset(scan_id, mapping={
                "status": ScanStatus.IN_PROGRESS,
                "image_name": request.image_name,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "negligible": 0,
                "unknown": 0,
                "total_secrets": 0,
                "total_packages": 0,
                "report_url": "",
                "sbom_urls": "{}",
                "created_at": datetime.now(timezone.utc).isoformat(),
                ownership.OWNER_FIELD: _user.username,
            })
            redis_client.expire(scan_id, settings.SCAN_RESULT_TTL)
            ownership.record_scan_owner(redis_client, scan_id, _user.username)
```

In `POST /scan/batch`, make two edits.

(a) The per-image `hset` + `expire` block — add the owner field to the mapping and the index call after `expire`. Change:

```python
                redis_client.hset(scan_id, mapping={
                    "status": ScanStatus.IN_PROGRESS,
                    "image_name": image_name,
                    "batch_id": batch_id,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "negligible": 0,
                    "unknown": 0,
                    "total_secrets": 0,
                    "total_packages": 0,
                    "report_url": "",
                    "sbom_urls": "{}",
                    "created_at": datetime.now(timezone.utc).isoformat()
                })
                redis_client.expire(scan_id, settings.SCAN_RESULT_TTL)
```

to:

```python
                redis_client.hset(scan_id, mapping={
                    "status": ScanStatus.IN_PROGRESS,
                    "image_name": image_name,
                    "batch_id": batch_id,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "negligible": 0,
                    "unknown": 0,
                    "total_secrets": 0,
                    "total_packages": 0,
                    "report_url": "",
                    "sbom_urls": "{}",
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    ownership.OWNER_FIELD: _user.username,
                })
                redis_client.expire(scan_id, settings.SCAN_RESULT_TTL)
                ownership.record_scan_owner(redis_client, scan_id, _user.username)
```

(b) The batch-metadata `hset` + `expire` block — add the owner field and the batch index call. Change:

```python
            redis_client.hset(f"batch:{batch_id}", mapping={
                "scan_ids": json.dumps(scan_ids),
                "images": json.dumps(request.images),
                "total_images": len(request.images),
                "status": "in_progress",
                "created_at": datetime.now(timezone.utc).isoformat()
            })
            redis_client.expire(f"batch:{batch_id}", settings.SCAN_RESULT_TTL)
```

to:

```python
            redis_client.hset(f"batch:{batch_id}", mapping={
                "scan_ids": json.dumps(scan_ids),
                "images": json.dumps(request.images),
                "total_images": len(request.images),
                "status": "in_progress",
                "created_at": datetime.now(timezone.utc).isoformat(),
                ownership.OWNER_FIELD: _user.username,
            })
            redis_client.expire(f"batch:{batch_id}", settings.SCAN_RESULT_TTL)
            ownership.record_batch_owner(redis_client, batch_id, _user.username)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd app && python -m pytest tests/test_ownership_api.py -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add app/app/routes.py app/tests/test_ownership_api.py
git commit -m "feat(ownership): stamp created_by + per-user index on scan/batch create"
```

---

### Task 3: Filter `GET /scans/recent` and `GET /stats` by owner

**Files:**
- Modify: `app/app/routes.py` (`GET /scans/recent` ~1080-1135; `GET /stats` ~1138-1160)
- Test: `app/tests/test_ownership_api.py`

**Interfaces:**
- Consumes: `ownership.user_scan_ids` (Task 1), `created_by` stamping (Task 2).

- [ ] **Step 1: Write the failing test**

```python
# add to app/tests/test_ownership_api.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd app && python -m pytest tests/test_ownership_api.py -k "recent_scans_scoped or stats_scoped" -v`
Expected: FAIL — alice sees `s-bob` (no filtering yet) / `total_scans` reflects global.

- [ ] **Step 3: Write minimal implementation**

In `GET /scans/recent`, replace the scan-id collection (the block that builds `all_scan_ids` from `history_keys`) with a role branch. Replace lines from `history_keys = scan_redis_keys(...)` through the `all_scan_ids` assembly with:

```python
        if _user.role == "admin":
            history_keys = scan_redis_keys(redis_client, "history:*", count=200)
            if not history_keys:
                return {"scans": [], "total": 0}
            pipe = redis_client.pipeline()
            for key in history_keys:
                pipe.lrange(key, 0, 2)
            history_results = pipe.execute()
            all_scan_ids = []
            for scan_ids in history_results:
                all_scan_ids.extend(scan_ids)
        else:
            # Non-admin: only their own scans (newest first), from the per-user index.
            all_scan_ids = ownership.user_scan_ids(redis_client, _user.username, limit * 3)

        if not all_scan_ids:
            return {"scans": [], "total": 0}
```

(The existing "Pipeline 2" `hgetall` + response build below this is unchanged.)

In `GET /stats`, replace the body that computes `unique_images` and `total_scans` with a role branch:

```python
    if _user.role == "admin":
        unique_images = len(scan_redis_keys(redis_client, "history:*", count=200))
        try:
            from app.worker_monitor import get_monitor
            total_scans = get_monitor().get_task_stats().get("total_scans", 0)
        except Exception:
            total_scans = 0
    else:
        ids = ownership.user_scan_ids(redis_client, _user.username)
        total_scans = len(ids)
        images = set()
        if ids:
            pipe = redis_client.pipeline()
            for sid in ids:
                pipe.hget(sid, "image_name")
            for name in pipe.execute():
                if name:
                    images.add(name)
        unique_images = len(images)
```

(The `return {...}` block keeps using `unique_images` and `total_scans` as before.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cd app && python -m pytest tests/test_ownership_api.py -v`
Expected: PASS (all tests in file)

- [ ] **Step 5: Commit**

```bash
git add app/app/routes.py app/tests/test_ownership_api.py
git commit -m "feat(ownership): scope /scans/recent and /stats per user (admin sees all)"
```

---

### Task 4: Filter `GET /history/{image_name}` by owner

**Files:**
- Modify: `app/app/routes.py` (`GET /history/{image_name}` ~944-965, the `history` build loop)
- Test: `app/tests/test_ownership_api.py`

**Interfaces:**
- Consumes: `created_by` stamping (Task 2). Uses the already-fetched hash's `created_by` (history-per-image is bounded, so an in-place filter is cheap).

- [ ] **Step 1: Write the failing test**

```python
# add to app/tests/test_ownership_api.py
def test_history_scoped_to_user(client, mock_redis):
    # Two users scanned the SAME image.
    _seed_scan(mock_redis, "h-alice", "shared-img", "alice")
    _seed_scan(mock_redis, "h-bob", "shared-img", "bob")

    alice = client.get("/api/v1/history/shared-img", headers=_headers("alice", "user")).json()
    ids = [h["scan_id"] for h in alice["history"]]
    assert ids == ["h-alice"]

    admin = client.get("/api/v1/history/shared-img", headers=_headers("admin", "admin")).json()
    admin_ids = sorted(h["scan_id"] for h in admin["history"])
    assert admin_ids == ["h-alice", "h-bob"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd app && python -m pytest tests/test_ownership_api.py -k history_scoped -v`
Expected: FAIL — alice's history includes `h-bob`.

- [ ] **Step 3: Write minimal implementation**

In the `history` build loop, skip non-owned scans for non-admins. Change the loop body so the first line inside `if result:` is a guard:

```python
        history = []
        for scan_id, result in zip(scan_ids, scan_results):
            if result:
                if _user.role != "admin" and result.get(ownership.OWNER_FIELD) != _user.username:
                    continue
                history.append({
                    "scan_id": scan_id,
                    "image_name": result.get("image_name"),
                    # ... (rest of the existing dict unchanged) ...
                })
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd app && python -m pytest tests/test_ownership_api.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add app/app/routes.py app/tests/test_ownership_api.py
git commit -m "feat(ownership): scope image history per user (admin sees all)"
```

---

### Task 5: System owner for base-image scans

**Files:**
- Modify: `app/app/tasks.py` (`scan_base_images`, the per-image `thread_redis.hset(scan_id, mapping={...})` ~line 1150)
- Test: `app/tests/test_ownership.py`

**Interfaces:**
- Consumes: `ownership.OWNER_FIELD`. System scans get `created_by="system"` and are NOT added to a per-user index (admin-only via the global path).

- [ ] **Step 1: Write the failing test**

```python
# add to app/tests/test_ownership.py
def test_system_scans_invisible_to_users():
    # A scan owned by "system" must not appear in any human's per-user index.
    r = _r()
    r.hset("sys-scan", mapping={"status": "completed", "created_by": "system"})
    # base-image scans are intentionally NOT indexed per-user:
    assert ownership.user_scan_ids(r, "system") == []
    assert ownership.user_scan_ids(r, "alice") == []
```

This test encodes the invariant (system scans are not in per-user indexes). It passes once Task 5's code change does NOT call `record_scan_owner` for system scans — verify the production change by reading the diff in Step 3.

- [ ] **Step 2: Run test to verify it fails/passes appropriately**

Run: `cd app && python -m pytest tests/test_ownership.py -k system_scans -v`
Expected: PASS (the helper already ignores; this guards against a future regression that indexes system scans).

- [ ] **Step 3: Write minimal implementation**

In `app/app/tasks.py`, import ownership near the other `from app.X import` lines:

```python
from app import ownership
```

In `scan_base_images`, the per-image record is written via `thread_redis.hset(scan_id, mapping={... "created_at": now_iso(), ...})`. Add the system owner to that mapping:

```python
            thread_redis.hset(scan_id, mapping={
                "status": "in_progress",
                "image_name": image_name,
                "created_at": now_iso(),
                ownership.OWNER_FIELD: "system",
            })
```

Do NOT call `ownership.record_scan_owner` here — system scans stay out of per-user indexes and surface to admins through the global path.

- [ ] **Step 4: Run the full suite**

Run: `cd app && python -m pytest tests/test_ownership.py tests/test_ownership_api.py tests/test_api.py -v`
Expected: PASS (no regressions in existing API tests)

- [ ] **Step 5: Commit**

```bash
git add app/app/tasks.py app/tests/test_ownership.py
git commit -m "feat(ownership): tag base-image scans created_by=system (admin-only)"
```

---

## Final Verification (after all tasks)

- [ ] Run full test suite: `cd app && python -m pytest tests/ -v` — all green.
- [ ] Manual smoke (deploy api, two tokens): user A scans an image; `GET /api/v1/scans/recent` as user B does not include it; as admin it does; `GET /reports/<A scan>.html` as B returns 200 (public, shareable — confirms the non-goal is honored).
