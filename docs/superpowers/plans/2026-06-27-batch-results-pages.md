# Batch Results Pages (Phase 2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development for the backend tasks (TDD). Frontend tasks are build-verified (no React unit-test harness) — implement, compile via the dashboard Docker build, manual smoke.

**Goal:** A Batches list page + a per-batch detail page (live progress, per-image results, report/SBOM links, policy-gate column, bulk re-scan, CSV), scoped per user (admin sees all). Builds on Phase 1 ownership.

**Architecture:** Three new `/api/v2` endpoints read the existing `batch:<id>` hashes + per-scan hashes; a new global `recent_batches` index lets admins list all batches while non-admins use the Phase-1 `user_batches:<username>` index. Two new React pages consume them; the `/batch` submit form redirects to the detail page.

**Tech Stack:** FastAPI + Redis (pytest + fakeredis for backend); React 18 + MUI v5 (design system: PageHeader, SeverityChip, LoadingSkeletons, useToast, SortableTable; CRA build via dashboard Dockerfile).

## Global Constraints

- Ownership (Phase 1): batch hash has `created_by` = `ownership.OWNER_FIELD`; per-user index `user_batches:<username>` populated by `ownership.record_batch_owner`. Admin = `_user.role == "admin"`.
- `GET /api/v2/batches` (list): admin → global `recent_batches` zset; non-admin → `user_batches:<username>`.
- `GET /api/v2/batches/{id}` and `/policy-check`: ownership-gated — 404 if batch missing OR (non-admin AND `created_by != me`). (Batch detail is a per-user "my work" view; individual report links remain public.)
- Redis `decode_responses=True` (str values). UUID path params validated.
- Frontend: import shared `api`/`apiV2` from `api.js`; never a local `:7070` instance. Use `SeverityChip` for severity, `MONO_FONT` for ids, skeletons not bare spinners, `useToast`/`useConfirm` (no `alert`/`window.confirm`).

## File Structure

- **Modify** `app/app/routes.py` — add `recent_batches` global index on batch submit.
- **Modify** `app/app/routes_v2.py` — three new endpoints (`/batches`, `/batches/{id}`, `/batches/{id}/policy-check`).
- **Create** `app/tests/test_batches_api.py` — backend tests.
- **Modify** `dashboard/src/api.js` — `getBatches`, `getBatchDetail`, `getBatchPolicyCheck`.
- **Create** `dashboard/src/pages/Batches.js` — list page.
- **Create** `dashboard/src/pages/BatchDetail.js` — detail page.
- **Modify** `dashboard/src/App.js` — routes `/batches`, `/batches/:batchId`.
- **Modify** `dashboard/src/components/Sidebar.js` — "Batch Results" nav entry.
- **Modify** `dashboard/src/pages/BatchScan.js` — redirect to detail on submit.

---

### Task B1: `recent_batches` index + `GET /api/v2/batches` list

**Files:** Modify `app/app/routes.py`, `app/app/routes_v2.py`; Test `app/tests/test_batches_api.py`

**Interfaces produced:** `GET /api/v2/batches?limit=&offset=` → `{ total, batches: [{batch_id, created_at, total_images, completed, failed, in_progress, status}] }`.

- [ ] **Step 1: Failing test** — create `app/tests/test_batches_api.py`:

```python
import json
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.auth import create_access_token
from app import ownership


@pytest.fixture
def client(mock_redis):
    return TestClient(app)


def _h(u, r):
    t, _ = create_access_token(u, r)
    return {"Authorization": f"Bearer {t}"}


def _seed_batch(r, batch_id, owner, scans):
    # scans: list of (scan_id, image, status, crit, high, med, low)
    scan_ids = [s[0] for s in scans]
    for sid, img, st, c, h, m, l in scans:
        r.hset(sid, mapping={"status": st, "image_name": img, "created_by": owner,
                             "critical": c, "high": h, "medium": m, "low": l,
                             "report_url": f"https://edge/reports/{sid}.html",
                             "sbom_report_url": f"https://edge/reports/{sid}_sbom.html"})
        ownership.record_scan_owner(r, sid, owner)
    r.hset(f"batch:{batch_id}", mapping={
        "scan_ids": json.dumps(scan_ids), "images": json.dumps([s[1] for s in scans]),
        "total_images": len(scans), "status": "in_progress",
        "created_at": "2026-06-27T00:00:00+00:00", "created_by": owner})
    ownership.record_batch_owner(r, batch_id, owner)
    r.zadd("recent_batches", {batch_id: 1})


def test_batches_list_scoped_to_user(client, mock_redis):
    _seed_batch(mock_redis, "b-alice", "alice", [("sa", "img-a", "completed", 1, 2, 0, 0)])
    _seed_batch(mock_redis, "b-bob", "bob", [("sb", "img-b", "completed", 0, 0, 1, 0)])

    alice = client.get("/api/v2/batches", headers=_h("alice", "user")).json()
    ids = [b["batch_id"] for b in alice["batches"]]
    assert "b-alice" in ids and "b-bob" not in ids
    assert alice["batches"][0]["total_images"] == 1
    assert alice["batches"][0]["completed"] == 1

    admin = client.get("/api/v2/batches", headers=_h("admin", "admin")).json()
    admin_ids = [b["batch_id"] for b in admin["batches"]]
    assert "b-alice" in admin_ids and "b-bob" in admin_ids
```

- [ ] **Step 2: Run → FAIL** (`404`/missing endpoint).
Run: `cd /opt/new-grype-scanner-v1/app && python3 -m pytest tests/test_batches_api.py -v`

- [ ] **Step 3: Implement.**

(a) In `app/app/routes.py` `POST /scan/batch`, right after `ownership.record_batch_owner(redis_client, batch_id, _user.username)` (added in Phase 1), add the global index:
```python
            redis_client.zadd("recent_batches", {batch_id: datetime.now(timezone.utc).timestamp()})
```

(b) In `app/app/routes_v2.py`, add the list endpoint (near the other v2 routes; `ownership`, `get_current_user`, `get_redis_client`, `json` are imported there — add `from app import ownership` if absent):
```python
@router_v2.get("/batches", summary="List batch scans")
async def list_batches(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    _user: TokenData = Depends(get_current_user),
):
    r = get_redis_client()
    if _user.role == "admin":
        batch_ids = r.zrevrange("recent_batches", 0, -1)
    else:
        batch_ids = ownership.user_batch_ids(r, _user.username)

    out = []
    for bid in batch_ids:
        bh = r.hgetall(f"batch:{bid}")
        if not bh:
            continue
        scan_ids = json.loads(bh.get("scan_ids", "[]"))
        completed = failed = in_progress = 0
        for sid in scan_ids:
            st = r.hget(sid, "status")
            if st == "completed":
                completed += 1
            elif st == "failed":
                failed += 1
            elif st:
                in_progress += 1
        total = len(scan_ids)
        status = ("completed" if completed == total else
                  "failed" if failed == total else "in_progress")
        out.append({
            "batch_id": bid,
            "created_at": bh.get("created_at"),
            "total_images": total,
            "completed": completed,
            "failed": failed,
            "in_progress": in_progress,
            "status": status,
        })
    return {"total": len(out), "batches": out[offset:offset + limit]}
```

- [ ] **Step 4: Run → PASS.** Then `python3 -m pytest tests/test_api.py -q` (no regression).
- [ ] **Step 5: Commit** `feat(batches): recent_batches index + GET /api/v2/batches list`.

---

### Task B2: `GET /api/v2/batches/{id}` enriched detail (ownership-gated)

**Files:** Modify `app/app/routes_v2.py`; Test `app/tests/test_batches_api.py`

**Interfaces produced:** `GET /api/v2/batches/{batch_id}` → `{batch_id, created_at, created_by, total_images, completed, failed, in_progress, status, totals:{critical,high,medium,low}, images:[{scan_id,image_name,status,critical,high,medium,low,report_url,sbom_report_url}]}`; 404 if missing or non-owner non-admin.

- [ ] **Step 1: Failing test** — append:
```python
def test_batch_detail_enriched_and_owner_gated(client, mock_redis):
    _seed_batch(mock_redis, "b-alice", "alice",
                [("sa", "img-a", "completed", 1, 2, 3, 4),
                 ("sa2", "img-a2", "failed", 0, 0, 0, 0)])

    d = client.get("/api/v2/batches/b-alice", headers=_h("alice", "user")).json()
    assert d["total_images"] == 2 and d["completed"] == 1 and d["failed"] == 1
    assert d["totals"]["critical"] == 1 and d["totals"]["medium"] == 3
    img = next(i for i in d["images"] if i["scan_id"] == "sa")
    assert img["report_url"].endswith("sa.html") and img["high"] == 2

    # bob (non-admin) cannot view alice's batch
    assert client.get("/api/v2/batches/b-alice", headers=_h("bob", "user")).status_code == 404
    # admin can
    assert client.get("/api/v2/batches/b-alice", headers=_h("admin", "admin")).status_code == 200
```

- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** in `routes_v2.py`:
```python
@router_v2.get("/batches/{batch_id}", summary="Batch detail")
async def batch_detail(
    batch_id: str = Path(...),
    _user: TokenData = Depends(get_current_user),
):
    r = get_redis_client()
    bh = r.hgetall(f"batch:{batch_id}")
    if not bh:
        raise HTTPException(status_code=404, detail="Batch not found")
    if _user.role != "admin" and bh.get(ownership.OWNER_FIELD) != _user.username:
        raise HTTPException(status_code=404, detail="Batch not found")

    scan_ids = json.loads(bh.get("scan_ids", "[]"))
    images, totals = [], {"critical": 0, "high": 0, "medium": 0, "low": 0}
    completed = failed = in_progress = 0
    for sid in scan_ids:
        s = r.hgetall(sid)
        if not s:
            continue
        st = s.get("status", "unknown")
        if st == "completed":
            completed += 1
        elif st == "failed":
            failed += 1
        else:
            in_progress += 1
        sev = {k: int(s.get(k, 0) or 0) for k in ("critical", "high", "medium", "low")}
        for k in totals:
            totals[k] += sev[k]
        images.append({
            "scan_id": sid, "image_name": s.get("image_name"), "status": st,
            **sev, "report_url": s.get("report_url"),
            "sbom_report_url": s.get("sbom_report_url"),
        })
    total = len(scan_ids)
    status = ("completed" if completed == total else
              "failed" if failed == total else "in_progress")
    return {
        "batch_id": batch_id, "created_at": bh.get("created_at"),
        "created_by": bh.get(ownership.OWNER_FIELD),
        "total_images": total, "completed": completed, "failed": failed,
        "in_progress": in_progress, "status": status,
        "totals": totals, "images": images,
    }
```

- [ ] **Step 4: Run → PASS** (+ test_api.py regression).
- [ ] **Step 5: Commit** `feat(batches): GET /api/v2/batches/{id} enriched, owner-gated`.

---

### Task B3: `GET /api/v2/batches/{id}/policy-check`

**Files:** Modify `app/app/routes_v2.py`; Test `app/tests/test_batches_api.py`

**Interfaces produced:** `GET /api/v2/batches/{batch_id}/policy-check?policy_id=` → `{policy_id, policy_name, results:[{scan_id, image_name, passed(bool|None), fail, warn}]}`. Owner-gated. Completed scans evaluated; non-completed → `passed: null`.

- [ ] **Step 1: Failing test** — append (uses the existing PolicyEngine; seed a simple policy + vulns):
```python
def test_batch_policy_check(client, mock_redis):
    from app.policy_engine import PolicyEngine
    pe = PolicyEngine()
    pol = pe.create_policy(name="no-critical", description="",
                           rules=[{"field": "severity", "operator": "equals",
                                   "value": "CRITICAL", "action": "fail"}])
    pid = pol.id if hasattr(pol, "id") else pol["id"]

    _seed_batch(mock_redis, "b-alice", "alice",
                [("sa", "img-a", "completed", 1, 0, 0, 0),
                 ("sb", "img-b", "completed", 0, 0, 1, 0)])
    mock_redis.set("vulns:sa", json.dumps([{"id": "CVE-1", "severity": "CRITICAL"}]))
    mock_redis.set("vulns:sb", json.dumps([{"id": "CVE-2", "severity": "MEDIUM"}]))

    res = client.get(f"/api/v2/batches/b-alice/policy-check?policy_id={pid}",
                     headers=_h("alice", "user")).json()
    by = {x["scan_id"]: x for x in res["results"]}
    assert by["sa"]["passed"] is False   # has a CRITICAL → fails
    assert by["sb"]["passed"] is True    # no CRITICAL → passes
```

- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** in `routes_v2.py` (PolicyEngine and json are available there):
```python
@router_v2.get("/batches/{batch_id}/policy-check", summary="Batch policy gate")
async def batch_policy_check(
    batch_id: str = Path(...),
    policy_id: str = Query(...),
    _user: TokenData = Depends(get_current_user),
):
    r = get_redis_client()
    bh = r.hgetall(f"batch:{batch_id}")
    if not bh:
        raise HTTPException(status_code=404, detail="Batch not found")
    if _user.role != "admin" and bh.get(ownership.OWNER_FIELD) != _user.username:
        raise HTTPException(status_code=404, detail="Batch not found")

    from app.policy_engine import PolicyEngine
    pe = PolicyEngine()
    policy = pe.get_policy(policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    results = []
    for sid in json.loads(bh.get("scan_ids", "[]")):
        s = r.hgetall(sid)
        image_name = s.get("image_name") if s else None
        if not s or s.get("status") != "completed":
            results.append({"scan_id": sid, "image_name": image_name,
                            "passed": None, "fail": 0, "warn": 0})
            continue
        raw = r.get(f"vulns:{sid}")
        vulns = json.loads(raw) if raw else []
        ev = pe.evaluate_vulnerabilities(policy_id, vulns)
        results.append({
            "scan_id": sid, "image_name": image_name,
            "passed": ev.passed, "fail": ev.summary.get("fail", 0),
            "warn": ev.summary.get("warn", 0),
        })
    return {"policy_id": policy_id, "policy_name": policy.name, "results": results}
```

- [ ] **Step 4: Run → PASS** (+ test_api.py + test_policy_engine.py).
- [ ] **Step 5: Commit** `feat(batches): GET /api/v2/batches/{id}/policy-check`.

---

### Task F1: api.js + Batches list page + nav

**Files:** Modify `dashboard/src/api.js`, `dashboard/src/App.js`, `dashboard/src/components/Sidebar.js`; Create `dashboard/src/pages/Batches.js`

**Verification:** CRA build compiles (the dashboard Docker build fails on errors/unused vars), `/batches` route serves, list renders.

- [ ] **Step 1:** Add to `api.js` (after the Approved Base Images block):
```javascript
// Batch results
export const getBatches = (params = {}) => apiV2.get('/batches', { params });
export const getBatchDetail = (batchId) => apiV2.get(`/batches/${batchId}`);
export const getBatchPolicyCheck = (batchId, policyId) =>
  apiV2.get(`/batches/${batchId}/policy-check`, { params: { policy_id: policyId } });
```

- [ ] **Step 2:** Create `dashboard/src/pages/Batches.js` — a `PageHeader` ("Batch Results") + sortable table (`useTableSort`/`SortableHeadCell` from `components/SortableTable`) over `getBatches().data.batches`. Columns: batch id (short 8-char, `MONO_FONT`), Created (`new Date(created_at).toLocaleString()`), Images (`total_images`), a completed/failed summary (`completed`/`total_images`, failed count in `error.main` if >0), Status chip (in_progress=info, completed=success, failed=error), and a row click → `navigate('/batches/' + batch_id)`. `TableSkeleton` while loading (keep PageHeader visible); empty state "No batch scans yet — run a Batch Scan to get started." `useToast` on fetch error. A Refresh `IconButton` in PageHeader actions.

- [ ] **Step 3:** In `App.js`, import `Batches` and add a user-accessible route alongside `/batch`:
```javascript
        <Route path="/batches" element={<Batches />} />
```

- [ ] **Step 4:** In `Sidebar.js`, add to `mainMenuItems` after the Batch Scan entry: `{ text: 'Batch Results', icon: <ViewListIcon />, path: '/batches' }` (reuse an imported icon or import `Inventory2Icon`/`FactCheckIcon`).

- [ ] **Step 5:** Build: `cd /opt/new-grype-scanner-v1/app && docker-compose -f docker-compose.yml -f docker-compose.edge.yml build dashboard` → "Compiled" (no errors). Commit `feat(batches): Batches list page + nav + api`.

---

### Task F2: BatchDetail page + submit redirect

**Files:** Create `dashboard/src/pages/BatchDetail.js`; Modify `dashboard/src/App.js`, `dashboard/src/pages/BatchScan.js`

**Verification:** CRA build compiles; submit a batch → lands on `/batches/:id`; detail polls + renders per-image rows, report/SBOM links, policy gate, bulk actions.

- [ ] **Step 1:** Create `dashboard/src/pages/BatchDetail.js`:
  - `const { batchId } = useParams();` load via `getBatchDetail(batchId)`; poll every 5s while `data.status !== 'completed' && data.status !== 'failed'` (clear interval on unmount / terminal).
  - **Header:** `PageHeader` title `Batch ${batchId.slice(0,8)}`, description with `created_at`; actions: Refresh; a `LinearProgress` (determinate `completed/total_images*100`) while not terminal.
  - **Rollup:** a row of `SeverityChip` count chips for `totals` (critical/high/medium/low) + `X / Y completed`.
  - **Bulk actions:** buttons `Re-scan failed` (collect `images` rows where status==='failed' → `startBatchScan(failedImages)` → toast + `navigate('/batches/'+resp.data.batch_id)`), `Re-scan all` (all image_names), `Export CSV` (build CSV string from rows client-side, download via Blob).
  - **Policy gate:** a `Select` of policies (load via `apiV2.get('/policies')`); on change call `getBatchPolicyCheck(batchId, policyId)` → map scan_id→{passed,fail}; render a Gate column (Pass = success chip, Fail = error chip, null = "—/pending").
  - **Per-image table** (`SortableTable`): Image (`MONO_FONT`, ellipsis+title), Status chip, severity counts (`SeverityChip`), Gate (if a policy selected), Report (`IconButton component={Link} href={report_url} target=_blank` with aria-label), SBOM (same), Retry (failed rows → `startBatchScan([image_name])` → toast). Skeleton on initial load; `useToast` for errors/copies.

- [ ] **Step 2:** In `App.js` import `BatchDetail` and add:
```javascript
        <Route path="/batches/:batchId" element={<BatchDetail />} />
```

- [ ] **Step 3:** In `BatchScan.js`, change the submit handler: after `const response = await startBatchScan(validImages);` replace the inline `pollBatchStatus(...)` flow with `navigate('/batches/' + response.data.batch_id);`. Remove now-unused inline polling/result state if it leaves unused vars (CRA build will flag them).

- [ ] **Step 4:** Build dashboard (as F1 Step 5) → compiles. Commit `feat(batches): batch detail page + submit redirect`.

---

## Final Verification (after all tasks)

- [ ] Backend suite: `cd /opt/new-grype-scanner-v1/app && python3 -m pytest tests/ -q` — green.
- [ ] Build + deploy api + dashboard; reload edge.
- [ ] Smoke (two users): alice submits a batch → redirected to `/batches/:id`; `/batches` lists it; `BatchDetail` shows per-image rows + report links; select a policy → gate column; bob (non-admin) `GET /api/v2/batches/<alice batch>` → 404; admin → 200.
