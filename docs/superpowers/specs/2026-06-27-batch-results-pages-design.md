# Batch Results Pages (Phase 2) — Design

**Date:** 2026-06-27
**Status:** Approved design (settled during Phase-1 brainstorm) → ready for plan
**Builds on:** Phase 1 per-user ownership (`created_by`, `user_scans`/`user_batches` indexes). See `2026-06-26-per-user-scan-ownership-design.md`.

## Problem

A batch scan (N images) creates one `batch_id` + N `scan_id`s, but today the
only view is the **ephemeral inline result** on the `/batch` submit page — leave
it and it's gone; no shareable URL, no way to revisit a past batch, no list of
batches. Users want to land on a dedicated results page when a batch finishes
and find past batches later.

## Goals

- A **Batches list** page (history of batch runs), scoped per user (admin sees all).
- A **Batch detail** page per `batch_id`: live progress + per-image results +
  report/SBOM links + a **policy-gate** column + **bulk actions** (re-scan
  failed/all, export CSV).
- Submitting a batch **redirects to its detail page** (the "land on it" behavior).
- Inherits Phase 1 per-user filtering for free.

## Non-Goals

- Report/SBOM files stay public & shareable (unchanged).
- No changes to how scans execute (the existing `batch_scan_images` Celery task).
- No new tenancy concepts beyond Phase 1.

## Design Decisions (from brainstorm)

- **Scope:** both the list AND the detail page.
- **Detail page does:** read-only summary + **bulk actions** + **policy-gate column**.
- **Detail-page ownership:** unlike individual scan reports (which stay public/
  shareable), the batch **detail is a per-user "my work" view** → ownership-gated
  (admin sees any; non-admin gets 404 on a batch they don't own). The per-image
  **report links still open publicly** (the artifacts are unchanged).

## Backend

### Data model
- Phase 1 already stamps `created_by` on the `batch:<id>` hash and populates
  `user_batches:<username>`. Add a **global** `recent_batches` sorted set
  (score = creation epoch) on batch submit, so admins can list all batches
  efficiently (mirrors the per-user index).

### Endpoints (all `app/app/routes_v2.py`, `/api/v2` prefix)

1. **`GET /api/v2/batches?limit=&offset=`** — list batches.
   - admin → `recent_batches` (global); non-admin → `user_batches:<username>`.
   - For each batch id: read `batch:<id>` hash + roll up its scans' statuses.
   - Returns: `{ total, batches: [{ batch_id, created_at, total_images,
     completed, failed, in_progress, status }] }` newest-first.

2. **`GET /api/v2/batches/{batch_id}`** — enriched detail (ownership-gated).
   - 404 if the batch hash is missing OR (non-admin AND `created_by != me`).
   - Returns: `{ batch_id, created_at, created_by, total_images, completed,
     failed, in_progress, status, totals: {critical,high,medium,low},
     images: [{ scan_id, image_name, status, critical, high, medium, low,
     report_url, sbom_report_url }] }`.

3. **`GET /api/v2/batches/{batch_id}/policy-check?policy_id=`** — per-image gate.
   - Ownership-gated like (2). For each completed scan in the batch, load
     `vulns:<scan_id>` and call `policy_engine.evaluate_vulnerabilities(policy_id,
     vulns)`. Returns `{ policy_id, policy_name, results: [{ scan_id,
     image_name, passed, status, fail, warn }] }`. Scans not yet completed →
     `passed: null` ("pending").

4. **Bulk re-scan** → reuse existing `POST /api/v1/scan/batch` with the chosen
   image list (frontend builds the list from failed/all rows). No new endpoint.

5. **Export CSV** → client-side from the loaded detail (no new endpoint).

## Frontend

### Routing & nav
- **`/batch`** (`BatchScan.js`) stays the submit form. On submit success →
  `navigate('/batches/' + batch_id)` instead of inline polling.
- **`/batches`** → new `Batches.js` (list). Sidebar entry "Batch Results" in the
  Scanning group (user-accessible, like `/batch`).
- **`/batches/:batchId`** → new `BatchDetail.js`.

### Pages (design-system: PageHeader, SeverityChip/tokens, LoadingSkeletons, useToast, SortableTable)
- **`Batches.js`** — sortable table: batch id (short, mono), created, # images,
  completed/failed chips, status, → row opens detail. Skeleton on load; empty
  state ("No batch scans yet").
- **`BatchDetail.js`**:
  - **Header**: PageHeader with batch id + created; rollup (`X/Y completed`,
    aggregate severity totals); live `LinearProgress` while status != terminal
    (poll `getBatchDetail` every 5s until completed/failed).
  - **Bulk actions**: `Re-scan failed` · `Re-scan all` · `Export CSV`.
  - **Policy gate**: a policy dropdown (default none); on select, call the
    policy-check endpoint and show a **Pass/Fail** column.
  - **Per-image table** (sortable): image name · status chip · severity counts
    (`SeverityChip`) · policy gate · **Report** + **SBOM** links (OpenInNew) ·
    `Retry` (re-scan that one image) on failed rows.

### api.js additions
- `getBatches(params)` → `apiV2.get('/batches', { params })`
- `getBatchDetail(batchId)` → `apiV2.get('/batches/' + batchId)`
- `getBatchPolicyCheck(batchId, policyId)` → `apiV2.get('/batches/'+batchId+'/policy-check', { params: { policy_id } })`
- (re-scan uses existing `startBatchScan`; policies list uses existing `apiV2.get('/policies')`.)

## Testing

- **Backend (pytest + fakeredis):** the three new endpoints — list scoped per
  user (admin all / non-admin own / ownership 404 on detail), rollup counts,
  enriched per-image fields, policy-check pass/fail. Seed batches with the
  Phase-1 helpers (`ownership.record_batch_owner`, `recent_batches`).
- **Frontend:** no unit-test harness — verify the CRA build compiles clean and
  do a manual two-user smoke (submit batch → land on detail → list shows it →
  non-admin doesn't see another user's batch).

## Rollout

Backend (endpoints + `recent_batches` index) then frontend (pages + routes +
redirect). Deploy api + dashboard. Manual smoke. No data migration (existing
batches simply won't be in `recent_batches`; admins still reach them by id,
non-admins via `user_batches` only if they own them).
