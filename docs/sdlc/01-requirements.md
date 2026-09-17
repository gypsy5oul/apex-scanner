# 01 — Requirements

**Project:** Apex Scanner 3.0
**Status:** awaiting approval (stage 1 of 10)
**Mode:** Brownfield. Requirements are reverse-engineered from the shipped code,
not invented. Every `[shipped]` / `[partial]` / `[gap]` label carries the
`file:line` or endpoint that justifies it.
**Sources read:** `docs/sdlc/00-business-idea.md`, `docs/sdlc/architecture-map.md`,
`app/app/**`, `app/docker-compose.yml`, `app/Dockerfile.api`, `app/Dockerfile.worker`,
`app/scripts/worker-entrypoint.sh`, `dashboard/src/App.js`, `.gitlab-ci.yml`,
`prometheus.yml`.
**Date:** 2026-08-01

---

## Contents

- [1. BRD](#1-brd)
  - [1.1 Problem statement](#11-problem-statement)
  - [1.2 Goals](#12-goals)
  - [1.3 Non-goals](#13-non-goals)
  - [1.4 Stakeholders](#14-stakeholders)
- [2. User stories](#2-user-stories)
  - [2.1 Scanning](#21-scanning)
  - [2.2 History, comparison, search, trends](#22-history-comparison-search-trends)
  - [2.3 Batch scanning](#23-batch-scanning)
  - [2.4 Base images](#24-base-images)
  - [2.5 Approved base-image catalog](#25-approved-base-image-catalog)
  - [2.6 Schedules](#26-schedules)
  - [2.7 Policy gates](#27-policy-gates)
  - [2.8 Enrichment and threat intelligence](#28-enrichment-and-threat-intelligence)
  - [2.9 Risk scoring](#29-risk-scoring)
  - [2.10 Remediation](#210-remediation)
  - [2.11 Compliance mapping](#211-compliance-mapping)
  - [2.12 VEX](#212-vex)
  - [2.13 IaC scanning](#213-iac-scanning)
  - [2.14 License compliance](#214-license-compliance)
  - [2.15 Dependency analysis](#215-dependency-analysis)
  - [2.16 AI triage](#216-ai-triage)
  - [2.17 Exports and reporting](#217-exports-and-reporting)
  - [2.18 Worker operations](#218-worker-operations)
  - [2.19 Authentication and tenancy](#219-authentication-and-tenancy)
  - [2.20 System administration and data platform](#220-system-administration-and-data-platform)
  - [2.21 Dashboard](#221-dashboard)
- [3. MoSCoW table](#3-moscow-table)
- [4. Non-functional requirements](#4-non-functional-requirements)
  - [4.1 Performance and timeouts](#41-performance-and-timeouts)
  - [4.2 Scale limits](#42-scale-limits)
  - [4.3 Availability and resilience](#43-availability-and-resilience)
  - [4.4 Security](#44-security)
  - [4.5 Tenancy](#45-tenancy)
  - [4.6 Observability](#46-observability)
  - [4.7 Data retention](#47-data-retention)
- [5. Open questions](#5-open-questions)
- [6. Handoff notes](#6-handoff-notes)

---

## 1. BRD

### 1.1 Problem statement

Container images are shipped from many teams into 6D's estate. Without this
platform:

- Each team runs a single scanner by hand. Grype and Trivy disagree on package
  identity and severity, and neither alone produces an SBOM. Nothing merges or
  deduplicates the two result sets — `orchestrator.py:247 merge_results`,
  `:331 _dedup_key`, `:386 _deduplicate_vulnerabilities` exist precisely because
  that correlation is otherwise manual.
- A raw CVE list has no priority signal. Nothing tells an engineer which of 900
  findings is being exploited in the wild. The platform layers CISA KEV
  (`enrichment.py:129`) and EPSS (`enrichment.py:26`) onto the merged set.
- There is no organizational verdict. Pass/fail against a stated threshold lives
  in `policy_engine.py` and is exposed at `GET /api/v2/scan/{scan_id}/policy-check`
  (`routes_v2.py:2402`); without it, "is this image releasable" is an opinion.
- Scan results are ephemeral and untraceable. Redis-backed history
  (`routes.py:933`), trends (`routes_v2.py:915-969`) and per-user ownership
  (`ownership.py`) are the record that a given image was assessed on a given day.
- Scanner vulnerability databases go stale. `update_vulnerability_databases`
  (beat, 3 h — `tasks.py:1289`) and `update_kev_database` (6 h — `tasks.py:1298`)
  keep the shared cache fresh; a hand-run scanner silently uses a month-old DB.
- Long scans leak Syft/Grype scratch directories of 0.5–1 GB each. Without
  `cleanup_old_scan_artifacts` (`tasks.py:1467`) the host disk fills — this
  already happened — 81 leaked directories put 63 GB into one batch worker's
  writable layer and took `/opt` to 98% full (`tasks.py:1519-1520`); an earlier
  episode reached 228 GB in 46 h (`docker-compose.yml:132-133`).

### 1.2 Goals

Each goal is stated against an observable already emitted by the system.

| # | Goal | Observable |
|---|---|---|
| G1 | One correlated result set per image, not per scanner | `GET /api/v1/scan/{id}` returns `multi_scanner.scanners_used`, `grype_unique`, `trivy_unique`, `both_scanners` (`routes.py:372-381`) |
| G2 | A partial scan is never reported as a clean scan | hard-fail guard marks the scan `failed` when BOTH vuln scanners fail and `sbom_packages == 0` (`tasks.py:716-739`, condition at `:723`). `scan_quality` is `full` / `degraded` only — see the defect noted in SC-3 |
| G3 | Findings carry exploit-likelihood, not just severity | `GET /api/v2/scan/{id}/enriched` (`routes_v2.py:1749`) returns EPSS scores; `GET /api/v2/scan/{id}/kev-matches` (`:1812`) returns KEV hits |
| G4 | A release decision is machine-readable | `GET /api/v2/scan/{id}/policy-check` returns `overall_passed` (`routes_v2.py:2446`) |
| G5 | Scanner databases are never more than 3 h stale | `GET /api/v2/system/db-status` (`routes_v2.py:1439`) timestamp; beat entry `update-vulnerability-db-frequent` at 10800 s (`tasks.py:1289`) |
| G6 | Interactive scan capacity of 24 parallel high-priority scans | `HIGH_WORKER_REPLICAS` 3 × `WORKER_HIGH_CONCURRENCY` 8 (`docker-compose.yml:105,142`); `GET /api/v2/workers/queues` depth |
| G7 | No unauthenticated read of any vulnerability data | every `/api/v1` and `/api/v2` **HTTP** route carries `Depends(get_current_user)` or stricter; static report/SBOM serving is gated at `main.py:123 _serve_protected`. **Not met today:** both WebSocket routes are unauthenticated — see AU-10 |
| G8 | A user sees their own scans; an admin sees all | `routes.py:1096`, `routes.py:951`, `routes_v2.py:138` |
| G9 | Disk and stuck-scan self-healing without operator action | `cleanup_old_scan_artifacts` hourly (`tasks.py:1303`), `reap_stale_scans` every 10 min (`tasks.py:1312`) |
| G10 | The datastore can be repointed by configuration alone | `REDIS_URL` / `DATABASE_URL` / `READ_FROM_POSTGRES` / `WRITE_TO_REDIS` (`config.py:17,23,31,38`) |

### 1.3 Non-goals

Each verified against the code before assertion.

- **Not a runtime or EDR agent.** Nothing observes running containers. The only
  execution paths are CLI invocations of Grype/Trivy/Syft against an image
  reference (`scanners/*_scanner.py`) and Trivy misconfig against files
  (`iac_scanner.py:282 _run_trivy_scan`). No eBPF, no sidecar, no process
  monitoring anywhere in `app/app/`.
- **Not a SAST or DAST tool.** No source analyzer is installed or invoked;
  a repository-wide grep for `semgrep|bandit` in `app/` returns no matches.
  Trivy runs with `--scanners vuln,secret` (`trivy_scanner.py:70`) — package
  vulnerabilities and secret patterns, not code analysis.
- **Not an image builder, patcher, or registry.** Remediation output is advisory:
  `GET /api/v2/scan/{id}/remediation-script` (`routes_v2.py:1319`) returns text.
  A grep for `docker build|docker push` in `app/` returns no matches; the
  platform never rebuilds, re-tags, or pushes an image.
- **Not a Kubernetes admission controller.** No admission/validating-webhook
  route exists (grep `admission` in `app/` → no matches). Gating is pull-based:
  a caller asks for `policy-check`.
- **Not a signing or attestation service.** No cosign/sigstore code or
  dependency (grep `cosign|sigstore` in `app/` → no matches). SBOMs are emitted
  unsigned in SPDX/CycloneDX/Syft JSON (`routes.py:1063`).
- **Not a ticketing/workflow system.** The only outbound integration is a Google
  Chat webhook class (`scheduler.py:20`). No Jira/ServiceNow code exists
  (grep → no matches).
- **Not a CVE database of record.** KEV and EPSS are consumed from upstream
  (`enrichment.py:26,129`); scanner DBs are pulled by Grype/Trivy themselves
  (`updater.py`). Apex Scanner republishes, it does not curate.
- **Not a multi-tenant SaaS with self-service accounts.** Local identity is two
  env-defined accounts, `ADMIN_USERNAME` and optional `USER_USERNAME`
  (`config.py:154,169`); the only other identity source is Keycloak OIDC
  (`oidc.py`). There are no user-CRUD endpoints.
- **Not a general-purpose log or metrics platform.** `/metrics` is exposed
  (`main.py:95`) for an external Prometheus to scrape; the platform stores no
  time series itself.

### 1.4 Stakeholders

| Role | Needs from the system | Surface used |
|---|---|---|
| Application/dev engineer | Scan an image before release, see what to fix first, get a fix command | Dashboard `/scan`, `/scan/:scanId`; `POST /api/v1/scan`; `GET /api/v2/scan/{id}/quick-wins`, `/remediation-script` |
| DevSecOps / platform security (**requires admin role today**) | Define pass/fail thresholds, review KEV/EPSS exposure across images, manage VEX suppressions | Dashboard `/policies`, `/vex`, `/trends`; `POST /api/v2/policies`, `POST /api/v2/vex/statements` |
| CI/CD pipeline (non-human) | Non-interactive scan submission and a machine-readable gate verdict | `X-API-Key` header (`auth.py:307`); `POST /api/v1/scan` → poll `GET /api/v1/scan/{id}` → `GET /api/v2/scan/{id}/policy-check` |
| Release/compliance owner (**requires admin role today**) | Evidence that images were assessed and mapped to PCI-DSS/SOC2/HIPAA/FedRAMP controls | Dashboard `/compliance`; `GET /api/v2/scan/{id}/compliance` (`routes_v2.py:2601`); `GET /api/v2/export/{id}/pdf` |
| Base-image owner / build team (**requires admin role today**) | Which approved base images are drifting, and the delta since last catalog refresh | Dashboard `/base-images`, `/approved-base-images`; `GET /api/v2/base-images/history?image_name=<n>&tag=<t>`, `GET /api/v2/approved-base-images` |

**Role reality check.** Three of the seven stakeholder rows above cannot reach any of
their listed surfaces without holding the single shared admin account. All eight
base-image routes require `get_current_admin` (`routes_v2.py:588,606,626,648,664,698,738,826`),
and 12 of the 22 React routes are wrapped in `<ProtectedRoute requiredRole="admin">`
(`App.js:112-147`) including `/policies`, `/vex`, `/trends`, `/compliance`,
`/base-images` and `/dependency-graph`. Combined with AU-9 (only two local identities
exist), "DevSecOps", "release/compliance owner" and "base-image owner" are today the
same person as "administrator". Role granularity is tracked by AU-9, whose priority
this raises.
| Platform operator (SRE) | Queue depth, worker health, DB freshness, disk safety, scaling | Dashboard `/workers`, `/system`; `GET /api/v2/workers/*`, `GET /health/scanners`, Flower on `127.0.0.1:5555` |
| Administrator | Identity config, API key lifecycle, schedule management, cache invalidation | Dashboard `/schedules`, `/system`; `POST /api/v2/api-keys`, `DELETE /api/v2/cache/invalidate/{image}` |

---

## 2. User stories

Priorities are MoSCoW for the SDLC cycle now starting. For a brownfield system,
`Must` on a `[shipped]` story means "must not regress".

### 2.1 Scanning

**SC-1 — Start a single-image scan** `[shipped]` `routes.py:451`
As an application engineer, I want to submit a container image reference for
scanning, so that I get a correlated vulnerability verdict without running three
tools myself.
- verify: `POST /api/v1/scan` with body `{"image_name":"nginx:latest"}` and a valid
  session returns HTTP 202 and a body whose `scan_id` matches
  `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`.
- verify: the scan record reaches a status other than `in_progress` within
  `SCAN_TIMEOUT`. (Do not assert on an immediate `GET /api/v2/workers/queues` reading —
  a free worker can consume the task before the poll, so depth 0 is a legitimate
  outcome. Routing itself is config, asserted at `tasks.py:106`.)
- verify: unauthenticated `POST /api/v1/scan` returns 401 with detail
  `Authentication required. Provide a Bearer token, X-API-Key header, or Basic Auth credentials.`
- Priority: **Must**

**SC-2 — Parallel multi-engine execution with merge and dedup** `[shipped]`
`orchestrator.py:127,153,247,331,386`
As a security engineer, I want Grype and Trivy findings merged and deduplicated
into one list, so that I count each real vulnerability once.
- verify: `GET /api/v1/scan/{id}` for a completed scan of `alpine:3.18` returns
  `multi_scanner.scanners_used` containing both `grype` and `trivy`, and
  `both_scanners` > 0.
- verify: no two entries in `vulnerabilities.all` share the same `(id, package_name)`
  pair, excluding entries whose `id` is empty / `N/A` / `UNKNOWN`. The dedup key is
  `f"{vid}:{pkg}"` (`orchestrator.py:331-341`) — CVE id and package name only, no
  version — and returns `""` for unusable ids, which are deliberately left undeduped.
- Priority: **Must**

**SC-3 — Degraded and failed scans are distinguishable from clean scans** `[shipped]`
`tasks.py:716-739` (guard at `:723`), `routes.py:370`, `app/tests/test_scan_result_failed.py`
As a release owner, I want a scan that could not run to be reported as failed
rather than as zero findings, so that I never approve an image on a non-result.
- verify: with BOTH `grype` and `trivy` binaries renamed on all workers, a scan ends
  `status == "failed"` with a non-empty `error`. Renaming only one is not sufficient:
  the guard is `{"grype","trivy"}.issubset(scanners_failed)` (`tasks.py:721`), so a
  single-scanner failure yields `degraded`, not `failed`.
- DEFECT (raised by this story, not yet fixed): neither failure branch
  (`tasks.py:695-700`, `:731-736`) ever writes `scan_quality: "failed"` — only
  `reap_stale_scans` (`tasks.py:1610`) does. `routes.py:370` therefore defaults a
  hard-failed scan to `scan_quality: "degraded"`. Do not assert `scan_quality == "failed"`
  until that write exists.
- verify: with Grype failing but Syft producing packages, the scan completes with
  `scan_quality == "degraded"` and `multi_scanner.scanner_errors.grype` non-empty.
- Priority: **Must**

**SC-4 — Unusable image references fail loudly and safely** `[shipped]`
`routes.py:174 validate_image_name`, `scanner_errors.py`
As an engineer, I want a bad image reference rejected or reported in plain
language, so that I am not handed raw scanner stderr.
- verify: `POST /api/v1/scan` with `{"image_name":"--config=/etc/passwd"}` returns 422
  (flag-injection guard `if v.startswith("-")` at `routes.py:57-60` inside
  `_validate_image_ref`; `routes.py:176-178` is only the Pydantic wrapper).
- verify: `POST /api/v1/scan` with `{"image_name":"nosuchregistry.invalid/x:1"}` returns
  202, and the scan record ends `status == "failed"` with an `error` produced by
  `scanner_errors.classify_scanner_errors`, not a raw multi-line stderr dump.
- Priority: **Must**

**SC-5 — Concurrent duplicate submissions collapse to one scan** `[shipped]`
`routes.py:462-490` (`SET NX ex=600` on `scan_dedup:{image}`)
As a platform operator, I want two simultaneous requests for the same image to
share one scan, so that duplicate work does not consume worker slots.
- verify: two `POST /api/v1/scan` calls for the same image issued within 1 s return
  the same `scan_id` while the first is `in_progress`, with message
  `Scan already in progress for this image`.
- verify: after the first scan completes, a third `POST` for the same image returns
  a **new** `scan_id` (mutable tags must be re-scannable — `routes.py:488-490`).
- Priority: **Must**

**SC-6 — Opt-in digest cache for high-volume identical scans** `[shipped]`
`routes.py:160-172` (`skip_cache` defaults `True`), `enrichment.py:261 DEFAULT_TTL 86400`
As a CI owner, I want to opt in to reusing a recent result for an identical image
digest, so that a pipeline scanning the same digest repeatedly does not re-run
the engines.
- verify: after a cache hit, `HGET <new_scan_id> created_by` equals the requesting
  user. DEFECT today: the task copies the whole cached hash onto the new scan
  (`tasks.py:646-652`), overwriting the `created_by` that `routes.py:513` stamped, so a
  user opting into the cache inherits the original scanner's attribution. NFR-T1's
  non-empty check cannot detect this.
- verify: `POST /api/v1/scan` with `{"image_name":"<img>","skip_cache":false}` twice
  within 24 h for an unchanged digest — the second scan record carries
  `cache_hit` set and completes in under 5 s.
- verify: default `POST` without `skip_cache` runs the engines (scan duration
  comparable to a cold scan) — confirms fresh-by-default.
- Priority: **Should**

**SC-7 — Live scan progress** `[shipped]` `routes_v2.py:1136` `/ws/scan/{scan_id}`,
`:1168` `/ws/global`, `websocket_manager.py`
As an engineer watching a scan, I want progress pushed to the browser, so that I
do not poll blindly for 10 minutes.
- verify: opening a WebSocket to `/api/v2/ws/scan/{scan_id}` during an active scan
  yields at least one message before the scan reaches `completed`.
- verify: `/api/v2/ws/global` receives a message when any scan completes.
- Priority: **Should**

**SC-8 — Orphaned scans are reaped** `[shipped]` `tasks.py:1560`, beat 600 s `tasks.py:1312`
As a platform operator, I want scans abandoned by a dead worker marked failed, so
that queue and history views reflect reality.
- verify: create a Redis hash keyed by a UUID with `status=in_progress` and
  `created_at` 24 h in the past, run `reap_stale_scans`, then the hash has
  `status == "failed"` and `error == "Scan interrupted (orphaned in_progress) — reaped by stale-scan cleanup"`.
- verify: the corresponding `scan_dedup:{image}` key is deleted, so the image can
  be rescanned immediately.
- Priority: **Must**

**SC-9 — Secret detection inside images** `[shipped]` `trivy_scanner.py:70`
As a security engineer, I want embedded secrets reported alongside CVEs, so that
a leaked credential in a layer is not invisible.
- verify: scanning an image containing a test AWS-style key returns
  `multi_scanner.total_secrets >= 1` from `GET /api/v1/scan/{id}`.
- Priority: **Should**

**SC-10 — Cancel a running scan** `[gap]`
As an operator, I want to cancel a scan I started by mistake, so that a wrong
20-minute scan does not hold a worker slot.
- Missing: no cancel/abort route exists. `GET /openapi.json` contains no path
  matching `/scan/.*/(cancel|abort)`; the only interruption mechanism is
  `DELETE /api/v2/workers/queues/{queue_name}` (`routes_v2.py:1673`), which purges
  a whole queue and is admin-only.
- Looked in: `routes.py` (13 routes), `routes_v2.py` (97 routes), `tasks.py`.
- verify: `GET /openapi.json | jq '.paths | keys[]' | grep -i cancel` returns nothing
  today; after implementation, `POST /api/v1/scan/{id}/cancel` returns 202 and the
  scan record reaches `status == "cancelled"` within 30 s.
- Priority: **Could**

### 2.2 History, comparison, search, trends

**TR-1 — Per-image scan history** `[shipped]` `routes.py:933`, tenancy filter `routes.py:951-957`
As an engineer, I want the scan history for one image, so that I can see whether
we are improving.
- verify: `GET /api/v1/history/nginx%3Alatest` returns scans newest-first, at most
  `limit` entries — default 20, hard ceiling 100 (`routes.py:935`,
  `Query(20, ge=1, le=100)`).
- verify (storage side): `LLEN history:<image>` never exceeds
  `MAX_HISTORY_PER_IMAGE` = 100 (`config.py:142`). That setting bounds the stored list,
  not the response.
- verify: as a non-admin, the response excludes scans whose `created_by` is another
  user (`routes.py:957`).
- Priority: **Must**

**TR-2 — Compare two scans** `[shipped, admin-only]` `routes.py:748`, gate at `:751`
As a security engineer, I want a new/fixed/unchanged diff between two scans, so
that I can prove a rebuild actually reduced exposure.
- verify: `GET /api/v1/compare/{id1}/{id2}` as admin returns `new_vulnerabilities`,
  `fixed_vulnerabilities`, `unchanged_vulnerabilities`.
- verify: the same call as a non-admin user returns 403 with detail
  `Admin access required. This action is restricted to administrators.`
- Priority: **Should** (the 403 for ordinary users is an open question — see OQ-9)

**TR-3 — Cross-scan vulnerability search** `[shipped, admin-only]` `routes.py:827`, gate at `:834`
As a security engineer, I want to find every image affected by a given CVE or
package, so that I can scope an incident.
- verify: `GET /api/v1/vulnerabilities/search?cve=CVE-2024-3094` as admin returns
  matching scans; `limit` is bounded to 1000 and `offset >= 0` (`routes.py:832-833`).
- verify: the same call with no query parameter returns 400 with detail
  `At least one search parameter required (cve, package, severity, or image)`.
- Priority: **Should**

**TR-4 — Trends and dashboard statistics** `[shipped]` `routes_v2.py:910-969`, `routes.py:1140`
As a security lead, I want global and per-image trend series plus a top-vulnerable
list, so that I can report direction rather than a snapshot.
- verify: `GET /api/v2/trends/global`, `/trends/top-vulnerable`, `/trends/distribution`,
  `/trends/image/{name}` each return 200 with a non-empty series after two scans of
  the same image on different days.
- verify: `GET /api/v1/stats` as a non-admin counts only that user's scans
  (`routes.py:1145`).
- Priority: **Should**

### 2.3 Batch scanning

**BA-1 — Submit a bounded batch** `[shipped]` `routes.py:564`, validator `:197-203`
As a build owner, I want to scan a release manifest of images in one call, so that
I do not script 30 separate requests.
- verify: `POST /api/v1/scan/batch` with 3 images returns 202 with `batch_id` and 3
  `scan_ids`.
- verify: a request with 51 images returns HTTP 422. Assert the status only, not the
  message. DEFECT: `BatchScanRequest.images` carries a hardcoded `max_length=50`
  (`routes.py:193`) which Pydantic v2 enforces during core validation, before the
  `@field_validator` at `routes.py:197-203` runs — so the emitted detail is
  `List should have at most 50 items after validation, not 51` and the
  `Maximum {BATCH_MAX_IMAGES}` message at `routes.py:202` is unreachable over HTTP.
  Raising `BATCH_MAX_IMAGES` (`config.py:122`) has no effect until the hardcode goes.
- Priority: **Must**

**BA-2 — Track batch progress** `[shipped]` `routes.py:663`, `routes_v2.py:130,171`
As a build owner, I want per-image status inside a batch, so that I know which
image is holding up the release.
- verify: the per-scan `status` values in `scans[]` agree with the aggregate counters.
  (Do not assert that the counters sum to `total_images`: `routes.py:704` computes
  `in_progress` as `len(scan_ids) - completed - failed` and `total_images` as
  `len(scan_ids)`, so that identity holds by construction and can never fail.)
- verify: `GET /api/v2/batches/{batch_id}` returns per-scan rows with `image_name`
  and `status`.
- Priority: **Must**

**BA-3 — Gate a whole batch on policy** `[shipped]` `routes_v2.py:218`
As a release owner, I want one pass/fail verdict for a batch, so that a release
train has a single gate.
- verify: `GET /api/v2/batches/{batch_id}/policy-check` returns a verdict, and it is
  failing when any member scan violates an enabled `fail` rule.
- Priority: **Should**

**BA-4 — Batch visibility follows ownership** `[shipped]` `routes_v2.py:138,180,228`
As a user, I want to see only my own batches, so that other teams' release
contents are not exposed to me.
- verify: user A creates a batch; `GET /api/v2/batches` as user B omits it, and
  `GET /api/v2/batches/{id}` as user B returns 403/404 (`routes_v2.py:180`).
- verify: the same calls as admin return the batch.
- Priority: **Must**

### 2.4 Base images

**BI-1 — Register and manage tracked base images** `[shipped]`
`routes_v2.py:581` (create), `:601` (list), `:689` (update), `:818` (delete),
`:730` (details)
As a base-image owner, I want to register the images my org standardises on, so
that they are tracked independently of any application scan.
- verify: `POST /api/v2/base-images` with a valid image returns 200/201 and the
  entry appears in `GET /api/v2/base-images`.
- verify: `DELETE /api/v2/base-images/remove` for that entry removes it from the
  list; a non-admin caller receives 403 (`get_current_admin` at `:586`, `:823`).
- Priority: **Must**

**BI-2 — Base-image history and comparison** `[shipped]` `routes_v2.py:617,638`
As a base-image owner, I want to compare two base images and see one image's
history, so that I can justify a migration.
- verify: `GET /api/v2/base-images/compare?...` returns per-severity deltas between
  the two named images.
- verify: `GET /api/v2/base-images/history?image_name=<name>&tag=<tag>` returns dated
  entries after two runs of the base-image scan. Both query parameters are required
  (`routes_v2.py:623-624`); omitting them returns 422.
- Priority: **Should**

**BI-3 — Scheduled daily rescan of all base images** `[shipped]`
`routes_v2.py:657` (manual), `tasks.py:1123 scan_base_images`
(soft limit 7200 s, hard 7500 s), beat 86400 s (`tasks.py:1284`), queue `low_priority`
As a base-image owner, I want every tracked base image rescanned daily on the
lowest-priority queue, so that drift is caught without starving interactive scans.
- verify: `GET /api/v2/workers/queues` during a base-image run shows the tasks on
  `low_priority`, not `high_priority`.
- verify: after `POST /api/v2/base-images/scan-all`, each tracked image has a scan
  record whose `created_by` is `system` (`tasks.py:1159`).
- Priority: **Should**

**BI-4 — Detect the base OS of a scanned application image** `[shipped]`
`base_image_tracker.py:86 detect_base_image`, `:152 categorize_vulnerabilities`
As an engineer, I want to know which findings come from the base layer versus my
own layers, so that I fix the right thing.
- verify: `GET /api/v1/scan/{id}` returns a populated `base_image` object
  (`os_full_name`, `os_version`) for a Debian- or Alpine-derived image
  (`routes.py:398-406`).
- Priority: **Should**

### 2.5 Approved base-image catalog

**AC-1 — Read the org's approved base-image catalog** `[shipped]`
`routes_v2.py:2891`, `gitlab_catalog.py:105 get_catalog`, TLS pinning via
`GITLAB_CA_CERT` (`config.py:222`), 900 s Redis cache (`config.py:223`)
As an engineer, I want the authoritative list of approved base images with their
current findings and migration hints, so that I pick a sanctioned base.
- verify: `GET /api/v2/approved-base-images` returns catalog entries whose
  `report_url` points at this deployment's edge host, not at the GitLab-recorded
  origin (`gitlab_catalog.py:34 _normalize_report_url`).
  Preconditions: `GITLAB_CATALOG_ENABLED=true` (defaults false, `config.py:216`), a
  reachable `gitlab.sixdee`, a valid `GITLAB_TOKEN` PAT, and the pinned
  `GITLAB_CA_CERT`. None of these exist on a default deployment.
- verify: with `GITLAB_CATALOG_ENABLED=false`, the endpoint returns HTTP 503 with
  detail `The Approved Base Images catalog is not configured`
  (`routes_v2.py:2897-2901`) — not a 500, and not an empty 200.
- Priority: **Should**

**AC-2 — Fail a scan when the image is not built on an approved base** `[gap]`
As a release owner, I want the gate to fail an image built on an unapproved base,
so that the catalog has teeth.
- Missing: `policy_engine._get_field_value` field mappings (`policy_engine.py:437-444`)
  cover `severity`, `epss_score`, `in_kev`, `cve_id`, `package`, `license` only. No
  rule field references the catalog, and `gitlab_catalog.py` is not imported by
  `policy_engine.py`.
- Looked in: `policy_engine.py`, `routes_v2.py:2402`, `gitlab_catalog.py`.
- verify: today, creating a policy with `{"field":"approved_base_image","operator":"equals","value":false,"action":"fail"}`
  produces zero matches on any scan. After implementation, the same rule fails a
  scan of an image whose base OS is absent from `GET /api/v2/approved-base-images`.
- Priority: **Should**

### 2.6 Schedules

**SH-1 — Manage cron scan schedules** `[shipped]`
`routes_v2.py:394` (create), `:431` (list), `:447` (get), `:466` (update), `:486` (delete)
As an administrator, I want named schedules holding an image set and a cron
expression, so that recurring assessments are declared, not remembered.
- verify: `POST /api/v2/schedules` with `{"name":"nightly","images":["nginx:latest"],"cron_expression":"0 2 * * *"}`
  returns 200 and the schedule appears in `GET /api/v2/schedules`.
- verify: the same POST as a non-admin returns 403 (`get_current_admin` at `:399`).
- Priority: **Must**

**SH-2 — Run a schedule on demand** `[shipped]` `routes_v2.py:505`
As an administrator, I want to trigger a schedule immediately, so that I can
validate it without waiting for the cron window.
- verify: `POST /api/v2/schedules/nightly/run` returns `status: "triggered"` with
  `len(scan_ids) == image_count` and `new_scans == image_count - skipped_duplicates`.
  `scan_ids` is unconditionally full length — `routes_v2.py:541` appends the existing
  scan id for skipped images too; `new_scans` (`routes_v2.py:574`) carries the
  subtraction.
- Priority: **Must**

**SH-3 — Schedules actually fire on their cron expression** `[gap]`
As an administrator, I want a stored cron schedule to run itself, so that
"scheduled scanning" is not a manual button.
- Missing (two layers, both needed): the generated entries target a Celery task named
  `run_scheduled_scan` which is **not defined anywhere** — `grep -rn "run_scheduled_scan" app/`
  returns only `scheduler.py:477`, the string that names it. So wiring the builder into
  beat would register a schedule for a task that does not exist; the task itself must be
  written as well. Second layer: `scheduler.get_celery_beat_schedule()` (`scheduler.py:464`) builds the
  crontab entries from `schedule:*` Redis keys, but nothing imports it. `tasks.py:1283`
  assigns a **static** `celery.conf.beat_schedule` containing only
  `scan_base_images`, `update_vulnerability_databases`, `update_kev_database`,
  `cleanup_old_scan_artifacts`, `reap_stale_scans`. The `scheduler` compose service
  runs `celery beat` against that static dict (`docker-compose.yml:247`).
- Looked in: `tasks.py` (grep `schedule` — only the static block), `scheduler.py:464`,
  `routes_v2.py` (imports `ScheduleManager`, `GoogleChatNotifier` only, `:27`).
- verify: today, `grep -rn "get_celery_beat_schedule" app/app` returns only its
  definition at `scheduler.py:464`. After implementation, a schedule with cron
  `* * * * *` produces a new entry under `schedule_runs:{name}` within 3 minutes
  with no manual trigger.
- Priority: **Must**

**SH-4 — Notify a chat channel when a scheduled scan completes** `[gap]`
As a team lead, I want the scheduled scan result posted to our Google Chat space,
so that the team sees regressions without opening the dashboard.
- Missing: `GoogleChatNotifier.send_scan_report` (`scheduler.py:26`) and
  `send_summary_report` (`scheduler.py:190`) are called from exactly one place —
  `POST /api/v2/test-notification` (`routes_v2.py:1214`). No scan-completion path in
  `tasks.py` calls either. The per-schedule `google_chat_webhook` field is stored
  (`scheduler.py:343`) and never read at scan completion.
- Looked in: `tasks.py` (grep `GoogleChat|notifier|webhook` → no matches),
  `scheduler.py`, `routes_v2.py`.
- verify: today, `grep -rn "send_scan_report" app/app` returns `scheduler.py:26` and
  `routes_v2.py:1214` only. After implementation, running a schedule that has
  `google_chat_webhook` set delivers one card to the webhook per completed scan.
- Priority: **Must**

**SH-5 — Validate a webhook before relying on it** `[shipped]` `routes_v2.py:1191`
As an administrator, I want to send a test card to a webhook, so that I learn the
URL is wrong before a real finding is lost.
- verify: `POST /api/v2/test-notification` with a valid Google Chat webhook returns
  success and the space receives a card; with a malformed URL it returns a failure
  flag rather than a 500.
- Priority: **Should**

**SH-6 — Schedule-triggered scans have an owner** `[gap]`
As a user, I want scans created by a schedule I own to appear in my scan list, so
that tenancy is consistent across entry points.
- Missing: `run_schedule_now` writes the scan hash directly (`routes_v2.py:552-557`)
  with no `created_by` field and no `ownership.record_scan_owner` call — unlike
  `routes.py:513-515`. Base-image scans stamp `created_by: "system"` (`tasks.py:1159`),
  which no human user can see except an admin.
- Looked in: `routes_v2.py:505-576`, `ownership.py`, `routes.py:499-521`.
- verify: today, after `POST /api/v2/schedules/{name}/run`, `HGET <scan_id> created_by`
  returns nil and the scan is absent from a non-admin's `GET /api/v1/scans/recent`.
  After the fix, the scan appears for the schedule's owner.
- Priority: **Should**

### 2.7 Policy gates

**PG-1 — Define and manage security policies** `[shipped]`
`routes_v2.py:2195,2236,2267,2294,2336`; defaults seeded at `policy_engine.py:89-204`
("Production Security Gate", "Development Security Gate", "IaC Security Gate")
As a DevSecOps engineer, I want named rule sets over severity, KEV and EPSS, so
that different environments carry different bars.
- verify: on a fresh deployment, `GET /api/v2/policies` returns the three seeded
  policies with `enabled: true`.
- verify: `POST /api/v2/policies` as a non-admin returns 403 (`get_current_admin` at
  `:2201`); as admin it returns the created policy id.
- Priority: **Must**

**PG-2 — Evaluate a scan against all enabled policies** `[shipped]` `routes_v2.py:2402`
As a CI pipeline, I want a single boolean verdict for a scan, so that the pipeline
can stop.
- verify: `GET /api/v2/scan/{id}/policy-check` returns `overall_passed: false` for a
  scan containing a CRITICAL finding while the seeded production policy is enabled.
- verify: for an unknown `scan_id` it returns 404 with detail `Scan {scan_id} not found`.
- Priority: **Must**

**PG-3 — A rule that cannot be evaluated fails closed** `[shipped]` `policy_engine.py:325-343`
As a security engineer, I want a malformed rule to fail the gate rather than
silently pass it, so that a policy typo cannot ship a vulnerable image.
- verify: create a policy with a rule missing `operator`, then
  `POST /api/v2/policies/evaluate` returns `status: "failed"` and a violation whose
  message starts with `Rule could not be evaluated (treated as a violation):`.
- Priority: **Must**

**PG-4 — Ordered severity comparisons** `[shipped]` `policy_engine.py:466 SEVERITY_RANK`, `:471 _to_number`
As a DevSecOps engineer, I want `severity >= HIGH` to work, so that I do not have
to enumerate every severity as a separate equality rule.
- verify: a rule `{"field":"severity","operator":"greater_or_equal","value":"HIGH","action":"fail"}`
  matches CRITICAL and HIGH findings and does not match MEDIUM.
- Priority: **Must**

**PG-5 — `apply_to` image scoping is enforced** `[gap]`
As a DevSecOps engineer, I want a policy to apply only to matching image patterns,
so that a strict production policy does not fail every sandbox scan.
- Missing: `apply_to` is accepted (`routes_v2.py:2175`), persisted
  (`policy_engine.py:59,228,272`) and returned (`routes_v2.py:2230`), but never read
  during evaluation. `evaluate_vulnerabilities` (`policy_engine.py:300`) and
  `check_scan_policies` (`routes_v2.py:2423`) iterate all enabled policies with no
  image-pattern filter.
- Looked in: full-repo grep for `apply_to` — 13 hits, none comparative.
- verify: today, a policy with `apply_to: ["prod/*"]` still fails a scan of
  `sandbox/app:1`. After implementation, that scan is reported as skipped for that
  policy and `overall_passed` is unaffected by it.
- Priority: **Must**

**PG-6 — A single CI-facing scan-and-gate call** `[gap]`
As a CI pipeline, I want one call that scans and returns the gate verdict, so that
my job is not a hand-written polling loop.
- Missing: scanning is asynchronous by design (202 + `scan_id`, `routes.py:439`) and
  the gate is a separate GET (`routes_v2.py:2402`). No synchronous or
  wait-for-completion variant exists; `GET /openapi.json` contains no `/scan/sync`
  or `?wait=` parameter. The repo's own `.gitlab-ci.yml` scan stage shells Trivy
  directly (`.gitlab-ci.yml:144-156`) rather than calling this API — the platform
  does not yet gate its own pipeline.
- Looked in: `routes.py`, `routes_v2.py`, `.gitlab-ci.yml`.
- verify: today, `grep -n "api/v1/scan" .gitlab-ci.yml` returns nothing. After
  implementation, a documented CI snippet exits non-zero within one job when
  `overall_passed` is false, with no polling code in the pipeline file.
- Priority: **Should**

### 2.8 Enrichment and threat intelligence

**EN-1 — EPSS exploit-probability on every finding** `[shipped]`
`enrichment.py:26` (`https://api.first.org/data/v1/epss`, 86400 s cache),
`routes_v2.py:1749`, `:1920`
As a security engineer, I want each CVE annotated with its EPSS score, so that I
can rank by likelihood of exploitation rather than by CVSS alone.
- verify: `GET /api/v2/scan/{id}/enriched` returns entries carrying `epss_score`
  for CVEs present in the EPSS feed.
- verify: `POST /api/v2/epss/lookup` with `["CVE-2021-44228"]` returns a score
  between 0 and 1.
- Priority: **Must**

**EN-2 — CISA KEV matching, refreshed automatically** `[shipped]`
`enrichment.py:129,131` (12 h cache), `routes_v2.py:1812,1879,1890,1901`,
beat `update_kev_database` every 21600 s (`tasks.py:1298`)
As a security engineer, I want findings flagged when they are on the CISA KEV
list, so that actively-exploited issues are unmissable.
- verify: `GET /api/v2/kev/check/CVE-2021-44228` returns an in-KEV result.
- verify: `GET /api/v2/kev/status` reports a `last_updated` within the last 6 hours
  on a running deployment.
- verify: `GET /api/v2/scan/{id}/kev-matches` for an image containing a KEV CVE
  returns a non-empty list.
- Priority: **Must**

**EN-3 — CVSS v3.1 exploitability detail and high-risk shortlist** `[shipped]`
`routes_v2.py:853` (`/scan/{id}/cvss`), `:1843` (`/scan/{id}/high-risk`),
`cvss_enrichment.py`
As an engineer, I want the CVSS vector broken out and a pre-filtered high-risk
list, so that I can start work without reading 900 rows.
- verify: `GET /api/v2/scan/{id}/cvss` returns per-CVE attack-vector and
  privileges-required fields.
- verify: `GET /api/v2/scan/{id}/high-risk` returns a strict subset of the full
  vulnerability list.
- Priority: **Should**

**EN-4 — Enrichment works without direct internet egress** `[gap]`
As a platform operator in a restricted network, I want the KEV and EPSS feeds
pulled from an internal mirror, so that enrichment does not silently stop when
egress is blocked.
- Missing: both feed URLs are module constants — `enrichment.py:26` and
  `enrichment.py:129`. `config.py` exposes no override field for either. There is
  no health signal specific to feed staleness beyond `GET /api/v2/kev/status`.
- Looked in: `config.py` (all 60+ settings), `enrichment.py`.
- verify: today, `grep -n "EPSS\|KEV" app/app/config.py` returns nothing. After
  implementation, setting `KEV_FEED_URL` / `EPSS_FEED_URL` to an internal mirror
  makes `GET /api/v2/kev/status` report a fresh update with egress blocked.
- Priority: **Should**

### 2.9 Risk scoring

**RS-1 — Weighted composite risk score per scan** `[shipped]`
`routes_v2.py:1354`, `risk_scoring.py:56 DEFAULT_WEIGHTS`, factors at `:337-368`
As a security lead, I want one score combining CVSS, network exposure, known
exploit, active exploitation and fix availability, so that images are comparable.
- verify: `GET /api/v2/scan/{id}/risk-score` returns a numeric score plus a factor
  breakdown where every entry has `weight`, and entries other than `Fix Available`
  also have `contribution`. The `Fix Available` entry emits
  `factor`/`value`/`weight`/`impact` with no `contribution` (`risk_scoring.py:365-370`).
- Priority: **Should**

**RS-2 — Tune the scoring weights** `[shipped]` `routes_v2.py:1375` (GET), `:1400` (PUT),
normalization at `risk_scoring.py:619-627`
As a security lead, I want to adjust factor weights to our risk appetite, so that
the score reflects our environment.
- verify: `PUT /api/v2/risk-weights` with ALL eight `DEFAULT_WEIGHTS` keys present and
  summing to 2.0 succeeds, and the subsequent `GET /api/v2/risk-weights` returns weights
  summing to 1.0. A partial payload does not normalise correctly: `update_weights`
  normalises what was submitted then does `self.weights.update(new_weights)`
  (`risk_scoring.py:619-624`), leaving the merged set summing to something other than 1.0.
- verify: the values survive an API restart (persisted at `risk_scoring.py:627` under
  the Redis key `risk_weights`).
- Priority: **Should**

**RS-3 — Weight changes are attributable** `[gap]`
As a compliance owner, I want a record of who changed the scoring weights and
when, so that a score shift can be explained.
- Missing: `update_risk_weights` (`routes_v2.py:1405`) does not call `record_audit`.
  Audit writes exist only for `auth.login`, `auth.login_failed`, `policy.create`,
  `policy.delete`, `apikey.create`, `apikey.revoke` (`routes_v2.py:70,72,2219,2355,2468,2504`).
- Looked in: full-repo grep for `record_audit` — 6 call sites, none for weights,
  schedules, VEX, or base images.
- verify: today, after a weight change, the Postgres `audit_log` table gains no row.
  After the fix, it gains one row with `action = "risk_weights.update"` and the
  caller's username in `actor`.
- Priority: **Should**

### 2.10 Remediation

**RM-1 — Prioritised remediation plan** `[shipped]` `routes_v2.py:1273`, `remediation.py`
As an engineer, I want an ordered plan of package upgrades, so that I know what
to do first.
- verify: `GET /api/v2/scan/{id}/remediation` returns actions ordered so that the
  first entry resolves at least as many CVEs as any later entry.
- Priority: **Must**

**RM-2 — Quick wins** `[shipped]` `routes_v2.py:1294`
As an engineer, I want the small set of upgrades that clears the most findings,
so that I get maximum reduction for minimum change.
- verify: `GET /api/v2/scan/{id}/quick-wins` returns entries each carrying a
  `cves_fixed` count greater than zero.
- Priority: **Should**

**RM-3 — Copy-pasteable remediation script** `[shipped]` `routes_v2.py:1319`
As an engineer, I want the upgrade commands as a script, so that I do not retype
package manager invocations.
- verify: `GET /api/v2/scan/{id}/remediation-script` returns text containing at
  least one package-manager command appropriate to the detected base OS
  (`remediation.py:41-42` for the npm case).
- Priority: **Should**

### 2.11 Compliance mapping

**CO-1 — List supported frameworks** `[shipped]` `routes_v2.py:2589`,
`compliance.py:23` (`pci-dss-4.0`, `soc2`, `hipaa`, `fedramp`)
As a compliance owner, I want to see which frameworks the platform maps to, so
that I know what evidence I can produce.
- verify: `GET /api/v2/compliance/frameworks` returns exactly the four ids
  `pci-dss-4.0`, `soc2`, `hipaa`, `fedramp` with control lists.
- Priority: **Should**

**CO-2 — Per-scan control assessment** `[shipped]` `routes_v2.py:2601`,
`compliance.py:15` (1 h cache)
As a compliance owner, I want a scan mapped to specific controls with pass/fail,
so that an auditor sees a control statement rather than a CVE list.
- verify: `GET /api/v2/scan/{id}/compliance?framework=pci-dss-4.0` returns per-control
  results including control `6.3.3` with its `max_fixable_critical: 0` threshold
  applied (`compliance.py:42-48`).
- verify: an unknown framework id returns 400 or 404, not 500.
- Priority: **Should**

**CO-3 — Estate-level, point-in-time compliance report** `[gap]`
As a compliance owner, I want one report covering all in-scope images for a
period, so that I can hand a single artefact to an auditor.
- Missing: every compliance and export route is keyed by a single `scan_id`
  (`routes_v2.py:2601`, `:982`, `:1048`, `:1098`). `export.py` exposes only
  `ReportExporter` (`export.py:30`) operating per scan. No aggregation endpoint or
  date-range parameter exists.
- Looked in: `routes_v2.py` (all 97 routes), `export.py`, `compliance.py`.
- verify: today, `GET /openapi.json` contains no compliance path without a
  `{scan_id}` segment. After implementation,
  `GET /api/v2/compliance/report?framework=soc2&from=...&to=...` returns one document
  covering every scan in the window.
- Priority: **Could**

### 2.12 VEX

**VX-1 — Author and manage VEX statements** `[shipped]`
`routes_v2.py:2677,2706,2733,2753,2783`; validation at `vex.py:19-26`
As a security engineer, I want to record that a CVE does not affect our product
with a standard justification, so that triage decisions persist across scans.
- verify: `POST /api/v2/vex/statements` with `status: "not_affected"` and
  `justification: "vulnerable_code_not_present"` returns 200; with
  `justification: "because"` it returns an error naming the valid justifications
  (`vex.py:52`).
- verify: `POST` with `status: "maybe"` is rejected with the message listing
  `not_affected, affected, fixed, under_investigation`.
- Priority: **Should**

**VX-2 — Export and import OpenVEX documents** `[shipped]` `routes_v2.py:2803,2827`,
OpenVEX 0.2.0 (`vex.py:3`)
As a security engineer, I want to exchange VEX documents with suppliers and
consumers, so that exploitability statements travel with the artefact.
- verify: `GET /api/v2/vex/document/{scan_id}` returns a document with
  `@context` and `statements[]` conforming to OpenVEX 0.2.0.
- verify: `POST /api/v2/vex/import` with that document round-trips — the statements
  reappear in `GET /api/v2/vex/statements`.
- Priority: **Should**

**VX-3 — View a scan with VEX applied** `[shipped]` `routes_v2.py:2845`
As an engineer, I want the vulnerability list with `not_affected` findings marked,
so that I am not re-triaging decided issues.
- verify: after creating a `not_affected` statement for a CVE present in a scan,
  `GET /api/v2/scan/{id}/vex-enriched` marks that CVE as suppressed while
  `GET /api/v2/scan/{id}/enriched` still lists it.
- Priority: **Should**

**VX-4 — VEX decisions affect the policy gate** `[gap]`
As a release owner, I want a `not_affected` CVE to stop failing the gate, so that
accepted risk does not block every subsequent release.
- Missing: `check_scan_policies` (`routes_v2.py:2413`) loads raw findings via
  `VulnerabilityRepository.get_raw(scan_id)` and passes them straight to
  `policy_engine.evaluate_vulnerabilities` (`:2427`). `vex` is not imported by
  `policy_engine.py` and appears nowhere in the policy code path.
- Looked in: `routes_v2.py:2402-2449`, `policy_engine.py`, `vex.py`.
- verify: today, marking a CRITICAL CVE `not_affected` leaves
  `GET /api/v2/scan/{id}/policy-check` at `overall_passed: false`. After
  implementation, the same call returns `true` and names the suppressing statement.
- Priority: **Must**

### 2.13 IaC scanning

**IA-1 — Scan pasted IaC content and file sets** `[shipped]`
`routes_v2.py:2000` (content), `:2033` (files); tasks `scan_iac_content`
(`tasks.py:1626`), `scan_iac_files` (`tasks.py:1791`) — both run on a worker
because only worker images carry Trivy (`Dockerfile.worker:117`)
As an engineer, I want to check a Dockerfile or manifest for misconfigurations
before committing it, so that I catch problems at authoring time.
- verify: `POST /api/v2/iac/scan/content` with a Dockerfile containing `USER root`
  returns findings with non-zero `summary.high` or `summary.medium`.
- verify: the API container itself has no Trivy binary — the work is executed on a
  worker (`docker exec fastapi_scanner which trivy` returns non-zero).
- Priority: **Should**

**IA-2 — Scan a Git repository** `[shipped]` `routes_v2.py:2069`,
`iac_scanner.py:170 scan_git_repo`, transport guard `iac_scanner.py:190-192`
As a platform engineer, I want to scan a whole infrastructure repository, so that
I assess Terraform, Helm and K8s manifests together.
- verify: `POST /api/v2/iac/scan/repo` with an `https://` URL returns findings
  grouped by file.
- verify: the same call with `file:///etc`, `ssh://…`, `git://…` or `ext::sh -c id`
  is rejected before any clone — the guard at `iac_scanner.py:190` accepts only
  `https://` and `http://`.
- Priority: **Must**

**IA-3 — Gate IaC findings on policy** `[shipped]` `routes_v2.py:2106`,
`policy_engine.py:379 evaluate_iac_findings`, seeded "IaC Security Gate"
(`policy_engine.py:175`)
As a platform engineer, I want IaC findings judged by the same policy engine, so
that infrastructure and images share one bar.
- verify: `POST /api/v2/iac/scan/content/with-policy` for content with a CRITICAL
  misconfiguration returns a failing verdict under the seeded IaC policy.
- Priority: **Should**

**IA-4 — IaC scan results are durable and comparable over time** `[gap]`
As a platform engineer, I want IaC results stored like image scans, so that I can
show that misconfigurations are trending down.
- Missing: the IaC endpoints block on `task.get(timeout=60)` and return the payload
  directly (`routes_v2.py:2011-2019`). No repository call, no Redis write, no
  `scan_id` record. A grep of `tasks.py` in the IaC task range (`:1626-1810`) shows
  no `hset`/`setex`/`ScanRepository` usage. Consequences: no history, no trends, no
  export, and a scan slower than 60 s returns a synthetic `status: "failed"`
  (`routes_v2.py:2021-2030`) while the worker keeps running.
- Looked in: `routes_v2.py:2000-2160`, `tasks.py:1626-1810`, `repositories/`.
- verify: today, after a successful `POST /api/v2/iac/scan/content`, no Redis key
  contains the returned findings (`redis-cli --scan --pattern 'iac*'` is empty).
  After implementation, the result is retrievable by id and appears in a history
  listing.
- Priority: **Should**

### 2.14 License compliance

**LI-1 — Per-scan license classification and verdict** `[shipped]`
`routes_v2.py:882`, `license_compliance.py:283 evaluate`, `:168 classify_one`,
persisted via `LicenseRepository` during the scan (`tasks.py:768`)
As a legal/compliance reviewer, I want packages classified by license category
with a pass/warn/fail verdict, so that a copyleft dependency is caught before
release.
- verify: `GET /api/v2/scan/{id}/licenses` returns per-category counts and a
  `status` of `pass`, `warn` or `fail`.
- verify: for a scan whose SBOM could not be loaded, the endpoint returns 404 with
  detail `License compliance data not found for this scan` rather than a false pass.
- Priority: **Should**

**LI-2 — Configurable organizational license policy** `[gap]`
As a legal reviewer, I want to declare which licenses are forbidden here, so that
the verdict reflects our counsel's position rather than a built-in default.
- Missing: `license_compliance.evaluate(packages, policy=None)` accepts a policy
  dict (`license_compliance.py:283`) but the only caller — `evaluate_licenses(sbom_packages)`
  at `tasks.py:760` (aliased at `tasks.py:19`) — passes
  none, and the endpoint documents "the default policy" (`routes_v2.py:889`). No
  license-policy CRUD route exists; `policy_engine` maps a `license` field
  (`policy_engine.py:443`) but no seeded or documented rule uses it.
- Looked in: `license_compliance.py`, `tasks.py:749-780`, `routes_v2.py:882-906`,
  `policy_engine.py`.
- verify: today, `GET /openapi.json` contains no `/license-policy` path. After
  implementation, setting AGPL-3.0 to `fail` makes `GET /api/v2/scan/{id}/licenses`
  return `status: "fail"` for a scan containing an AGPL package.
- Priority: **Should**

### 2.15 Dependency analysis

**DA-1 — Dependency graph with vulnerability paths** `[shipped]`
`routes_v2.py:1228`, `dependency_analyzer.py:46 parse_sbom_dependencies`,
`:242 _calculate_vulnerability_paths`
As an engineer, I want to see which direct dependency pulls in a vulnerable
transitive package, so that I change the right line in my manifest.
- verify: `GET /api/v2/scan/{id}/dependency-graph` returns `nodes`, `edges` and at
  least one path terminating at a vulnerable package for an image with transitive
  CVEs.
- Priority: **Should**

**DA-2 — Blast radius of one package** `[shipped]` `routes_v2.py:1249`,
`dependency_analyzer.py:408 get_package_impact`, `:449 _get_all_dependents`
As an engineer, I want to know everything that depends on a package before I
upgrade it, so that I can size the change.
- verify: `GET /api/v2/scan/{id}/package-impact/openssl` returns the dependent set;
  for a package absent from the SBOM it returns 404, not an empty 200.
- Priority: **Could**

### 2.16 AI triage

**AI-1 — LLM triage summary for a scan** `[shipped, conditional]`
`routes_v2.py:2510`, `ai_triage.py:278 generate_triage`, 24 h cache (`ai_triage.py:37`)
As a security lead, I want an executive summary and top-five prioritised actions,
so that I can brief a team in one paragraph.
- verify: with a provider configured, `GET /api/v2/scan/{id}/ai-triage` returns
  `risk_classification` in `{critical_action, high_priority, monitor, accept_risk}`
  plus `prioritized_actions` of length ≤ 5.
- verify: calling it twice returns `cached: true` on the second call within 24 h.
- Priority: **Could**

**AI-2 — Absent or failing AI degrades, never breaks** `[shipped]`
`ai_triage.py:78 is_ai_enabled`, `:284-289`, `:348-361`; status at `routes_v2.py:2575`
As an engineer, I want the product to work fully with AI switched off, so that a
model outage never blocks a release decision.
- verify: with `AI_TRIAGE_PROVIDER` unset (the compose default, `docker-compose.yml:39`),
  `GET /api/v2/ai-triage/status` returns `enabled: false` and
  `GET /api/v2/scan/{id}/ai-triage` returns HTTP 200 with
  `error: "AI triage unavailable — configure AI_TRIAGE_PROVIDER (anthropic or openai)"`,
  not a 5xx.
- verify: with a provider pointed at an unreachable base URL, the endpoint returns
  an `error` field and the rest of the scan detail page still renders.
- Priority: **Must**

**AI-3 — Self-hosted model support for data residency** `[shipped]`
`ai_triage.py:58 _provider`, `:147-177` (OpenAI-compatible client honouring
`AI_TRIAGE_BASE_URL`), noise-stripping at `:105-132`
As a security officer, I want triage to run against an internally hosted model, so
that vulnerability inventories never leave our network.
- verify: with `AI_TRIAGE_PROVIDER=openai` and `AI_TRIAGE_BASE_URL` pointing at a stub
  HTTP server that returns a `<think>`-wrapped, markdown-fenced JSON body,
  `GET /api/v2/ai-triage/status` reports that endpoint and triage returns parsed JSON
  (noise stripping at `ai_triage.py:105-132`). The stub is the fixture — a real
  vLLM/Ollama deployment is not required and does not exist in any environment today.
- Priority: **Should**

### 2.17 Exports and reporting

**EX-1 — CSV exports of findings and SBOM** `[shipped]` `routes_v2.py:982,1016`
As an engineer, I want findings and package inventory as CSV, so that I can work
them in a spreadsheet or feed another system.
- verify: `GET /api/v2/export/{scan_id}/csv` returns `Content-Type: text/csv` with a
  header row and one row per finding.
- verify: `GET /api/v2/export/{scan_id}/sbom-csv` row count equals the scan's
  `total_packages`.
- Priority: **Should**

**EX-2 — Executive and detailed PDF reports** `[shipped]` `routes_v2.py:1048,1098`,
`export.py:30 ReportExporter`
As a release/compliance owner, I want a PDF suitable for a stakeholder or auditor,
so that I can distribute a result outside the tool.
- verify: `GET /api/v2/export/{scan_id}/pdf` returns `application/pdf` whose first
  page carries the image name and the severity counts matching
  `GET /api/v1/scan/{scan_id}`.
- Priority: **Should**

**EX-3 — HTML report and SBOM files served only to authenticated callers** `[shipped]`
`main.py:137,142`, `_serve_protected` at `main.py:123-134`, tests in
`app/tests/test_report_auth.py`
As a security officer, I want report URLs to be unreadable without a session, so
that a shared link does not leak an inventory of our vulnerabilities.
- verify: `curl -i https://apexscanner.6dcorp.internal/reports/<file>.html` with no
  credentials returns 401 with detail `Authentication required`.
- verify: the same request with `Accept: text/html` returns 302 to `/login`.
- verify: `curl --path-as-is` for `/reports/../../etc/passwd`, and separately for the
  percent-encoded `/reports/%2e%2e%2f%2e%2e%2fetc%2fpasswd`, each return 404 with detail
  `Not found` (realpath containment, `main.py:128-131`). `--path-as-is` is required:
  curl collapses dot segments client-side, so without it the guard is never exercised.
- verify: any authenticated user — not only the scan owner — can read the report;
  this is the deliberate design recorded at `main.py:103-108`.
- CONFLICT: this criterion and AU-8 cannot both hold. A report at
  `/reports/{scan_id}.html` contains the same finding set as the scan detail, so
  tenant-scoping the scan endpoint while leaving reports readable by every
  authenticated user leaves the boundary open. Blocked on OQ-11.
- Priority: **Must, gated on OQ-11**

**EX-4 — SBOM in all three standard formats** `[shipped]` `routes.py:1032,1063`
As a supply-chain consumer, I want the SBOM in SPDX, CycloneDX or Syft JSON, so
that it loads into whatever tool the consumer runs.
- verify: `GET /api/v1/sbom/{scan_id}/download/spdx-json`, `.../cyclonedx-json` and
  `.../syft-json` each return a parseable JSON document; any other format value
  returns 4xx.
- Priority: **Should**

### 2.18 Worker operations

**WK-1 — Worker, queue and task visibility** `[shipped]`
`routes_v2.py:1535,1549,1571,1641,1705`, `worker_monitor.py`
As a platform operator, I want live worker and queue state, so that I can tell a
backlog from an outage.
- verify: `GET /api/v2/workers/status` lists each running worker with its queues;
  `GET /api/v2/workers/queues` returns a depth per queue named in `tasks.py:92`
  (`high_priority`, `default`, `batch`, `low_priority`, `system`).
- verify: all `/workers/*` routes return 403 for a non-admin (`get_current_admin` at
  `:1540`, `:1554`, `:1576`, `:1646`, `:1710`).
- Priority: **Must**

**WK-2 — Liveness probe and queue purge** `[shipped]` `routes_v2.py:1654,1673`
As a platform operator, I want to ping workers and drain a poisoned queue, so that
I can recover without a redeploy.
- verify: `POST /api/v2/workers/ping` returns one entry per live worker.
- verify: `DELETE /api/v2/workers/queues/batch` as admin empties that queue —
  `GET /api/v2/workers/queues` shows depth 0 for `batch` afterwards.
- Priority: **Should**

**WK-3 — Autoscaling on queue depth** `[gap]` `autoscaler.py:15-22,186-202,204-255`,
`routes_v2.py:1599,1620`
As a platform operator, I want batch workers added when the queue is deep and
removed when it drains, so that capacity follows demand within a bounded range.
- Missing: the decision loop runs and records history, but actuation cannot execute.
  `scale_workers` shells `subprocess.run(['docker-compose','up','-d','--scale',...],
  cwd='/opt/new-grype-scanner-v1/app')` (`autoscaler.py:186-191`) and three independent
  things stop it: (a) the autoscaler image is built from `Dockerfile.worker`, which
  installs no `docker` or `docker-compose` binary — the only occurrence of the string is
  a comment at `Dockerfile.worker:151`; (b) the `autoscaler` service declares no
  `volumes` (`docker-compose.yml:290-315`), so that `cwd` does not exist inside the
  container; (c) it reaches Docker only through `docker-socket-proxy` with `POST: 0`
  (`docker-compose.yml:271`), which forbids container creation. Every attempt ends in a
  `FileNotFoundError` swallowed at `autoscaler.py:200-202`.
- verify: today, drive total queue depth above 10 and
  `docker ps --filter label=com.docker.compose.service=worker-batch | wc -l` is unchanged.
  After the fix, that count increases toward `MAX_WORKERS` and falls back on drain.
- verify: `GET /api/v2/workers/autoscaler` returns `config.min_workers: 2`,
  `config.max_workers: 10`, `config.scale_up_threshold: 10`,
  `config.scale_down_threshold: 2` — the values are nested under `config`
  (`routes_v2.py:1615`, populated from `autoscaler.py:288-294`), not at the top level.
- verify: with total queue depth above 10, `GET /api/v2/workers/scaling-history`
  records a scale-up decision whose reason matches
  `Queue depth (N) > threshold (10)`.
- Priority: **Should**

**WK-4 — Interactive (high-priority) capacity also autoscales** `[gap]`
As a platform operator, I want interactive scan capacity to scale, so that a burst
of dashboard scans does not queue behind a fixed slot count.
- Missing: `AutoScaler.get_worker_count` and `get_all_workers` filter on the Docker
  label `com.docker.compose.service=worker-batch` (`autoscaler.py:128,146`) and
  `scale_workers` scales only `worker-batch` (`autoscaler.py:187`). `worker-high` is
  fixed at `HIGH_WORKER_REPLICAS` (default 3, `docker-compose.yml:142`).
  Additionally, the scaling decision uses **total** queue depth
  (`autoscaler.py:115,222`), so a `high_priority` backlog scales the wrong pool.
- Looked in: `autoscaler.py`, `docker-compose.yml:98-149`.
- verify: today, enqueue 50 `scan_image` tasks and observe
  `docker ps --filter label=com.docker.compose.service=worker-high | wc -l` unchanged
  while `GET /api/v2/workers/scaling-history` shows `worker-batch` decisions.
- Priority: **Could**

### 2.19 Authentication and tenancy

**AU-1 — Browser login issuing an httpOnly cookie** `[shipped]`
`routes_v2.py:47` (login), `:91` (logout), `:114` (verify), cookie helpers
`auth.py:552,565`
As a user, I want to log in to the dashboard and stay logged in, so that I am not
re-authenticating on every page.
- verify: `POST /api/v2/auth/login` with valid credentials returns 200 and a
  `Set-Cookie` carrying `HttpOnly`; `GET /api/v2/auth/verify` with that cookie
  returns the username and role.
- verify: `POST /api/v2/auth/logout` clears the cookie and a subsequent
  `/auth/verify` returns 401.
- Priority: **Must**

**AU-2 — Keycloak SSO with server-side code exchange** `[shipped]`
`routes_v2.py:293,314`, `oidc.py`, group-to-role mapping via `OIDC_ADMIN_GROUP`
(`config.py:209`), default role `user` (`config.py:210`)
As a security officer, I want SSO where the token exchange happens server-side, so
that no OIDC token is exposed to browser JavaScript.
- verify: with `OIDC_ENABLED=true`, `GET /api/v2/auth/config` advertises SSO and
  `GET /api/v2/auth/oidc/login` redirects to the Keycloak authorize URL.
- verify: after callback, a member of the `devops` group receives `role: "admin"`
  from `/auth/verify`; a non-member receives `role: "user"`.
- Priority: **Must**

**AU-3 — Brute-force lockout on every password path** `[shipped]`
`auth.py:178 check_rate_limit` (5 attempts / 900 s from `config.py:187,191`), applied
to `/auth/login` and also to HTTP Basic at `auth.py:413`
As a security officer, I want password guessing throttled on all entry points, so
that an attacker cannot bypass the login throttle by using `curl -u` against any
authenticated endpoint.
- verify: five failed `POST /api/v2/auth/login` from one IP, then a sixth returns 429
  with a `Retry-After` header and detail beginning `Too many failed login attempts`.
- verify: five failed `curl -u wrong:wrong https://.../api/v1/stats` from one IP then
  a sixth returns 429, not 401.
- Priority: **Must**

**AU-4 — Refuse to start with insecure credentials** `[shipped]`
`auth.py:95 validate_credentials_or_die`, invoked at `main.py:299`
As a security officer, I want the service to refuse to boot on default or missing
secrets, so that a misconfigured deployment cannot serve traffic.
- verify: starting the API with `JWT_SECRET_KEY` empty exits with status 1 and prints
  `SECURITY ERROR: Cannot start with insecure credentials!` to stderr.
- verify: starting with plaintext `ADMIN_PASSWORD` and no `ADMIN_PASSWORD_HASH` also
  exits 1 with the bcrypt migration instruction.
- Priority: **Must**

**AU-5 — API keys for non-interactive callers** `[shipped]`
`routes_v2.py:2453,2473,2488`; `auth.py:264 create_api_key` (SHA-256 hashed at rest,
`auth.py:259`), `:307 validate_api_key`, `:359 revoke_api_key`
As a CI owner, I want a revocable key with an expiry, so that pipelines authenticate
without a human password.
- verify: `POST /api/v2/api-keys` returns the raw key exactly once; `GET /api/v2/api-keys`
  thereafter shows metadata with no `key` field.
- verify: `DELETE /api/v2/api-keys/{key_id}` makes a subsequent request bearing that
  `X-API-Key` return 401.
- verify: `HGETALL api_key:<sha256>` in Redis contains `key_hash` and never the raw key.
- Priority: **Must**

**AU-6 — API keys must not be implicitly administrative** `[gap]`
As a security officer, I want a CI key scoped to the identity and privileges it
needs, so that a leaked pipeline key does not grant full administrative access to
every tenant's data.
- Missing: `create_api_key` hardcodes `"role": "admin"` and
  `"created_by": settings.ADMIN_USERNAME` (`auth.py:276-277`); `validate_api_key`
  returns that role verbatim (`auth.py:330`). Every API key therefore satisfies
  `get_current_admin` (defined at `auth.py:440`; the role comparison is at `:451`) and,
  through `created_by`, is treated as the
  admin user by the ownership indexes. There is no scope, role, or owner parameter
  on `APIKeyCreate` (`auth.py:69-72`).
- Looked in: `auth.py:257-372`, `routes_v2.py:2453-2506`, `ownership.py`.
- verify: today, `POST /api/v2/api-keys` then
  `curl -H "X-API-Key: <key>" /api/v2/workers/queues` returns 200 (an administrative
  route) and `GET /api/v1/scans/recent` returns other users' scans. After the fix, a
  key created with role `user` receives 403 on `/api/v2/workers/queues`.
- Priority: **Must**

**AU-7 — List views are scoped to the caller** `[shipped]`
`routes.py:951,1096,1145`, `routes_v2.py:138,180,228`, `ownership.py`,
`app/tests/test_ownership.py`, `app/tests/test_ownership_api.py`
As a user, I want my scan lists to contain only my scans, so that team activity is
not disclosed across teams.
- verify: user A scans an image; `GET /api/v1/scans/recent` and `GET /api/v1/stats`
  as user B exclude it, and as admin include it.
- verify: the per-user index `user_scans:<username>` is trimmed to 2000 entries and
  carries `SCAN_RESULT_TTL` (`ownership.py:15,25-26`).
- Priority: **Must**

**AU-8 — Direct fetch of a scan by id is tenant-scoped** `[gap]`
As a user, I want another team's scan detail to be inaccessible to me even if I
know its id, so that tenancy is not merely a list filter.
- Missing: `get_scan_result` (`routes.py:719-733`) checks authentication only. It
  never compares `created_by` against `_user.username`, unlike the history endpoint
  (`routes.py:957`) or the batch endpoints (`routes_v2.py:180,228`). Scan ids are
  UUIDv4, so this is obscurity rather than access control. The same absence applies
  to the per-scan `/api/v2` enrichment routes (`:853`, `:882`, `:1228`, `:1273`,
  `:1354`, `:1749`, `:2510`, `:2601`, `:2845`), which take `Depends(get_current_user)`
  with no ownership assertion.
- Looked in: `routes.py:709-740`, `routes_v2.py` per-scan routes, `ownership.py`.
- verify: today, as non-admin user B, `GET /api/v1/scan/{id_owned_by_A}` returns 200
  with full findings. After the fix it returns 403 or 404, while an admin still gets 200.
- Note: this must be decided together with the deliberate "any authenticated user may
  read any report" design at `main.py:103-108` — the two policies directly conflict, and
  fixing AU-8 alone leaves the same data reachable through `/reports/{scan_id}.html`.
  Raised as OQ-11; AU-8's final priority follows that answer.
- Priority: **Must, gated on OQ-11**

**AU-10 — WebSocket connections are authenticated and scan-scoped** `[gap]`
As a security officer, I want the live-progress WebSockets to require the same
authentication as every other data path, so that vulnerability data is not streamed to
anonymous clients.
- Missing: neither WebSocket route takes an auth dependency. Both signatures are bare —
  `async def websocket_scan_progress(websocket: WebSocket, scan_id: str)`
  (`routes_v2.py:1136-1140`) and `async def websocket_global(websocket: WebSocket)`
  (`routes_v2.py:1168-1170`). `/api/v2/ws/global` therefore streams every scan-completion
  payload to any client that can reach the edge, with no credential and no tenancy
  filter. `/api/v2/ws/scan/{scan_id}` exposes any scan whose id is known or guessed.
- This is invisible to the obvious check: FastAPI does not emit `APIWebSocketRoute` into
  `openapi.json`, so an openapi-driven auth sweep reports full coverage while both
  routes are open. See NFR-SEC2.
- verify: today, `websocat ws://127.0.0.1:7070/api/v2/ws/global` with no cookie and no
  `X-API-Key` connects and receives scan payloads. After the fix, the same connection is
  closed with policy-violation code 1008 before any payload is sent.
- verify: after the fix, an authenticated non-admin connecting to
  `/api/v2/ws/scan/{id_owned_by_another_user}` is closed with 1008, while the owner and
  an admin connect successfully.
- Priority: **Must**

**AU-9 — More than two local identities** `[gap]`
As an administrator, I want per-person accounts, so that ownership and audit
attribute actions to a human.
- Missing: local identity is exactly `ADMIN_USERNAME` + `ADMIN_PASSWORD_HASH` and an
  optional `USER_USERNAME` + `USER_PASSWORD_HASH` (`config.py:154-176`,
  `auth.py:144-173`). No user table (`db/models.py` has `scans`, `vulnerabilities`,
  `batches`, `licenses`, `audit_log`, `kv_settings` — no users) and no user routes.
  Every non-SSO user therefore shares one of two identities, which makes
  `created_by` and `audit_log.actor` weak.
- Looked in: `config.py`, `auth.py`, `db/models.py`, `routes_v2.py`.
- verify: today, `GET /openapi.json | jq '.paths|keys[]' | grep users` is empty and
  `db/models.py` defines no user model. After the fix (or after mandating OIDC),
  two distinct humans produce two distinct `created_by` values.
- Priority: **Should** (may be satisfied by mandating Keycloak instead of building
  user CRUD — see OQ-6)

### 2.20 System administration and data platform

**SY-1 — Scanner and database freshness visibility** `[shipped]`
`routes_v2.py:1423` (tool versions), `:1439` (db status), `:1496` (update history),
`:1515` (notifications)
As a platform operator, I want to see scanner versions and when each vulnerability
DB was last refreshed, so that I can prove results are current.
- verify: `GET /api/v2/system/tool-versions` returns versions for grype, trivy and
  syft matching the binaries pinned in `Dockerfile.worker:33,49,65`
  (v0.116.0 / v0.72.0 / v1.49.0).
- verify: `GET /api/v2/system/db-status` reports a Grype and Trivy DB timestamp
  within the last 3 hours on a running deployment.
- Priority: **Must**

**SY-2 — Force a database update** `[shipped]` `routes_v2.py:1455`,
`tasks.py:1325 update_vulnerability_databases`, atomic swap at `updater.py:428,470`
As a platform operator, I want to pull fresh vulnerability data immediately, so
that I can rescan after a zero-day announcement without waiting 3 hours.
- verify: `POST /api/v2/system/update-db` as admin returns an accepted response and
  `GET /api/v2/system/db-status` shows a newer timestamp within 10 minutes.
- verify: a failed Trivy Java-DB download does not roll back the main DB update
  (`updater.py:417-424`).
- Priority: **Must**

**SY-3 — Readiness reflects real scanner availability** `[shipped]`
`main.py:219 scanner_health`, worker preflight publishing at `tasks.py:191-210`
(1 h TTL on `worker:health:<hostname>`)
As a platform operator, I want the health endpoint to fail when a scanner binary or
DB is broken, so that an orchestrator stops routing traffic to a useless instance.
- verify: `GET /health/scanners` returns 200 with all enabled scanners `healthy` on a
  good deployment.
- verify: with no worker health keys in Redis, it returns 503 and each scanner shows
  `error: "No worker health data available"`.
- Priority: **Must**

**SY-4 — Automatic artefact and scratch cleanup** `[shipped]`
`tasks.py:1467`, beat hourly (`tasks.py:1303`), `ARTIFACT_RETENTION_DAYS` = 7
(`config.py:148`), scratch cutoff `TMP_SCRATCH_MAX_AGE = max(SCAN_TIMEOUT*3+1800, 9000)`
(`tasks.py:66`), shared `/opt/scanner-tmp:/tmp` across all workers
(`docker-compose.yml:135,184,230`), test at `app/tests/test_scratch_cleanup.py`
As a platform operator, I want leaked scanner scratch directories reaped hourly, so
that the host disk cannot fill.
- verify: create `/opt/scanner-tmp/stereoscope-test` with an mtime older than
  `TMP_SCRATCH_MAX_AGE`, run `cleanup_old_scan_artifacts`, and the directory is gone
  with `deleted.tmp_scanner_dirs >= 1` in the task result.
- verify: a `stereoscope-*` directory younger than the cutoff is preserved.
- verify: report and SBOM files older than 7 days are deleted from
  `/opt/scanner-reports` and `/opt/scanner-sboms`.
- Priority: **Must**

**SY-5 — Digest cache inspection and invalidation** `[shipped]` `routes_v2.py:1943,1954`
As a platform operator, I want to drop the cached result for an image, so that a
re-pushed mutable tag is definitely rescanned.
- verify: `DELETE /api/v2/cache/invalidate/{image_name}` as admin returns success and
  the next `POST /api/v1/scan` with `skip_cache=false` runs the engines rather than
  returning a cache hit.
- Priority: **Should**

**SY-6 — Reversible, verifiable Redis-to-Postgres migration** `[partial]`
`config.py:31 READ_FROM_POSTGRES`, `:38 WRITE_TO_REDIS`, `db/dual_write.py`,
`db/read_pg.py`, `db/parity_check.py`, `db/backfill.py`, Alembic baseline
`db/migrations/versions/1d68b1e53cac_baseline_schema.py`
As a platform operator, I want the datastore cutover to be a flag flip that I can
verify and reverse, so that migration risk is bounded.
- verify: `docker exec -w /app fastapi_scanner python -m app.db.parity_check`
  (`db/parity_check.py:5`) prints `Extended parity check (Redis vs Postgres):` and
  reports zero diffs across scans, batches, vulnerabilities and licenses before any
  cutover.
- verify: with `READ_FROM_POSTGRES=true`, `GET /api/v1/scan/{id}` returns the same
  payload as with the flag false, for the same id.
- verify: flipping the flag back restores Redis reads without a data migration step.
- Partial because: phase 3 read cutover is not enabled anywhere (`READ_FROM_POSTGRES`
  default false, `config.py:31`), `parity_check` is a manual CLI with no endpoint or
  scheduled task, and `read_pg.py` is documented as "sync, best-effort" with a Redis
  fallback on miss (`architecture-map.md` §7), so a partial PG dataset silently reads
  through to Redis rather than erroring.
- Priority: **Must**

**SY-7 — Durable data has a defined retention and a purge that enforces it** `[partial]`
As a compliance owner, I want scan data to be retained for exactly as long as
policy requires and then removed, so that retention is enforced rather than
incidental.
- Enforced today: Redis scan hashes carry `SCAN_RESULT_TTL` = 2 592 000 s / 30 days
  (`config.py:66`, applied at `routes.py:514`, `:601`, `:622`, `tasks.py:1166`);
  per-user indexes expire on the same TTL (`ownership.py:26`); report and SBOM files
  are deleted after 7 days (`config.py:148`); Celery results expire after 86 400 s
  (`tasks.py:117`); Postgres dumps are pruned after `PG_BACKUP_RETENTION_DAYS` = 7
  (`docker-compose.yml:428`).
- Missing: Postgres rows never expire. `db/dual_write.py` upserts with no TTL
  concept and there is no purge task — a grep of `tasks.py` finds no Postgres
  deletion. Once `WRITE_TO_REDIS=false` (`config.py:38`), the 30-day TTL that is
  currently the de-facto retention policy disappears entirely and the dataset grows
  without bound. Redis `maxmemory-policy volatile-lru` (`docker-compose.yml:357`)
  also means a memory-pressured Redis may evict scan data **before** 30 days.
- verify: today, `SELECT count(*) FROM scans WHERE created_at < now() - interval '30 days'`
  returns a non-zero count on a deployment older than 30 days, while the matching
  Redis keys are gone. After the fix, the two agree within one purge interval.
- Priority: **Must**

**SY-8 — Administrative actions are auditable and readable** `[partial]`
`db/audit.py:16 record_audit`, table `audit_log` (`db/models.py:80`), indexes on
`actor` and `ts` (`1d68b1e53cac_baseline_schema.py:33-34`)
As a compliance owner, I want to read who changed what, so that an auditor can
review privileged activity.
- Covered today: login success, login failure, policy create, policy delete, API key
  create, API key revoke (`routes_v2.py:70,72,2219,2355,2468,2504`).
- Missing: no read path — no endpoint, no dashboard view, no export; the only access
  is direct SQL. Not covered: policy **update** (`routes_v2.py:2300`), schedule CRUD,
  VEX CRUD, base-image CRUD, risk-weight change, queue purge, cache invalidation,
  forced DB update. Writes are best-effort and swallow failures at debug level
  (`db/audit.py:34`), so an audit gap is silent. With `DATABASE_URL` empty the audit
  log does not exist at all (`main.py:320-321`).
- verify: today, `GET /openapi.json | jq '.paths|keys[]' | grep audit` is empty, and
  after `DELETE /api/v2/workers/queues/batch` the `audit_log` table gains no row.
  After the fix, every admin-gated mutating route produces exactly one row, and
  `GET /api/v2/audit?actor=...` returns it.
- Priority: **Should**

**SY-9 — Metrics are exposed and actually collected** `[partial]`
`main.py:84-97` (Prometheus instrumentator), `metrics.py` (20 custom collectors
including `SCANS_TOTAL`, `SCAN_DURATION`, `QUEUE_SIZE`, `WORKERS_ACTIVE`)
As a platform operator, I want scan throughput, duration and queue depth in our
monitoring system, so that I can alert before users notice.
- verify: `curl 127.0.0.1:7070/metrics` returns `text/plain` including
  `scanner_scans_total` and `http_requests_inprogress`. No metric carries an `apex_`
  prefix — all 20 collectors in `metrics.py` are prefixed `scanner_`
  (`SCANS_TOTAL = 'scanner_scans_total'`, `metrics.py:22`).
- Missing: nothing scrapes it in the shipped deployment. `docker-compose.yml` defines
  12 services and none is Prometheus, Grafana, or an exporter. The root
  `prometheus.yml` targets `api:8000`, `redis-exporter:9121` and `nginx:80`, of which
  only `api` exists in the compose file; `grafana/provisioning/datasources/prometheus.yml`
  has no consuming service either. No alert rules exist anywhere in the repository.
- verify: today, `docker compose -f app/docker-compose.yml config --services` lists no
  `prometheus` and no `grafana`. After the fix, a Prometheus target for `scanner-api`
  reports `UP` and at least one alert rule exists for scan-failure rate and queue depth.
- Priority: **Must**

### 2.21 Dashboard

The 90 stories above are all backend/API. These three cover user-facing behaviour that
no API criterion exercises. Anything else in the dashboard is deliberately unspecified
for this cycle.

**DB-1 — Session expiry returns the user to login without a dead page** `[shipped]`
`api.js:57-61` (`on401Response` on both instances), `App.js:77`, `context/AuthContext.js`
As a user, I want an expired session to send me to the login page, so that I am not
staring at a page of failed widgets.
- verify: with the dashboard open, delete the auth cookie, then trigger any data fetch —
  the app navigates to `/login` rather than rendering an error state.
- verify: the redirect fires for both API versions — the `on401Response` interceptor is
  registered on `api` and `apiV2` alike (`api.js:57-61`).
- Priority: **Must**

**DB-2 — Role-gated navigation matches the API's authorization** `[partial]`
`App.js:112-147` (`<ProtectedRoute requiredRole="admin">` on 12 of 22 routes),
`components/ProtectedRoute.js`
As a user, I want to be shown only what my role can actually use, so that I do not
navigate into a page that will 403.
- verify: signed in as a non-admin, the admin-only routes (`/policies`, `/vex`,
  `/trends`, `/compliance`, `/base-images`, `/dependency-graph`, `/schedules`,
  `/workers`, `/system`) are not reachable and are not offered in the sidebar.
- verify: every route the UI offers a non-admin returns 2xx for that user's role — no
  offered link 403s.
- Partial because: the gate is correct but the role model behind it is not. With only
  two local identities (AU-9), most real stakeholders must share the admin account, so
  the gate protects nothing in practice. See the role reality check in §1.4.
- Priority: **Should**

**DB-3 — All dashboard HTTP goes through the shared axios instances** `[shipped]`
`api.js:28,36` (`api` → `/api/v1`, `apiV2` → `/api/v2`), interceptors at `:57-61`
As a platform engineer, I want every page to use the two shared clients, so that auth,
the 401 redirect and the same-origin base URL cannot be bypassed by one page.
- verify: `grep -rn "axios.create" dashboard/src` returns matches only in
  `dashboard/src/api.js`.
- verify: `grep -rn ":7070" dashboard/src` returns no hardcoded host — a hardcoded port
  breaks behind the TLS edge with a mixed-content or connection-refused failure.
- Priority: **Must**

---

## 3. MoSCoW table

Every story in section 2 appears exactly once.

| ID | Title | Priority | Status |
|---|---|---|---|
| SC-1 | Start a single-image scan | Must | shipped |
| SC-2 | Parallel multi-engine execution with merge and dedup | Must | shipped |
| SC-3 | Degraded and failed scans distinguishable from clean | Must | shipped |
| SC-4 | Unusable image references fail loudly and safely | Must | shipped |
| SC-5 | Concurrent duplicate submissions collapse to one scan | Must | shipped |
| SC-6 | Opt-in digest cache | Should | shipped |
| SC-7 | Live scan progress over WebSocket | Should | shipped |
| SC-8 | Orphaned scans are reaped | Must | shipped |
| SC-9 | Secret detection inside images | Should | shipped |
| SC-10 | Cancel a running scan | Could | gap |
| TR-1 | Per-image scan history | Must | shipped |
| TR-2 | Compare two scans | Should | shipped |
| TR-3 | Cross-scan vulnerability search | Should | shipped |
| TR-4 | Trends and dashboard statistics | Should | shipped |
| BA-1 | Submit a bounded batch | Must | shipped |
| BA-2 | Track batch progress | Must | shipped |
| BA-3 | Gate a whole batch on policy | Should | shipped |
| BA-4 | Batch visibility follows ownership | Must | shipped |
| BI-1 | Register and manage tracked base images | Must | shipped |
| BI-2 | Base-image history and comparison | Should | shipped |
| BI-3 | Scheduled daily rescan of all base images | Should | shipped |
| BI-4 | Detect base OS of a scanned image | Should | shipped |
| AC-1 | Read the approved base-image catalog | Should | shipped |
| AC-2 | Fail a scan built on an unapproved base | Should | gap |
| SH-1 | Manage cron scan schedules | Must | shipped |
| SH-2 | Run a schedule on demand | Must | shipped |
| SH-3 | Schedules fire on their cron expression | Must | gap |
| SH-4 | Chat notification on scheduled scan completion | Must | gap |
| SH-5 | Validate a webhook before relying on it | Should | shipped |
| SH-6 | Schedule-triggered scans have an owner | Should | gap |
| PG-1 | Define and manage security policies | Must | shipped |
| PG-2 | Evaluate a scan against all enabled policies | Must | shipped |
| PG-3 | Unevaluable rule fails closed | Must | shipped |
| PG-4 | Ordered severity comparisons | Must | shipped |
| PG-5 | `apply_to` image scoping is enforced | Must | gap |
| PG-6 | Single CI-facing scan-and-gate call | Should | gap |
| EN-1 | EPSS exploit-probability on findings | Must | shipped |
| EN-2 | CISA KEV matching, auto-refreshed | Must | shipped |
| EN-3 | CVSS v3.1 detail and high-risk shortlist | Should | shipped |
| EN-4 | Enrichment without direct internet egress | Should | gap |
| RS-1 | Weighted composite risk score | Should | shipped |
| RS-2 | Tune the scoring weights | Should | shipped |
| RS-3 | Weight changes are attributable | Should | gap |
| RM-1 | Prioritised remediation plan | Must | shipped |
| RM-2 | Quick wins | Should | shipped |
| RM-3 | Copy-pasteable remediation script | Should | shipped |
| CO-1 | List supported frameworks | Should | shipped |
| CO-2 | Per-scan control assessment | Should | shipped |
| CO-3 | Estate-level compliance report | Could | gap |
| VX-1 | Author and manage VEX statements | Should | shipped |
| VX-2 | Export and import OpenVEX documents | Should | shipped |
| VX-3 | View a scan with VEX applied | Should | shipped |
| VX-4 | VEX decisions affect the policy gate | Must | gap |
| IA-1 | Scan pasted IaC content and file sets | Should | shipped |
| IA-2 | Scan a Git repository | Must | shipped |
| IA-3 | Gate IaC findings on policy | Should | shipped |
| IA-4 | IaC results are durable and comparable | Should | gap |
| LI-1 | Per-scan license classification and verdict | Should | shipped |
| LI-2 | Configurable organizational license policy | Should | gap |
| DA-1 | Dependency graph with vulnerability paths | Should | shipped |
| DA-2 | Blast radius of one package | Could | shipped |
| AI-1 | LLM triage summary for a scan | Could | shipped |
| AI-2 | Absent or failing AI degrades, never breaks | Must | shipped |
| AI-3 | Self-hosted model support | Should | shipped |
| EX-1 | CSV exports of findings and SBOM | Should | shipped |
| EX-2 | Executive and detailed PDF reports | Should | shipped |
| EX-3 | Reports and SBOMs served only to authenticated callers | Must | shipped |
| EX-4 | SBOM in SPDX, CycloneDX and Syft JSON | Should | shipped |
| WK-1 | Worker, queue and task visibility | Must | shipped |
| WK-2 | Liveness probe and queue purge | Should | shipped |
| WK-3 | Autoscaling on queue depth | Must | gap |
| WK-4 | Interactive capacity also autoscales | Could | gap |
| AU-1 | Browser login issuing an httpOnly cookie | Must | shipped |
| AU-2 | Keycloak SSO with server-side code exchange | Must | shipped |
| AU-3 | Brute-force lockout on every password path | Must | shipped |
| AU-4 | Refuse to start with insecure credentials | Must | shipped |
| AU-5 | API keys for non-interactive callers | Must | shipped |
| AU-6 | API keys must not be implicitly administrative | Must | gap |
| AU-7 | List views scoped to the caller | Must | shipped |
| AU-8 | Direct fetch of a scan by id is tenant-scoped | Must | gap |
| AU-9 | More than two local identities | Should | gap |
| AU-10 | WebSocket connections authenticated and scan-scoped | Must | gap |
| SY-1 | Scanner and database freshness visibility | Must | shipped |
| SY-2 | Force a database update | Must | shipped |
| SY-3 | Readiness reflects real scanner availability | Must | shipped |
| SY-4 | Automatic artefact and scratch cleanup | Must | shipped |
| SY-5 | Digest cache inspection and invalidation | Should | shipped |
| SY-6 | Reversible, verifiable Redis-to-Postgres migration | Must | partial |
| SY-7 | Defined retention with an enforcing purge | Must | partial |
| SY-8 | Administrative actions auditable and readable | Should | partial |
| SY-9 | Metrics exposed and actually collected | Must | partial |
| DB-1 | Session expiry returns the user to login | Must | shipped |
| DB-2 | Role-gated navigation matches API authorization | Should | partial |
| DB-3 | All dashboard HTTP goes through shared axios instances | Must | shipped |

Counts: 94 stories. Priority split: 47 Must, 42 Should, 5 Could.
Status split: 70 shipped, 5 partial, 19 gap.

---

## 4. Non-functional requirements

Each NFR states what the code enforces and, where nothing enforces it, says so.

### 4.1 Performance and timeouts

| NFR | Enforced value | Where | Check |
|---|---|---|---|
| NFR-P1 | Single scan budget 900 s (`SCAN_TIMEOUT`) | `config.py:86`, `docker-compose.yml:33` | verify: a scan of a large image either completes or is marked failed within the soft limit; it is never left `in_progress` past `SCAN_TIMEOUT*6` (reaper, `tasks.py:1574`) |
| NFR-P2 | Celery soft limit `SCAN_TIMEOUT*2` = 1800 s, hard `SCAN_TIMEOUT*3` = 2700 s | `tasks.py:78-79` | verify: `celery -A app.tasks.celery inspect conf` reports `task_time_limit: 2700`, `task_soft_time_limit: 1800` |
| NFR-P3 | Base-image sweep bounded at 7200 s soft / 7500 s hard | `tasks.py:1120-1121` | verify: `scan_base_images` never runs past 7500 s |
| NFR-P4 | Scanner timeouts are deliberately not retried | `orchestrator.py:109` | verify: a scanner that times out produces one attempt, not three, in the worker log |
| NFR-P5 | IaC synchronous call bounded at 60 s | `routes_v2.py:2018` | verify: an IaC scan exceeding 60 s returns a JSON body with `status: "failed"` rather than hanging the HTTP client. **Unenforced side effect:** the worker task keeps running after the API gives up — no cancellation |
| NFR-P6 | Redis broker visibility timeout 43 200 s | `tasks.py:124` | verify: `inspect conf` shows `broker_transport_options.visibility_timeout: 43200` |

### 4.2 Scale limits

| NFR | Enforced value | Where | Check |
|---|---|---|---|
| NFR-S1 | Max 50 images per batch | `config.py:122`, `routes.py:201` | verify: 51 images returns 422 |
| NFR-S2 | 24 parallel high-priority slots (3 replicas × concurrency 8) | `docker-compose.yml:105,142` | verify: `GET /api/v2/workers/status` reports 3 `worker-high` instances |
| NFR-S3 | 24 batch slots (2 replicas × concurrency 12), autoscalable to 10 replicas | `docker-compose.yml:159,189`; `autoscaler.py:16` | verify: `GET /api/v2/workers/autoscaler` reports `max_workers: 10` |
| NFR-S4 | Prefetch 1 and `max-tasks-per-child` 50/100/200 to bound memory and leaks | `tasks.py:83`, `docker-compose.yml:108,162,209` | verify: `inspect conf` shows `worker_prefetch_multiplier: 1` |
| NFR-S5 | Per-container caps: worker 4 CPU / 4 GB, API 2 CPU / 2 GB, Redis 2 CPU / 2.5 GB | `docker-compose.yml:144-149,86-93,372-379` | verify: `docker stats` shows no container exceeding its limit |
| NFR-S6 | Redis capped at 2 GB with `volatile-lru` eviction | `docker-compose.yml:356-357` | verify: `redis-cli config get maxmemory-policy` returns `volatile-lru`. **Risk:** under memory pressure, scan data is evicted before its 30-day TTL — a silent data-loss path while Redis remains authoritative |
| NFR-S7 | Per-user index capped at 2 000 entries | `ownership.py:15,25` | verify: a user with 2 100 scans has exactly 2 000 members in `user_scans:<name>` |
| NFR-S8 | History capped at 100 scans per image | `routes.py:518-521` (`add_to_history`, honours `MAX_HISTORY_PER_IMAGE`, `config.py:142`) | verify: `LLEN history:<image>` never exceeds 100. DEFECT: `routes_v2.py:563` hardcodes `ltrim(history_key, 0, 99)` and ignores the setting, so the two enforcers drift if the config changes |
| **Unenforced** | No target for images/day or peak concurrent scans is stated anywhere in code or config | — | see OQ-2 |
| **Unenforced** | No per-user or per-API-key request rate limit; `check_rate_limit` (`auth.py:178`) throttles failed logins only. A single key can enqueue unbounded scans | `auth.py:178`, `routes.py:451` | verify: 200 rapid `POST /api/v1/scan` calls with one API key are all accepted |

### 4.3 Availability and resilience

- NFR-A1 — Every long-lived service restarts automatically: `restart: unless-stopped`
  on all 12 compose services. verify: `docker kill fastapi_scanner` and the container
  is running again within 30 s.
- NFR-A2 — Startup ordering is health-gated: `api`, the three worker services and
  `flower` depend on `redis` and `postgres` with `condition: service_healthy`. The
  `scheduler` (celery beat) is gated differently — `redis: service_healthy` and
  `worker-high: service_started` only, not postgres (`docker-compose.yml:248-252`)
  (`docker-compose.yml:68-72,109-113,163-167,210-214,330-334`). verify:
  `docker compose up` never starts the API before `redis-cli ping` succeeds.
- NFR-A3 — Postgres unavailability must not stop the product while Redis is
  authoritative: startup logs a warning and continues (`main.py:313-321`); dual-write
  is best-effort (`db/dual_write.py`). verify: stop `apex_postgres`, then
  `POST /api/v1/scan` still returns 202 and the scan completes.
- NFR-A4 — Task delivery survives worker loss: `task_acks_late=True`,
  `task_reject_on_worker_lost=True`, `task_acks_on_failure_or_timeout=False`
  (`tasks.py:87-89`). verify: kill a worker mid-scan and the task is redelivered or
  the scan is reaped within 10 minutes (`tasks.py:1312`).
- NFR-A5 — Redis durability: AOF `appendonly yes` with `appendfsync everysec` plus RDB
  snapshots (`docker-compose.yml:351-355`). verify: `redis-cli config get appendonly`
  returns `yes`.
- NFR-A6 — Postgres backups: `pg-backup` sidecar dumps every `PG_BACKUP_INTERVAL`
  (86 400 s) retaining 7 days (`docker-compose.yml:416-433`). verify: the `pg-backups`
  volume contains a gzipped dump newer than 24 h.
  **Unenforced:** dumps stay on the same host in a local volume; no off-host copy and
  no restore test exists in the repository.
- NFR-A7 — Log volume is bounded at 50 MB × 5 files per container
  (`docker-compose.yml:7-11`). verify: `docker inspect` shows `max-size=50m` on every
  service.

### 4.4 Security

- NFR-SEC1 — All service ports bind to loopback only; TLS terminates at the edge proxy
  for `apexscanner.6dcorp.internal`. `api` `127.0.0.1:7070` (`docker-compose.yml:67`),
  `flower` `127.0.0.1:5555` (`:329`), `dashboard` `127.0.0.1:3001` (`:448`); `redis` and
  `postgres` publish no host port at all. verify: `ss -ltn` on the host shows no
  `0.0.0.0` binding for these ports.
- NFR-SEC2 — No unauthenticated data path on HTTP routes. Every `/api/v1` and `/api/v2`
  HTTP route depends on `get_current_user`, `get_current_admin` or `get_optional_admin`;
  static reports and SBOMs are gated at `main.py:123`. Public routes are exactly `/`,
  `/health`, `/health/scanners`, `/metrics`, `/docs`, `/redoc`, `/openapi.json`, the auth
  bootstrap routes `/api/v2/auth/login`, `/auth/config`, `/auth/oidc/login`,
  `/auth/oidc/callback`, plus `POST /api/v2/auth/logout` (`routes_v2.py:91-97`, no
  dependency) and `GET /api/v2/auth/status` (`routes_v2.py:262`, `get_optional_admin`
  returns `None` rather than raising).
  verify: enumerate `app.routes` in-process and assert every `APIRoute` outside that
  list returns 401/403 unauthenticated. Do NOT verify via `GET /openapi.json`: FastAPI
  omits `APIWebSocketRoute` from the schema, so an openapi-driven check is structurally
  blind to the two unauthenticated WebSocket routes (see AU-10) and passes while the
  hole is open.
- NFR-SEC3 — Secrets at rest: admin and user passwords are bcrypt hashes
  (`config.py:158,173`; `auth.py:152,165`); API keys are stored as SHA-256 digests
  only (`auth.py:259,274`). verify: `HGETALL api_key:<hash>` contains no plaintext key,
  and `.env` contains no `ADMIN_PASSWORD` plaintext.
- NFR-SEC4 — CORS is deny-by-default; the middleware is only installed when
  `CORS_ORIGINS` is non-empty, and never uses a wildcard (`main.py:70-81`). verify:
  with `CORS_ORIGINS` unset, a cross-origin `OPTIONS` receives no
  `Access-Control-Allow-Origin` header.
- NFR-SEC5 — Command-injection and traversal guards: image references are validated
  before reaching a scanner CLI (`routes.py:174`, `_validate_image_ref`); IaC repo URLs
  accept only `http(s)` to block `file://`, `ssh://`, `git://`, `ext::sh`
  (`iac_scanner.py:190-192`); IaC filenames go through `_safe_join`
  (`iac_scanner.py:19`); report and SBOM paths are realpath-contained
  (`main.py:128-131`). Tests: `app/tests/test_iac_security.py`,
  `app/tests/test_report_auth.py`. verify: each hostile input above returns 4xx and
  produces no subprocess invocation.
- NFR-SEC6 — Scanner binaries are supply-chain verified at build time: Grype v0.116.0,
  Trivy v0.72.0 and Syft v1.49.0 are downloaded with their publisher checksum files and
  validated with `sha256sum -c` (`Dockerfile.worker:32-78`). The build fails on
  mismatch. verify: the build log contains `Grype installed and verified successfully`
  and the two equivalents.
- NFR-SEC7 — Docker socket exposure is brokered and read-only: only the `autoscaler`
  reaches Docker, via `tecnativa/docker-socket-proxy` with `CONTAINERS: 1` and every
  other capability including `POST`, `EXEC` and `IMAGES` set to 0
  (`docker-compose.yml:260-279`); the socket is mounted `:ro`. Workers do **not**
  mount the socket (`docker-compose.yml:96-97`) — scanners pull images directly from
  registries. verify: `docker exec` into a worker and confirm `/var/run/docker.sock`
  is absent.
- NFR-SEC8 — Container user: the API runs as the non-root `scanner` user
  (`Dockerfile.api:53`). Workers do **not** — `Dockerfile.worker` creates the `scanner`
  user (`:107-108`) but never issues `USER`, and `worker-entrypoint.sh:54-55` states
  "Run command as root to avoid bind-mount permission failures" before `exec "$@"`.
  So three worker services and the beat scheduler run as uid 0 with a shared host
  bind-mount at `/opt/scanner-tmp`. This is a knowingly accepted exception; whether it
  is permanent is OQ-1. verify: `docker exec <worker> id -u` returns `0` today; the
  target state is `1000`.
- NFR-SEC9 — Credential hygiene is enforced at boot: the API exits non-zero on a
  default or missing `JWT_SECRET_KEY` or a plaintext `ADMIN_PASSWORD`
  (`auth.py:95-139`, `main.py:299`); compose refuses to render without
  `REDIS_PASSWORD`, `POSTGRES_PASSWORD`, `JWT_SECRET_KEY`, `ADMIN_PASSWORD_HASH`,
  `FLOWER_USER`, `FLOWER_PASSWORD` (required `?` substitutions throughout
  `docker-compose.yml`). verify: `docker compose config` with any of those unset fails
  with the named error.
- NFR-SEC10 — CI blocks secret leakage into images, but only at one of two stages. The
  `validate` stage runs `app/scripts/ci-secret-scan.sh` (`.gitlab-ci.yml:53-56`) and IS
  blocking. The image self-scan before publish (`.gitlab-ci.yml:144-156`) sets
  `allow_failure: true` (`.gitlab-ci.yml:145`, "non-blocking until the Trivy DB mirror is
  confirmed on runners") and therefore cannot block anything today.
  verify: a commit adding a `.env` to the build context fails the pipeline at `validate`.
- **Unenforced:** `COOKIE_SECURE` defaults to `false` (`docker-compose.yml:56`). Behind
  the TLS edge this should be `true` in every deployed environment; nothing in the code
  forces it. verify: `docker exec fastapi_scanner env | grep COOKIE_SECURE` on the
  production host.
- **Unenforced:** no CSRF token on cookie-authenticated state-changing routes. The
  cookie is `HttpOnly` and CORS is deny-by-default, which mitigates but does not
  eliminate cross-site request forgery for same-origin-hosted content.
  verify: `grep -rn "csrf" app/app --include=*.py` returns only the two OIDC
  state-parameter sites (`oidc.py:74`, `routes_v2.py:331`) and no token issued or
  validated on any non-OIDC state-changing route. (The earlier claim that the grep
  returns nothing was wrong — it returns those two.)

### 4.5 Tenancy

- NFR-T1 — Every scan and batch is stamped with `created_by` at creation
  (`routes.py:513,600,621`) and indexed per user (`ownership.py:37,42`). verify:
  `HGET <scan_id> created_by` is non-empty for any scan created via `/api/v1`.
- NFR-T2 — Non-admins see only their own scans and batches in list, stats and history
  views (`routes.py:951,1096,1145`; `routes_v2.py:138,180,228`). verify: the
  cross-user checks in AU-7.
- NFR-T3 — Admin role is required for destructive and global operations: schedules,
  base images, policies, API keys, worker control, system updates, compare and search
  (`get_current_admin` at 40+ sites). verify: each returns 403 for a `user`-role token.
- **Known holes, all with stories:** direct scan fetch is not owner-checked (AU-8);
  every API key is admin and attributed to the admin user (AU-6); schedule-triggered
  scans have no owner (SH-6); reports are readable by any authenticated user by
  deliberate design (`main.py:103-108`), which contradicts AU-8's target.

### 4.6 Observability

- NFR-O1 — Structured JSON logging by default across the app
  (`logging_config.py`, `LOG_FORMAT=json` at `docker-compose.yml:35`). verify:
  `docker logs fastapi_scanner | head -1 | jq .` parses.
- NFR-O2 — Request-scoped context on scan operations via `LogContext`
  (`routes.py:456,569,726`). verify: log lines for a scan carry `scan_id` and `image`.
- NFR-O3 — 20 domain metric collectors plus FastAPI instrumentation are exposed at
  `/metrics` (`metrics.py`, `main.py:95`). verify: the NFR check in SY-9.
- NFR-O4 — Worker preflight health is published to Redis with a 1 h TTL and surfaced at
  `GET /health/scanners` (`tasks.py:204`, `main.py:219`). verify: SY-3.
- NFR-O5 — Celery task introspection is available through Flower on
  `127.0.0.1:5555` with mandatory basic auth (`docker-compose.yml:327`). verify:
  an unauthenticated request to Flower returns 401.
- **Unenforced:** nothing scrapes `/metrics`, no dashboards are provisioned into the
  deployment, and no alert rules exist (SY-9). Operational awareness today is
  pull-based through the dashboard `/workers` and `/system` pages.

### 4.7 Data retention

Stated as enforced values; the policy of record is OQ-3.

| Data | Retention | Enforced by |
|---|---|---|
| Scan hashes, batch records, vuln lists, license JSON (Redis) | 30 days | `SCAN_RESULT_TTL` 2 592 000 s, `config.py:66`, applied at `routes.py:514,601,622` |
| Same data in Postgres | unbounded | nothing — no purge task exists (SY-7) |
| Per-user indexes | 30 days | `ownership.py:26` |
| Per-image history list | last 100 entries; 30-day TTL **except on the batch path** (`routes.py:605` passes no ttl — "no TTL on the batch path, as before"), so history keys first created by a batch never expire | `config.py:142`, `routes.py:518-521,605`, `routes_v2.py:563-564` |
| HTML reports, SBOM files | 7 days | `ARTIFACT_RETENTION_DAYS`, `config.py:148`, `tasks.py:1477` |
| Scanner scratch dirs in `/tmp` | `max(SCAN_TIMEOUT*3+1800, 9000)` s | `tasks.py:66,1525` |
| Celery task results | 24 h | `tasks.py:117` |
| AI triage output | 24 h | `ai_triage.py:37` |
| Compliance assessment | 1 h | `compliance.py:15` |
| KEV feed cache | 12 h | `enrichment.py:131` |
| EPSS feed cache | 24 h | `enrichment.py:27` |
| GitLab catalog cache | 15 min | `config.py:223` |
| Worker health records | 1 h | `tasks.py:206` |
| Postgres dumps | 7 days | `docker-compose.yml:428` |
| Audit log rows | unbounded | nothing |
| Login-attempt counters | 900 s | `config.py:191`, `auth.py:203` |
| API keys | 365 days default | `auth.py:72,285` |

---

## 5. Open questions

Each blocks a decision that cannot be read out of the code. Owner for all:
vishnu.raveendran (vishnu.prakash@6dtech.co.in).

**OQ-1 — Are root-running workers accepted permanently, or is dropping to uid 1000 in
scope for this cycle?**
The API already runs as `scanner` (`Dockerfile.api:53`). `Dockerfile.worker` builds the
same user but issues no `USER`, and `worker-entrypoint.sh:54` documents the choice:
"Run command as root to avoid bind-mount permission failures". The bind mounts in
question are `/opt/scanner-reports`, `/opt/scanner-sboms`, `/opt/scanner-tmp` and the
two scanner caches. Blocks: NFR-SEC8, and any container-hardening item in the
feasibility and plan stages. The code shows the current state, not the decision.

**OQ-2 — What is the target scale: images scanned per day, peak concurrent scans, and
number of tracked base images?**
The code encodes capacity (24 high-priority slots, 24 batch slots autoscaling to 10
replicas, 50 images per batch) but no target anywhere states what demand this must
serve. Blocks: sizing the Postgres migration, deciding whether AU-6 and request rate
limiting are urgent, and whether WK-4 (high-priority autoscaling) matters.

**OQ-3 — What is the retention policy of record for scan data, reports and audit rows?**
The code enforces three different windows — 30 days in Redis, 7 days for report and
SBOM files, unbounded in Postgres — and Redis `volatile-lru` may evict earlier than 30
days under pressure. Once `WRITE_TO_REDIS=false`, the only enforced retention
disappears. Blocks: SY-7, Postgres capacity planning, and whether compliance evidence
(CO-2 output) survives long enough to be evidence.

**OQ-4 — Is there a deadline or trigger for the Postgres read cutover, and who signs
off the parity check?**
`READ_FROM_POSTGRES` defaults false (`config.py:31`); `parity_check.py` is a manual CLI
with no endpoint, no scheduled run and no recorded pass. Blocks: SY-6, and whether
phases 3–4 belong in this cycle's plan or the next.

**OQ-5 — Who consumes the compliance assessments, and are they audit evidence or
internal hygiene?**
Four frameworks are hardcoded with specific thresholds (`compliance.py:23` onward, e.g.
PCI-DSS 6.3.3 `max_fixable_high: 5`, SOC2 CC8.1 `max_scan_age_days: 7`). Nothing in the
code says who set those numbers or who receives the output. Blocks: CO-3 priority, and
whether the thresholds must become configurable rather than hardcoded.

**OQ-6 — Is Keycloak the intended sole identity source, or must local per-person
accounts be built?**
Local auth supports exactly two accounts (`config.py:154,169`); OIDC is present but
`OIDC_ENABLED` defaults false (`config.py:203`). AU-9 can be closed either by building
user management or by mandating SSO and reducing local accounts to a break-glass
admin. Blocks: AU-9, and the strength of `created_by` and `audit_log.actor`.

**OQ-7 — Should API keys carry a role and an owner, and what should existing keys
become on the change?**
Every key today is created with `role: "admin"` and `created_by: ADMIN_USERNAME`
(`auth.py:276-277`). Fixing AU-6 is a breaking change for any pipeline already using a
key against an admin route. Blocks: AU-6, and the tenancy model in AU-8.

**OQ-8 — Were automatic cron firing (SH-3) and scheduled-scan chat notification (SH-4)
descoped deliberately, or are they defects?**
Both have complete supporting code that is never wired: `get_celery_beat_schedule`
(`scheduler.py:464`) is never imported, and `send_scan_report` (`scheduler.py:26`) is
reachable only from `POST /api/v2/test-notification`. The business idea document states
"Google Chat notifications on scheduled scans" as a shipped feature, which the code
contradicts. Blocks: whether these are P1 bug fixes or new feature work in the plan.

**OQ-9 — Should `compare` and `search` remain admin-only?**
`routes.py:751` and `:834` require `get_current_admin`, while every other read surface
is `get_current_user` with ownership filtering. This looks like an inconsistency rather
than a policy. Blocks: TR-2, TR-3, and the consistency target for AU-8.

**OQ-11 — Are HTML reports tenant-scoped, or shareable among all authenticated users?**
`main.py:103-108` records a deliberate decision that any authenticated user may read any
report or SBOM, and EX-3 carries that as an acceptance criterion. AU-8 requires the
opposite for the same data: a report at `/reports/{scan_id}.html` contains the same
finding set as `GET /api/v1/scan/{scan_id}`. Tenant-scoping the API while leaving reports
open closes nothing. Both stories are currently Must, so the cycle cannot start until one
of them changes. Blocks: AU-8, EX-3, and the tenancy target in NFR-T3.

**OQ-10 — Which registries must be supported, and should scanning a private image be
attributable to the requesting user?**
The credential *mechanism* is not open — it is a single shared Docker config file
bind-mounted read-only into every worker (`DOCKER_CONFIG_PATH`,
`docker-compose.yml:126,180`), defaulting to
`scripts/empty-docker-config.json`. What is open is the required registry list and
whether per-user attribution is needed. There is no per-user, per-team or per-registry
credential store, so all users scan with one machine identity. Blocks: whether private
registry support needs a credential-management story, and whether scanning a private
image should be attributable to the requesting user.

---

## 6. Handoff notes

- **Needs architect (not decided here):** whether IaC results get their own storage
  domain or reuse the scan schema (IA-4); whether the CI gate is a new synchronous
  endpoint, a callback, or a CLI (PG-6); how VEX suppression is composed into policy
  evaluation without a second full pass over findings (VX-4); where the Postgres purge
  runs and how it interacts with `volatile-lru` eviction (SY-7); the monitoring
  topology for SY-9.
- **Highest-risk gaps by blast radius:** AU-6 (every API key is an admin for every
  tenant), AU-8 (scan detail is not owner-checked), PG-5 (`apply_to` silently ignored,
  so a strict policy applies everywhere), VX-4 (accepted risk cannot unblock a gate),
  SH-3/SH-4 (a documented feature does not run).
- **Test coverage context for stage 6:** `routes_v2.py` (2 906 LOC, 97 endpoints) and
  `tasks.py` (1 810 LOC) have no dedicated test file (`architecture-map.md` §10). Every
  gap story above lands in one of those two modules. The suite is 17 `test_*.py` modules
  plus `conftest.py` and `__init__.py` (19 files in `app/tests/`).
- **Corrections to prior project notes, verified in code:** workers do not mount the
  Docker socket (`docker-compose.yml:96-97`; access is brokered read-only to the
  autoscaler only); scanner binaries are checksum-verified at build
  (`Dockerfile.worker:32-78`); the API container runs as non-root
  (`Dockerfile.api:53`) while the three worker services and beat still run as uid 0
  (`worker-entrypoint.sh:54`); Python is 3.12 on both images
  (`Dockerfile.api:4`, `Dockerfile.worker:83`); a test suite (17 test modules) and a
  GitLab CI pipeline both exist.
