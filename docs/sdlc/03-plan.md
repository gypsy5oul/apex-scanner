# 03 — Project Plan

**Project:** Apex Scanner 3.0
**Status:** awaiting approval (stage 3 of 10)
**Date:** 2026-08-02
**Mode:** Brownfield remediation over a live production system. Every task
below changes running software; none builds a new one.
**Inputs:** `01-requirements.md`, `02-feasibility.md`, and the four decisions
recorded in `state.json` on 2026-08-02.

**Sizing is relative, estimated from code inspection only. No team velocity,
team size, or historical cycle-time data was available. XS≈half a day,
S≈1–2 d, M≈3–5 d, L≈6–10 d. Treat these as ordering weights, not commitments.**

---

## Contents

- [1. Decisions this plan is built on](#1-decisions-this-plan-is-built-on)
- [2. Milestones](#2-milestones)
- [3. Backlog](#3-backlog)
- [4. Dependency order](#4-dependency-order)
- [5. Not in this cycle](#5-not-in-this-cycle)
- [6. Still-open questions carried forward](#6-still-open-questions-carried-forward)

---

## 1. Decisions this plan is built on

Answered 2026-08-02. These override what `01-requirements.md` and
`02-feasibility.md` say where they differ.

| OQ | Answer | Effect on this plan |
|---|---|---|
| OQ-11 | Reports stay readable by any authenticated user | **AU-8 drops Must→Should** and is largely cosmetic — the same findings stay readable at `/reports/{scan_id}.html`. Demoted to M6, not funded as a sprint. AU-10's second criterion inherits the weaker rule |
| OQ-7 | API keys gain role+owner; existing keys grandfathered admin | AU-6 is buildable with no pipeline breakage. **Exposure persists until every key is rotated**, so T-31 is a rotation task with a named owner, not a code task |
| OQ-5 | Compliance output is or will be audit evidence | **SY-8 rises Should→Must.** `compliance.py:23` thresholds must become configurable. AU-9 becomes a compliance dependency |
| OQ-3 | Postgres retention matches the 30-day Redis `SCAN_RESULT_TTL` | T-43 builds exactly that |
| Compliance window | **30 days**, answered 2026-08-02 | T-44 is unblocked. Operational and compliance retention are deliberately equal. Forces `ARTIFACT_RETENTION_DAYS` 7 → 30 so the report files outlive neither the record nor each other. Residual risk recorded in T-44: 30 days cannot evidence an annual audit |
| T-31 owner | **devops-ops**, assigned 2026-08-02 | The key rotation that actually closes the AU-6 exposure now has a named owner |

---

## 2. Milestones

Each ends in something demonstrable to a person, not a layer completed.

| # | Milestone | Demonstrable at the end |
|---|---|---|
| **M0** | Ground truth | Characterization suite runs in CI and fails when a shipped behaviour changes; five spikes answered; six ADRs merged. Demo: deliberately break an endpoint, watch CI catch it |
| **M1** | Close the anonymous feed | `websocat` to `/api/v2/ws/global` with no credential is refused. Demo: connect anonymously, get closed 1008; connect authenticated, receive payloads |
| **M2** | A gate you can trust | Demo: a sandbox image passes under a `prod/*`-scoped policy that used to fail it; a CVE marked `not_affected` no longer blocks release; an image on an unapproved base fails |
| **M3** | Scoped credentials | Demo: a key created with role `user` gets 403 on `/api/v2/workers/queues`; an admin key still works; every production key rotated and logged |
| **M4** | Audit evidence that survives an auditor | Demo: `GET /api/v2/audit?actor=…` returns rows for a policy edit, a queue purge and a weights change; PG purge removes 31-day-old rows; thresholds edited without a redeploy |
| **M5** | Schedules that actually run | Demo: create a schedule with cron `* * * * *`, walk away, come back to scan records and a Google Chat card — no manual trigger |
| **M6** | Cleanup slice | Demo: EPSS/KEV pulled from an internal mirror with egress blocked; license policy set to fail AGPL and a scan turns red; risk-weight change appears in the audit log |

---

## 3. Backlog

Sizes: XS / S / M / L. No task is XL. Every task carries a runnable check.

### M0 — Ground truth

**T-01 — Authenticated test-client fixture** · size S · files: `app/tests/conftest.py`
Story: enables M1 (regression safety). Dependencies: none. **Task zero.**
`conftest.py:49-63` provides fakeredis only — no authenticated client, no
`dependency_overrides`, so every new `routes_v2` test currently hand-mints a JWT.
- Acceptance: a fixture yields a `TestClient` authenticated as admin and one as
  a non-admin `user`, both via `dependency_overrides`, no hand-minted JWTs.
- step → verify: a test using the admin client gets 200 on
  `/api/v2/workers/status` and the same test using the user client gets 403.
  (A `grep` for `dependency_overrides` would be satisfied by a comment, and
  `pytest tests/ -q` already passes today — neither can fail.)

**T-02 — Characterization suite for `routes_v2.py`** · size L · files: `app/tests/test_routes_v2_characterization.py`
Stories: the 36 shipped Must "must not regress" obligations. Depends: T-01.
Only 7 of 97 `routes_v2` endpoints are exercised today.
**Size correction: L was optimistic — this is an XL and must split.**
T-02a read-only GET routes (M), T-02b mutating routes (M), T-02c the four IaC
routes (S) which call `task.get(timeout=60..180)` (`routes_v2.py:2018,2055,2092,2128`)
with no Celery worker in CI and would otherwise hang the suite for ~7 minutes —
stub `AsyncResult` there.
- Acceptance: every `routes_v2` endpoint has at least a status-code and
  response-shape assertion for the authenticated-happy and unauthenticated
  cases. Not behavioural depth — a tripwire.
- step → verify: an in-process test enumerates `app.routes`, computes the set of
  paths covered by the suite, and asserts ≥90 of 97 are present, failing with
  the uncovered list. **Do not count with `--collect-only`** — that counts
  tests, so five tests against one endpoint would satisfy it.

**T-03 — Characterization suite for `tasks.py`** · size M · files: `app/tests/test_tasks_characterization.py`
Depends: T-01. `tasks.py` is 1,810 LOC with no dedicated test file.
- Acceptance: `scan_image` happy path, both failure branches
  (`tasks.py:695-700`, `:731-736`), the cache-hit path, and `reap_stale_scans`
  each have a test running against fakeredis with scanners stubbed.
- step → verify: `cd app && python -m pytest tests/test_tasks_characterization.py -q` passes.

> **CHECKPOINT C1** — the regression tripwire exists. Demo: change a status code
> in `routes_v2.py`, run the suite, watch it fail, revert.

**T-04 — Spike S1: WebSocket auth transport** · size S · time box 1 d · files: none (findings only)
Depends: none. Runs in parallel with T-01..T-03.
- Acceptance: a written answer to whether the edge proxy forwards the HttpOnly
  cookie on the WS `Upgrade` and whether SameSite survives. Browsers cannot set
  headers on WebSockets, so this decides cookie-vs-ticket for AU-10.
- step → verify: findings appended to `docs/sdlc/spikes/S1.md`, naming which
  transport ADR-11 should adopt.

**T-05 — Spike S4: production API key inventory** · size XS · time box 1 d
Depends: none.
- Acceptance: count of live keys, holders, and which routes each calls.
- step → verify: `docs/sdlc/spikes/S4.md` records counts from
  `api_keys:index` (`auth.py:294`) and `last_used` (`:326`), cross-referenced
  against edge access logs. Determines T-31's rotation window.

**T-06 — Spike S2: production parity + read latency** · size S · time box 2 d
Depends: none. Informs SY-6, which is out of cycle — run it anyway so next
cycle starts with data.
- Acceptance: a recorded parity verdict against the production dataset and a
  measured `read_scan_detail` latency at real row counts, sufficient for next
  cycle to size SY-6 without re-running the spike.
- step → verify: `docker exec -w /app fastapi_scanner python -m app.db.parity_check`
  output and `read_scan_detail` timings recorded in `docs/sdlc/spikes/S2.md`.

**T-07 — Spike S5: monitoring topology** · size XS · time box 0.5 d
Depends: none.
- Acceptance: a yes/no on whether a central Prometheus can scrape this host,
  with the owning team named if yes.
- step → verify: `docs/sdlc/spikes/S5.md` states whether 6D runs a central
  Prometheus that can scrape this host. Gates SY-9, which is out of cycle.

**T-08 — Spike S3: autoscaler actuation options** · size S · time box 2 d
Depends: none. Gates WK-3, which is out of cycle. Run only if capacity allows.
- Acceptance: a recommendation naming one actuation option, with the Docker API
  surface each would expose, so the security sign-off has something concrete to
  approve or refuse.
- step → verify: `docs/sdlc/spikes/S3.md` compares proxy `POST:1` + Docker SDK,
  a host agent polling a Redis desired-replicas key, and Swarm/systemd, with
  the resulting Docker API surface for each.

**T-09 — ADR-4: policy-evaluation input contract** · size S · files: `docs/adr/0004-policy-context.md`
Depends: none. **Gates T-21, T-22, T-23** — without it three builders invent
three context-passing schemes.
- Acceptance: decides how `image_name`, base OS and VEX suppressions reach
  `policy_engine.evaluate_vulnerabilities` (`policy_engine.py:300`), which also
  serves `evaluate_iac_findings` (`:379`), batch gating and IaC-with-policy.
- step → verify: ADR merged with status Accepted and a named `ScanContext`
  shape; `ls docs/adr/0004-*.md`.

**T-10 — ADR-8: decompose `routes_v2.py` (touched domains only)** · size S · files: `docs/adr/0008-routes-split.md`
Depends: none. **Gates the parallelism of everything in M2–M4.**
- Acceptance: decides whether to split auth/tenancy, policy and iac into
  domain routers before the cycle. 13 stories otherwise serialize on one
  2,906-LOC file.
- step → verify: ADR merged; if the decision is "split", T-11 is created.

**T-11 — Execute the `routes_v2.py` split** · size M · files: `app/app/routes_v2.py` → `app/app/routes/{auth,policy,iac,…}.py`
Depends: T-02, T-10, **T-20 and T-21** (T-20 is an out-of-band hotfix inside
`routes_v2.py`; splitting the file underneath it would conflict).
Conditional on ADR-8 deciding "split".
- Acceptance: endpoints move; no behaviour changes; all URLs unchanged.
- step → verify: commit a snapshot of sorted `(path, methods)` from
  `app.routes` before the split; after it, diff the same snapshot and require
  zero differences. (A route *count* is preserved by any split that mounts the
  routers, including one that changes paths — the exact regression this task
  promises not to cause.)

**T-12 — ADR-3: scheduled-execution mechanism** · size XS · files: `docs/adr/0003-scheduling.md`
Depends: none. Gates M5.
- Acceptance: picks between RedBeat, a custom `Scheduler` subclass, and a
  1-minute beat tick that polls Redis and dispatches. Must account for the beat
  shelve at `/tmp/celerybeat-schedule` living in a container with no volumes —
  schedule state has to be in Redis regardless.
- step → verify: ADR merged.

**T-13 — ADR-6: retention of record** · size XS · files: `docs/adr/0006-retention.md`
Depends: none. Gates T-41.
- Acceptance: records the OQ-3 answer (PG matches the 30-day Redis TTL), and
  records the unresolved tension with OQ-5 plus the 7-day report expiry as an
  explicit open item, not a silent gap.
- step → verify: ADR merged and references T-43.

**T-14 — ADR-2: API-key identity model** · size XS · files: `docs/adr/0002-api-keys.md`
Depends: T-05 (S4 evidence). Gates T-30.
- Acceptance: records OQ-7's grandfathering decision and the rotation plan.
- step → verify: ADR merged.

**T-15 — Postgres service in the CI pytest job** · size XS · files: `.gitlab-ci.yml` (`:120-138`)
Depends: none. **Gates T-40a/b/c, T-41, T-43** — every one of their checks needs
a live database, and the pytest job starts none today, so the SY-8 Must and the
SY-7 purge would ship with tests that cannot run in the gate.
- Acceptance: the pytest job declares a `postgres:16-alpine` service and a
  `DATABASE_URL` pointing at it; DB-backed tests run in CI rather than being
  skipped.
- step → verify: a CI run shows the DB-backed tests executed, not skipped —
  `pytest -q -m "not skip"` output in the job log lists them as passed.

> **CHECKPOINT C2** — spikes answered, ADRs merged, tripwire green. Go/no-go on
> the remaining milestones with real evidence. Demo: a failing test that
> imports the `ScanContext` type ADR-4 names, proving the decision is concrete
> enough to build against — not a document walkthrough.

### M1 — Close the anonymous feed

**T-20 — Authenticate both WebSocket routes** · size S · files: `app/app/routes_v2.py` (`:1136`, `:1168`), `app/app/websocket_manager.py`
Story: AU-10 (Must). Depends: T-04 (transport decision), T-01.
**Ship this out of band if the cycle boundary would delay it.** Today both
routes take bare signatures and `/ws/global` streams every scan-completion
payload to anyone who can reach the edge with no credential.
- Acceptance: unauthenticated connect is closed with code 1008 before any
  payload. Authenticated connect works. Fix the two latent bugs in passing:
  `finally: await pubsub.disconnect()` (`:1165`) raising `UnboundLocalError`
  when `manager.connect` throws, and one `RedisPubSubManager` per connection
  (`:1152`, `:1174`) — share one.
- step → verify: through the edge — `websocat wss://apexscanner.6dcorp.internal/api/v2/ws/global`
  with no cookie closes 1008; with a valid cookie it receives a payload. The
  loopback `127.0.0.1:7070` case is the negative test only; verifying solely
  there would bypass the edge and miss the exact question spike S1 exists to
  answer. Plus a pytest case
  using `TestClient.websocket_connect` asserting `WebSocketDisconnect(1008)`.
- Note: per-scan tenancy on `/ws/scan/{id}` follows the OQ-11 rule — any
  authenticated user may connect, matching the report policy. Do not build a
  stricter rule here than the reports enforce.

**T-20b — Dashboard WebSocket client** · size S · files: `dashboard/src/api.js` (`:301-309`)
Story: AU-10 / SC-7. Depends: T-04. **Must deploy together with T-20.**
`api.js:304` and `:309` build `ws://${host}:7070/api/v2/ws/...` — hardcoded
port, no credential, bypassing the edge. Authenticating the server side without
this ships M1 and kills live scan progress for every user.
- Acceptance: the client uses the S1-chosen transport (cookie or ticket) and
  derives its URL from the page origin through the edge, not a hardcoded
  `:7070`. Matches the existing shared-instance rule in `api.js`.
- step → verify: `grep -c ":7070" dashboard/src/api.js` returns 0; open a scan
  in the browser through `apexscanner.6dcorp.internal` and observe live
  progress; log out and confirm the socket closes.

**T-21 — Route-enumeration auth test** · size XS · files: `app/tests/test_auth_coverage.py`
Story: NFR-SEC2. Depends: T-20.
The current hole was invisible because FastAPI omits `APIWebSocketRoute` from
`openapi.json`, so an OpenAPI-driven sweep reports full coverage while both
routes are open.
- Acceptance: a test enumerates `app.routes` in-process — including
  `APIWebSocketRoute` — and asserts every route outside the documented public
  list rejects unauthenticated access.
- step → verify: `cd app && python -m pytest tests/test_auth_coverage.py -q`
  passes, and the test fails if a new unauthenticated route is added.

> **CHECKPOINT C3** — the anonymous feed is closed and a test prevents its
> return. Demo: anonymous `websocat` refused; add a bare route, watch T-21 fail.

### M2 — A gate you can trust

All three of these change the same call and must be one builder, sequentially,
after ADR-4.

**T-22 — Thread `ScanContext` into policy evaluation** · size M · files: `app/app/policy_engine.py`, `app/app/routes_v2.py` (`:2408`)
Stories: enables PG-5, VX-4, AC-2. Depends: T-09, T-02.
`check_scan_policies` reads only `VulnerabilityRepository.get_raw` (`:2413`),
so image name, base OS and VEX state are absent from the evaluation input.
- Acceptance: the context object from ADR-4 reaches
  `evaluate_vulnerabilities` without changing any current verdict.
- step → verify: `cd app && python -m pytest tests/test_policy_engine.py -q`
  passes unchanged — this task must be behaviour-neutral.

**T-23 — Enforce `apply_to` image scoping** · size S · files: `app/app/policy_engine.py`
Story: PG-5 (Must). Depends: T-22.
`apply_to` is accepted (`routes_v2.py:2175`), stored (`policy_engine.py:59`) and
never read.
- Acceptance: a policy with `apply_to: ["prod/*"]` is skipped for a scan of
  `sandbox/app:1`, and `overall_passed` is unaffected by it.
- step → verify: new pytest case asserts a `prod/*` policy does not fail a
  `sandbox/*` scan and does fail a `prod/*` scan.

**T-24 — Apply VEX suppressions to the gate** · size S · files: `app/app/policy_engine.py`, `app/app/vex.py`
Story: VX-4 (Must). Depends: T-22.
- Acceptance: a CVE with a `not_affected` statement no longer fails the gate,
  and the response names the suppressing statement.
- step → verify: create a `not_affected` statement for a CRITICAL CVE present
  in a scan, then `GET /api/v2/scan/{id}/policy-check` returns
  `overall_passed: true` — asserted in pytest.

**T-25 — Approved-base-image gate rule** · size S · files: `app/app/policy_engine.py`, `app/app/gitlab_catalog.py`
Story: AC-2 (Should). Depends: T-22.
- Acceptance: a rule `{"field":"approved_base_image","operator":"equals","value":false,"action":"fail"}`
  fails a scan whose base OS is absent from `GET /api/v2/approved-base-images`.
  **The catalog lookup must not block the event loop:** `get_catalog` is a
  synchronous `httpx.Client(timeout=20.0)` (`gitlab_catalog.py:96,105`), so on
  a cache miss it would stall the single uvicorn process for up to 20 s from
  the async handler at `routes_v2.py:2402`. Resolve it at scan time or run it
  in a threadpool.
- Precondition: `GITLAB_CATALOG_ENABLED=true`, a valid `GITLAB_TOKEN` and the
  pinned `GITLAB_CA_CERT` — absent on a default deployment.
- step → verify: pytest with the catalog stubbed asserts the rule matches and
  fails; plus one non-stubbed timing assertion that a policy check on a cache
  miss returns in under 1 s.

> **CHECKPOINT C4** — the gate's verdict is trustworthy in both directions.
> Demo: the three scenarios in M2's demo line.

### M3 — Scoped credentials

**T-30 — Role and owner on API keys** · size M · files: `app/app/auth.py` (`:69-72`, `:264-306`, `:307-335`), `app/app/routes_v2.py` (`:2453`)
Story: AU-6 (Must). Depends: T-14, T-02.
`create_api_key` hardcodes `"role": "admin"` and
`"created_by": settings.ADMIN_USERNAME` (`auth.py:276-277`);
`validate_api_key` returns them verbatim (`:330`).
- Acceptance: `APIKeyCreate` accepts `role` (`user`|`admin`, default `user`)
  and `owner`; `validate_api_key` returns the stored role; **and `APIKeyInfo`
  plus `list_api_keys` expose `role` and `owner`** (`auth.py:84-89` currently
  returns only `key_id`/`name`/`created_at`/`expires_at`, which would make
  T-31's verify unsatisfiable). **Keys with no
  stored role are treated as admin** — the grandfathering decision — and that
  branch is explicitly tested so it cannot be removed by accident.
- step → verify: pytest asserts a `user`-role key gets 403 on
  `/api/v2/workers/queues`, an `admin`-role key gets 200, and a legacy key with
  no `role` field still gets 200.

**T-31 — Rotate every production API key** · size S · files: none — operational
Story: AU-6 (Must). Depends: T-82 (the M3 rollout — the role-aware code must be
running in production before keys are rotated against it), T-05.
**Owner: devops-ops.**
Grandfathering means the cross-tenant exposure stays open until this is done.
This is the task that actually closes the risk; T-30 only makes it possible.
- Acceptance: every key from the S4 inventory reissued with an explicit role,
  and the legacy no-role keys revoked. A dated record of what was rotated.
- step → verify: `GET /api/v2/api-keys` shows zero keys lacking a `role` field,
  and the S4 inventory is reconciled to zero legacy keys.

> **CHECKPOINT C5** — least-privilege keys exist AND are in use. Demo: M3's
> demo line, plus the rotation record.

### M4 — Audit evidence

**T-40 — Audit coverage on every admin-gated mutation** · size M · files: `app/app/routes_v2.py`, `app/app/db/audit.py`
Story: SY-8 (**Must**, escalated by OQ-5). Depends: T-02, T-11 (if split).
Today 6 actions are logged (`routes_v2.py:70,72,2219,2355,2468,2504`). Policy
*update*, schedule CRUD, VEX CRUD, risk-weight change (RS-3), queue purge and
cache invalidation are not.
**Size correction: this is L, not M, and it splits by domain** — T-40a policy
and schedule routes, T-40b VEX and base-image routes, T-40c queue purge, cache
invalidation and forced DB update. Each is S. They share `routes_v2.py`, so
they run sequentially in that lane.
- Acceptance: every admin-gated mutating route writes exactly one `audit_log`
  row. Write failures stop being swallowed at debug (`db/audit.py:34`) — they
  log at warning, because a silent audit gap is an audit finding. **RS-3
  (risk-weight change, `routes_v2.py:1405`) is inside this task's scope** —
  T-62 is deleted to avoid two builders writing the same call.
  `record_audit` is a synchronous psycopg session (`db/audit.py:16-34`) called
  from async handlers, so ~27 new call sites add ~27 blocking round-trips to
  the single event loop: it must become fire-and-forget via `BackgroundTasks`
  or a threadpool as part of this task.
- step → verify: pytest asserts exactly one `audit_log` row per mutating route,
  enumerated in-process from `app.routes`. **Do not use
  `grep -c "record_audit"`** — it already returns 11 today (6 calls plus 5
  local imports) and would pass at roughly 17 real routes out of 33.

**T-41 — Audit log read endpoint** · size S · files: `app/app/routes_v2.py`, `app/app/db/read_pg.py`
Story: SY-8 (Must). Depends: T-40.
No read path exists — no endpoint, no export, only direct SQL.
- Acceptance: `GET /api/v2/audit` with `actor`, `action` and date-range filters,
  admin-only, paginated.
- step → verify: `curl -s "…/api/v2/audit?actor=admin" | jq '.items | length'`
  returns ≥1 after a policy edit; unauthenticated returns 401; non-admin 403.

**T-42 — Configurable compliance thresholds** · size M · files: `app/app/compliance.py` (`:23`), `app/app/routes_v2.py` (new GET/PUT). **No Alembic revision required** — `KvSetting` already exists (`db/models.py:91`, in the baseline revision)
Story: CO-2 / OQ-5 escalation (Must). Depends: T-40.
Four frameworks carry hardcoded numbers (e.g. PCI 6.3.3 `max_fixable_high: 5`).
Nobody can defend a threshold they did not set.
- Acceptance: thresholds are readable and settable at runtime, persisted in
  `kv_settings`, defaulting to today's values. Every change writes an audit row.
- step → verify: change `max_fixable_high` via the API, restart the API
  container, `GET /api/v2/compliance/frameworks` still shows the new value, and
  `GET /api/v2/audit?action=compliance.threshold.update` returns the change.

**T-43 — Postgres retention purge** · size S · files: `app/app/tasks.py`, beat schedule
Story: SY-7 (Must). Depends: T-13, T-03.
Postgres rows never expire and no purge task exists.
- Acceptance: a `system`-queue task deletes `scans` by `scan_timestamp` (the
  indexed column — `created_at` is unindexed, `db/models.py:25-26`) and
  cascades children by `scan_id`. `Vulnerability` and `License` have no
  timestamp column at all (`db/models.py:43-77`), so they cannot be aged
  directly. Add the index migration if the purge scans sequentially.
- **Ships disabled.** The beat entry is gated on `RETENTION_PURGE_ENABLED`,
  default `false`. Enabling it is an acceptance criterion of T-44, not of this
  task — purging on a 30-day rule before the compliance window is known would
  destroy the evidence T-44 exists to size. This is the OQ-3/OQ-5 tension in
  execution, not just in prose.
- step → verify: with the flag on in a test environment, insert rows dated 31
  days ago into all four tables, run the task, and confirm all four are empty:
  `SELECT count(*) FROM scans WHERE scan_timestamp < now() - interval '30 days'`
  returns 0, and the same for the three child tables by `scan_id`. With the
  flag off (the shipped default), confirm the beat schedule has no purge entry.

**T-44 — Compliance-evidence retention** · size S · files: `app/app/config.py` (`:148`), `app/app/tasks.py`
Story: SY-7 / OQ-5. Depends: T-43. **UNBLOCKED 2026-08-02: the window is 30 days.**
Compliance evidence retains for 30 days, matching the operational
`SCAN_RESULT_TTL`. The two windows are now deliberately equal, which resolves
the OQ-3/OQ-5 tension by decision rather than by design.
- **Implication the decision forces:** `ARTIFACT_RETENTION_DAYS` is currently 7
  (`config.py:148`), so the HTML reports and SBOMs an auditor is actually
  handed expire 23 days before the evidence window closes. Raise it to 30 so
  the artifact and the record expire together.
- **Check disk headroom before raising it.** Reports and SBOMs live on the
  `/opt/scanner-reports` and `/opt/scanner-sboms` bind mounts, and this host has
  filled twice — 228 GB in 46 h (`docker-compose.yml:132-133`) and 63 GB from
  81 leaked directories (`tasks.py:1519-1520`). Quadrupling artifact retention
  is a real capacity change, not a config tweak.
- Acceptance: `ARTIFACT_RETENTION_DAYS` is 30; measured artifact growth per day
  is recorded alongside free space on `/opt`, with headroom for 30 days at that
  rate; and `RETENTION_PURGE_ENABLED` is switched on, activating T-43's purge.
- step → verify: `du -sh /opt/scanner-reports /opt/scanner-sboms` recorded
  against `df -h /opt` before the change; after 31 days (or by back-dating file
  mtimes in a test environment) files older than 30 days are gone and files
  aged 29 days remain; and the beat schedule shows the purge entry active.

**Residual risk accepted by this decision:** a 30-day window cannot evidence an
annual audit. If an auditor asks for a scan from four months ago, it will not
exist in Redis, Postgres, or on disk. This was raised twice and the 30-day
answer was reaffirmed; recording it here so the constraint is visible to
whoever meets that request.

> **CHECKPOINT C6** — an auditor's three questions are answerable: who changed
> the threshold, what was it before, is the evidence still there. Demo: M4's
> demo line, plus the purge running with a 30-day window and reports retained
> to match.

### M5 — Schedules that actually run

**T-50 — Write the `run_scheduled_scan` task** · size S · files: `app/app/tasks.py`
Story: SH-3 (Must). Depends: T-12, T-03.
`get_celery_beat_schedule()` (`scheduler.py:464`) generates entries naming a
task `run_scheduled_scan` that **does not exist** — the string appears only at
`scheduler.py:477`.
- Acceptance: the task exists, resolves a schedule's image list, and enqueues
  scans through `ScanRepository` (not a raw `hset`).
- step → verify: in-process, `"run_scheduled_scan" in celery.tasks`, plus a
  behavioural test that the task enqueues N scans for an N-image schedule.
  (`celery inspect registered` broadcasts to running workers — it returns
  nothing in CI, and would pass the moment the decorator exists regardless of
  whether the body does anything.)

**T-51 — Wire cron firing** · size M · files: `app/app/tasks.py` (`:1283`), `app/app/scheduler.py`
Story: SH-3 (Must). Depends: T-50.
`celery.conf.beat_schedule` is a static dict; nothing reads user schedules.
- Acceptance: per ADR-3, a stored schedule fires on its cron expression with no
  manual trigger, and editing a schedule takes effect without restarting beat.
- step → verify: create a schedule with cron `* * * * *`, wait 3 minutes,
  `redis-cli LLEN schedule_runs:<name>` is ≥1 with no manual call.

**T-52 — Notify on scheduled-scan completion** · size S · files: `app/app/tasks.py`
Story: SH-4 (Must). Depends: T-51.
`send_scan_report` (`scheduler.py:26`) is reachable only from
`POST /api/v2/test-notification`; the per-schedule `google_chat_webhook`
(`scheduler.py:343`) is stored and never read.
- Acceptance: a completed scheduled scan posts one card per scan to the
  schedule's webhook. Webhook failure does not fail the scan.
- step → verify: run a schedule with a webhook pointed at a stub HTTP server;
  the stub receives one POST per scan; then point it at an unreachable URL and
  confirm the scan still completes.

**T-53 — Ownership on schedule-triggered scans** · size S · files: `app/app/routes_v2.py` (`:552`), `app/app/tasks.py` (`:1607`), `app/app/base_image_tracker.py` (`:246`, `:285`)
Story: SH-6 (Should) — **but it also closes a dual-write parity hole.**
Depends: T-51, T-03.
These four sites write scan hashes with a raw `hset`, skipping
`ScanRepository` and therefore skipping dual-write entirely;
`parity_check.py:46-47` counts each as `pg_missing`. Fixing it is a
prerequisite for any future cutover sign-off, which is why it is in-cycle
despite being Should.
- Acceptance: all four write paths go through a repository and stamp
  `created_by`.
- Acceptance also covers the historical rows: run `app/app/db/backfill.py` so
  the scans already counted `pg_missing` are reconciled, not just new ones.
- step → verify: run a schedule, then `python -m app.db.parity_check` shows a
  `pg_missing` delta of 0 for the new scans; and after
  `POST /api/v2/schedules/{name}/run`, `HGET <scan_id> created_by` is non-empty
  and the row exists in Postgres. (A `grep` for `hset` is not runnable as a
  check — it matches legitimate non-scan writes such as
  `scheduler.py:419-421`.)

> **CHECKPOINT C7** — scheduled scanning is real, and the parity hole is shut.
> Demo: M5's demo line, plus a `parity_check` run showing zero *new*
> `pg_missing` after a scheduled run (historical rows are reconciled by the
> backfill in T-53, not by the fix itself).

### M5b — Admin surfaces in the dashboard

Four backend features land in M3–M4 whose stakeholders reach them only through
the UI. Without these, those milestone demos are curl-only and the shipped
capability is unreachable by the people who asked for it. Each touches a
distinct page file, so they are mutually parallel.

**T-70 — API key role and owner in the UI** · size S · files: `dashboard/src/pages/SystemStatus.js`
Story: AU-6. Depends: T-30.
- Acceptance: the key-creation form offers a role and an owner; the key list
  shows both columns.
- step → verify: create a `user`-role key from the dashboard, confirm it
  appears with role `user` in the list.

**T-71 — Audit log viewer** · size S · files: `dashboard/src/pages/AuditLog.js` (new), `dashboard/src/App.js`, `dashboard/src/api.js`
Story: SY-8 (Must). Depends: T-41.
An auditor cannot be handed a `curl` command.
- Acceptance: an admin-only route lists audit rows with actor, action and date
  filters and paging, using the shared `apiV2` instance.
- step → verify: edit a policy, open the page, see the row. `grep -c "axios.create" dashboard/src/pages/AuditLog.js`
  returns 0 — it must use the shared instance.

**T-72 — Compliance threshold editor** · size S · files: `dashboard/src/pages/Compliance.js`
Story: CO-2 / OQ-5 escalation. Depends: T-42.
- Acceptance: thresholds are editable per framework by an admin, with the
  current value shown.
- step → verify: change `max_fixable_high` in the UI, reload, value persists.

**T-73 — License policy editor** · size S · files: `dashboard/src/pages/Policies.js`
Story: LI-2. Depends: T-61.
- Acceptance: license categories are settable to pass/warn/fail.
- step → verify: set AGPL-3.0 to fail in the UI, rescan, the scan shows `fail`.

> **CHECKPOINT C8** — every backend capability shipped this cycle is reachable
> by the stakeholder who asked for it, not only by curl. Demo: do M3's and M4's
> demos entirely through the dashboard.

### M6 — Cleanup slice

**T-60 — Configurable KEV/EPSS feed URLs** · size XS · files: `app/app/config.py`, `app/app/enrichment.py` (`:26`, `:129`)
Story: EN-4 (Should). Depends: T-02.
- Acceptance: both feed URLs are settings with today's values as defaults;
  enrichment works against a repointed URL with egress blocked. Provisioning an
  actual internal mirror is out of scope and needs a named owner — this task
  only removes the hardcoding.
- step → verify: set `KEV_FEED_URL` to a stub, block egress,
  `GET /api/v2/kev/status` still reports a fresh update.

**T-61 — Organizational license policy** · size S · files: `app/app/license_compliance.py`, `app/app/tasks.py` (`:760`), `app/app/routes_v2.py`
Story: LI-2 (Should). Depends: T-02. (The earlier T-61/T-62 exclusion was
wrong — T-62 is deleted, and feasibility R15 covered IA-4/LI-2/AU-9, two of
which are out of cycle. The `routes_v2.py` lane already serializes this.)
`evaluate(packages, policy=None)` already accepts a policy its only caller
never passes.
- Acceptance: a license policy is persistable and editable, `tasks.py:760`
  passes it, and the built-in default is preserved when none is set.
- step → verify: set AGPL-3.0 to `fail`, then
  `GET /api/v2/scan/{id}/licenses` returns `status: "fail"` for a scan with an
  AGPL package.

*(T-62 deleted — RS-3 folded into T-40 to avoid duplicating the same audit
call at `routes_v2.py:1405`.)*

**T-63 — Owner check on scan detail** · size M · files: `app/app/routes.py` (`:719`), `app/app/ownership.py`, 22 handlers in `routes_v2.py`
Story: AU-8 (**Should**, demoted by OQ-11). Depends: T-02, T-11.
**Read the OQ-11 note before starting.** With reports staying shared, this is
largely cosmetic — the same findings remain readable at
`/reports/{scan_id}.html`. It is here for consistency, not for security value.
**Do not start it if M0–M5 are running late.**
- Acceptance: a `can_view` helper exists in `ownership.py` and is applied to
  the 22 `routes_v2.py` per-scan handlers plus `routes.py:719`. **Deliberately
  excluded:** `routes.py:748, :1012, :1032, :1063` and the static serves at
  `main.py:138,143` — all report/SBOM/compare surfaces that OQ-11 leaves
  readable by any authenticated user. Scoping them would contradict the
  decision.
- step → verify: as non-admin user B, `GET /api/v1/scan/{id_owned_by_A}`
  returns 403; admin still gets 200; `/reports/{id}.html` still returns 200 for
  any authenticated user, per OQ-11.

**T-64 — Fix the `scan_quality: "failed"` write** · size XS · files: `app/app/tasks.py` (`:695-700`, `:731-736`)
Story: SC-3 defect found in stage 1. Depends: T-03.
Neither failure branch writes `scan_quality: "failed"`; `routes.py:370` then
defaults a hard-failed scan to `degraded`.
- Acceptance: both hard-failure branches write `scan_quality: "failed"`, and
  the stage-1 SC-3 criterion that was suppressed because of this defect is
  re-enabled in the test suite.
- step → verify: force both vuln scanners to fail; `GET /api/v1/scan/{id}`
  returns `scan_quality: "failed"`.

**T-65 — Un-hardcode `REDIS_URL` in compose** · size XS · files: `app/docker-compose.yml` (`:23`, `:326`)
Story: G10 / feasibility R5. Depends: none.
`REDIS_URL` is a bare literal with no `${...}` wrapper, so it overrides `.env`;
Flower hardcodes its own broker independently. The requirements claim a
config-only datastore swap; it is currently true for Postgres only.
- Acceptance: `REDIS_URL` is `${REDIS_URL:-redis://redis:6379/0}` and the
  Flower broker derives from the same variable rather than its own literal.
- step → verify: set `REDIS_URL` in `.env` to a different host,
  `docker compose config | grep REDIS_URL` shows the override, and the Flower
  broker line resolves from the same variable.

### Rollout

`publish` and `deploy` are `when: manual` on `main` (`.gitlab-ci.yml:194,229`),
so nothing reaches production without a deliberate click. Every milestone whose
demo describes production behaviour needs a rollout node, and no such node
existed in the first draft of this plan.

**T-80..T-86 — Roll out M1 … M6 (one task each)** · size XS each · files: none — operational
Each depends on the last task of its milestone. Each is the terminal node of
its milestone, and the milestone is not complete until it lands.
- Acceptance per rollout: pipeline green, `publish` and `deploy` clicked, the
  post-deploy health check at `.gitlab-ci.yml:272-280` passes, and the
  milestone's demo is performed against production.
- step → verify: `curl -fsS https://apexscanner.6dcorp.internal/health` returns
  200 with the new image tag, and the milestone demo line is reproduced live.
- Rollback if the health check fails: re-run `deploy` on the previous good
  pipeline (`.gitlab-ci.yml:281`). There is no scripted revert — this is
  manual, and the operator must have the previous pipeline id to hand before
  clicking deploy.

**T-31 depends on the M3 rollout (T-82), not on T-30's merge** — it rotates
production keys, which cannot happen before the code that understands roles is
actually running in production.

---

## 4. Dependency order

No cycles, no forward references. **ADR-8 (T-10) produces two different
graphs — both are given, because the first draft only showed the split branch
and left the other undefined.**

### Branch A — ADR-8 decides SPLIT (T-11 runs)

```
T-01 ─┬─ T-02a/b/c ─┬─ T-11 (also needs T-10, T-20, T-21)
      │             │    └─ unlocks 4 disjoint router lanes:
      │             │         auth lane   : T-30 → T-63
      │             │         policy lane : T-22 → T-23 → T-24 → T-25
      │             │         audit lane  : T-40a → T-40b → T-40c → T-41 → T-42
      │             │         misc lane   : T-61
      │             └─ T-60
      └─ T-03 ── [tasks.py lane, strictly serial]
                  T-64 → T-50 → T-51 → T-52 → T-53 → T-43 → T-44

Independent, start day one: T-04, T-05, T-06, T-07, T-08, T-09, T-10,
                            T-12, T-13, T-15, T-65
T-14 needs T-05.   T-20 + T-20b need T-04.   T-21 needs T-20.
T-30 needs T-14.   T-31 needs T-82 (M3 rollout), not T-30.
T-22 needs T-09.   T-40a needs T-15.   T-43 needs T-13.
Dashboard: T-70←T-30, T-71←T-41, T-72←T-42, T-73←T-61 — mutually parallel.
Rollout:   T-80←M1, T-81←M2, T-82←M3, T-83←M4, T-84←M5, T-85←M5b, T-86←M6.
```

### Branch B — ADR-8 decides NO SPLIT (T-11 does not run)

Every `routes_v2.py` task collapses into **one serial lane**. This is the
branch that makes the cycle long, and it is the reason ADR-8 is scheduled on
day one rather than discovered later.

```
T-01 ─┬─ T-02a/b/c ── [routes_v2.py lane, strictly serial]
      │                 T-20 → T-21 → T-22 → T-23 → T-24 → T-25
      │                      → T-30 → T-40a → T-40b → T-40c → T-41 → T-42
      │                      → T-61 → T-63
      └─ T-03 ── [tasks.py lane, strictly serial — unchanged from Branch A]
                  T-64 → T-50 → T-51 → T-52 → T-53 → T-43 → T-44
```

Under Branch B the two lanes still run concurrently with each other, and the
spikes, ADRs, T-15, T-65, T-60, the dashboard tasks and the rollouts are
unaffected. Nothing downstream *breaks* under Branch B — it only serializes.

**Hard serialization constraints:**

- Until T-11 lands (Branch A) or permanently (Branch B), treat every
  `routes_v2.py` task as exclusive — one builder at a time.
- T-22 → T-23/T-24/T-25 is one builder start to finish, under either branch.
  Three builders would produce three context schemes.
- **`tasks.py` is the second exclusive lane.** T-64, T-50, T-51, T-52, T-53 and
  T-43 all edit it, and T-43 and T-51 both mutate
  `celery.conf.beat_schedule` (`tasks.py:1283`).
- No new Alembic revision is expected this cycle: `kv_settings` already exists
  (`db/models.py:91`, created in the baseline revision), and IA-4/AU-9 are out
  of cycle. If T-43's index migration or T-61 needs one, a single named owner
  takes all revisions. Feasibility R15 is dormant this cycle.
- The characterization mandate (feasibility M1) is satisfied by T-01, T-02a/b/c
  and T-03, and is interleaved: T-02* gates every `routes_v2.py` task, T-03
  gates every `tasks.py` task. It is not appended at the end.

## 5. Not in this cycle

| Story | Reason | Precondition to reopen |
|---|---|---|
| **WK-3 / WK-4** autoscaler actuation | Three independent blockers (`autoscaler.py:186-191`, no volumes at `docker-compose.yml:290-315`, `POST: 0` at `:271`). The only in-container fix reverses NFR-SEC7. Host-infrastructure work, not application work | T-08 (S3) result + a security sign-off on the Docker API surface. Recommend demoting from Must |
| **SY-6** Postgres read cutover | `read_pg` is sync-on-the-event-loop (`read_pg.py:15-32` via `scan_repository.py:31-36`); flipping the flag today puts blocking DB calls in the single event loop. A partial PG dataset silently falls through to Redis rather than erroring. No parity pass ever recorded | T-06 (S2) result + an async read path + OQ-4 (cutover deadline). T-53 removes one blocker by closing the parity hole |
| **SY-9** metrics collected | App side is done — 20 collectors emit at `/metrics`. The remainder is deployment topology this repo cannot decide | T-07 (S5). If 6D runs a central Prometheus this is another team's change; if not, it is a compose overlay |
| **PG-6** single scan-and-gate call, **IA-4** durable IaC results, **SC-10** cancel a scan | All three need ADR-5 (async contract for long operations), which is deferred. Note IA-4 also carries a live availability defect: `routes_v2.py:2018` blocks the single event loop for up to 3 minutes | ADR-5. Consider pulling the `--workers` mitigation forward independently — see below |
| **CO-3** estate-level compliance report, **AU-9** per-person identity, **DA-2** blast radius | Could-priority, or blocked on OQ-6 | OQ-6 for AU-9, which OQ-5 has now made a compliance dependency — expect it next cycle |

**One carve-out worth taking now:** the IaC event-loop stall is a live
availability defect independent of IA-4's storage work. Running uvicorn with
`--workers 2` (`Dockerfile.api:59`) mitigates it in one line without waiting
for ADR-5. Not scheduled above because it needs a load check first, but it is
the cheapest risk reduction available in this plan.

---

## 6. Still-open questions carried forward

| OQ | Blocks | Needed by |
|---|---|---|
| **OQ-4** cutover deadline | SY-6 | Next cycle planning |
| **OQ-8** are SH-3/SH-4 defects or descoping | Nothing structurally — M5 builds them either way. Affects whether they are counted as bug-fix or feature | Before M5 kickoff, for reporting only |
| **OQ-1** root workers, **OQ-2** target scale, **OQ-6** identity source, **OQ-9** compare/search admin-only, **OQ-10** registry list | Priorities and next-cycle scope | Next cycle |
