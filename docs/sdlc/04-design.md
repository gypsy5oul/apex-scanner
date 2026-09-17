# 04 — System Design (stage 4)

**Project:** Apex Scanner 3.0 · **Mode:** brownfield · **Date:** 2026-08-03
**Inputs:** `docs/sdlc/03-plan.md`, `02-feasibility.md`, `01-requirements.md`, `architecture-map.md`, `state.json.decisions`
**Conflict rule:** ADR wins architecture, SPEC (`03-plan.md` + `state.json.decisions`) wins scope. Where this document contradicts `01-requirements.md`, the six binding decisions in `state.json` are the reason; each is called out inline.

---

## 1. Scope boundary

### 1.1 Components this cycle modifies

| # | Component | File(s) | Change |
|---|---|---|---|
| C1 | API v2 router | `app/app/routes_v2.py` | WS auth (`:1136`,`:1168`), policy-check context (`:2408`), api-key handlers (`:2453`–`:2505`), ~27 audit call sites, ownership on 22 per-scan handlers. **No route moves** (ADR-8) |
| C2 | API v1 router | `app/app/routes.py` | one ownership check at `:719` (T-63) |
| C3 | App shell | `app/app/main.py` | include the new domain routers (`:147-148`). Static serves at `:137,:143` **unchanged** (OQ-11) |
| C4 | Identity | `app/app/auth.py` | `APIKeyCreate`/`APIKeyResponse`/`APIKeyInfo` (`:69-91`), `create_api_key` (`:264`), `validate_api_key` (`:307`), `list_api_keys` (`:336`) |
| C5 | Tenancy | `app/app/ownership.py` | new `can_view()` helper (T-63) |
| C6 | Policy engine | `app/app/policy_engine.py` | `evaluate_vulnerabilities` (`:300`) / `evaluate_iac_findings` (`:379`) take a context; `apply_to` (`:59`) read; scan-level rule branch |
| C7 | **Policy context (NEW)** | `app/app/policy_context.py` | `ScanContext` + `build_scan_context` (ADR-4) |
| C8 | VEX | `app/app/vex.py` | expose per-CVE status map for the gate (reuses `get_statements_for_cve` `:177`, `apply_vex_to_vulnerabilities` `:187`) |
| C9 | Base-image catalog | `app/app/gitlab_catalog.py` | `is_approved_base()` predicate over `get_catalog` (`:105`) |
| C10 | Compliance | `app/app/compliance.py` | `FRAMEWORKS` (`:23`) becomes defaults under a kv overlay |
| C11 | License compliance | `app/app/license_compliance.py` | policy load path for `evaluate(packages, policy)` (`:283`) |
| C12 | Enrichment | `app/app/enrichment.py` | feed URLs from settings (`:26`,`:129`) |
| C13 | Celery app + tasks | `app/app/tasks.py` | 3 new tasks, 2 new beat entries (`:1283`), 3 new routes (`:105`), `scan_quality:"failed"` (`:695-700`,`:731-736`), reaper write (`:1607`), license policy (`:760`) |
| C14 | Schedule store | `app/app/scheduler.py` | `created_by` on schedules; `get_celery_beat_schedule` (`:464`) retired |
| C15 | WebSocket transport | `app/app/websocket_manager.py` | `authenticate_websocket()`, one shared pub/sub pump |
| C16 | Audit writer | `app/app/db/audit.py` | `audit()` background helper; failure → WARNING + metric (`:34`) |
| C17 | PG read layer | `app/app/db/read_pg.py` | `read_audit_page`/`read_audit_count` |
| C18 | **Settings store (NEW)** | `app/app/settings_store.py` | typed access to `kv_settings` (`db/models.py:91`) |
| C19 | **Domain routers (NEW)** | `app/app/routers/{__init__,audit,compliance_admin,license_policy}.py` | only NEW endpoints (ADR-8) |
| C20 | Config | `app/app/config.py` | `ARTIFACT_RETENTION_DAYS` 7→30 (`:148`), `RETENTION_*`, `KEV_FEED_URL`, `EPSS_FEED_URL` |
| C21 | Scan repository | `app/app/repositories/scan_repository.py` | callers only — no signature change |
| C22 | Base-image tracker | `app/app/base_image_tracker.py` | raw `hset` → repository (`:246`,`:285`) |
| C23 | Backfill | `app/app/db/backfill.py` | run only (T-53) |
| C24 | FE API client | `dashboard/src/api.js` | WS URL derivation (`:301-310`), audit calls |
| C25 | FE pages | `dashboard/src/pages/{SystemStatus,Compliance,Policies,AuditLog}.js`, `App.js` | four admin surfaces |
| C26 | Test harness | `app/tests/**` | fixtures + characterization + auth sweep |
| C27 | CI pipeline | `.gitlab-ci.yml` (`:120-138`) | postgres service in the pytest job |
| C28 | Compose topology | `app/docker-compose.yml` (`:23`,`:326`) | `REDIS_URL` indirection only |
| C29 | Decision record | `docs/adr/*.md` | ADRs |
| C30 | Spike record | `docs/sdlc/spikes/S{1..5}.md` | findings |
| C31 | Operations (no code) | — | rollouts, key rotation |

### 1.2 Components this cycle leaves alone

| Component | Why untouched |
|---|---|
| `scanners/orchestrator.py`, `base.py`, `grype/trivy/syft_scanner.py`, `normalization.py`, `scanner_errors.py` | No story touches scan execution. SC-10 (cancel) is out of cycle |
| `iac_scanner.py`, the four IaC routes (`routes_v2.py:2006-2128`) | IA-4 out of cycle. T-02c only **stubs** `AsyncResult` in tests; the `task.get(timeout=…)` event-loop stall at `:2018,:2055,:2092,:2128` is **not fixed this cycle** |
| `autoscaler.py`, `docker-proxy` service (`docker-compose.yml:258-275`) | WK-3/WK-4 out of scope. `POST:0` stays 0 |
| `updater.py`, `worker_monitor.py` | No story |
| `oidc.py` | AU-9 / identity source out of cycle. Note R13: the Keycloak initiative also edits `auth.py` |
| `risk_scoring.py`, `remediation.py`, `trends.py`, `ai_triage.py`, `cvss_enrichment.py`, `dependency_analyzer.py`, `export.py` | RS-3 is an audit **call site** in `routes_v2.py:1405`, not an engine change |
| `db/dual_write.py`, `db/engine.py`, `db/sync_engine.py`, `db/parity_check.py` | SY-6 out of scope; T-53 fixes callers, not the mirror |
| `metrics.py` | One additive counter only; SY-9 topology out of scope |
| `Dockerfile.api`, `Dockerfile.worker`, `worker-entrypoint.sh`, edge proxy config | `--workers` carve-out is **not scheduled**; root workers held (OQ-1) |
| Redis / Postgres / pg-backup service definitions | Only the `REDIS_URL` literal changes |

### 1.3 Every plan task → component

| Task | Component(s) |
|---|---|
| T-01 | C26 |
| T-02a/b/c | C26 |
| T-03 | C26 |
| T-04 (S1), T-05 (S4), T-06 (S2), T-07 (S5), T-08 (S3) | C30 |
| T-09, T-10, T-12, T-13, T-14 | C29 |
| T-11 | **not executed** — ADR-8 decides NO SPLIT |
| T-15 | C27 |
| T-20 | C1 + C15 |
| T-20b | C24 |
| T-21 | C26 |
| T-22 | C7 + C6 + C1 |
| T-23 | C6 |
| T-24 | C6 + C8 |
| T-25 | C6 + C9 |
| T-30 | C4 + C1 |
| T-31 | C31 |
| T-40a | C1 + C16 |
| T-40b | C1 + C16 |
| T-40c | C1 + C16 |
| T-41 | C19 + C17 |
| T-42 | C19 + C18 + C10 |
| T-43 | C13 + C20 |
| T-44 | C20 + C13 + C31 |
| T-50 | C13 |
| T-51 | C13 + C14 |
| T-52 | C13 + C14 |
| T-53 | C1 + C13 + C22 + C14 + C23 |
| T-60 | C20 + C12 |
| T-61 | C19 + C18 + C11 + C13 |
| T-63 | C2 + C5 + C1 |
| T-64 | C13 |
| T-65 | C28 |
| T-70 | C25 (`SystemStatus.js`) |
| T-71 | C25 (`AuditLog.js`, `App.js`) + C24 |
| T-72 | C25 (`Compliance.js`) |
| T-73 | C25 (`Policies.js`) |
| T-80…T-86 | C31 |

**No task maps to no component.** Three bookkeeping/scope gaps in the plan:

- **G-A — the "44 tasks" headline does not reconcile.** Counting distinct task ids in the plan (T-01, T-02a/b/c, T-03…T-65, T-70–73, T-80–86) gives 46 non-rollout + 7 rollout = 53, against 43 backlog *entries* — the entry count is right, the id count in the headline is not, because T-02 and T-40 each split into three. An earlier draft of this section said 49/42 and was also wrong. Not a scope gap; fix the headline when the plan is next touched.
- **G-B — T-11 has no owner under a NO-SPLIT decision and is now void.** Branch A of §4 of the plan is dead; Branch B is the executing graph. Stated in ADR-8.
- **G-C — T-53 requires a field the plan never names.** Stamping `created_by` on schedule-triggered scans presupposes the schedule knows its creator. `ScheduleManager.create_schedule` (`scheduler.py:326-350`) stores no creator. T-53 must add `created_by` to the schedule record and fall back to `settings.ADMIN_USERNAME` for pre-existing schedules. Flagged to BA as a missing acceptance criterion, not invented scope.

### 1.4 File ownership under parallel builders

Exclusive lanes (one builder at a time, in this order):

- **`routes_v2.py` lane (serial):** T-20 → T-21 → T-22 → T-30 → T-40a → T-40b → T-40c → T-53(API part) → T-63.
- **`policy_engine.py` lane (serial, one builder start to finish):** T-22 → T-23 → T-24 → T-25.
- **`tasks.py` lane (serial):** T-64 → T-50 → T-51 → T-52 → T-53 → T-43 → T-44.
- **`app/app/routers/__init__.py` (serial, shared):** T-41 creates it, T-42 appends, T-61 appends.
- Everything else (C24, C25 pages, C26, C27, C28, C29, C30) is disjoint and parallel.

---

## 2. ADRs

Numbering continues the register in `02-feasibility.md` §7. ADR-1, 5, 7, 9, 10 are recorded for completeness because builders will otherwise re-open them.

### ADR-1 — Scan/report tenancy boundary · **Accepted (no build)**
**Context.** AU-8 and EX-3 contradict on the same data (`01-requirements.md:1125-1142`); `main.py:103-108` deliberately serves any report to any authenticated user.
**Decision.** Reports and SBOMs stay readable by every authenticated user. No report tenancy is designed or built. T-63's `can_view` applies **only** to `routes.py:719` and the 22 `routes_v2.py` per-scan handlers; `routes.py:748,:1012,:1032,:1063` and `main.py:137,:143` are explicitly excluded.
**Consequences.** T-63 is cosmetic (findings stay reachable at `/reports/{scan_id}.html`) and is the first drop candidate if the cycle slips. **`01-requirements.md:1160-1162` (AU-10's second criterion — non-owner gets 1008 on `/ws/scan/{id}`) is void**: per OQ-11 any authenticated user may connect. Requirements text is stale; the decision wins.
**Alternatives rejected.** Scoping reports too (contradicts OQ-11); leaving AU-8 open with no note (leaves builders guessing which handlers to touch).

### ADR-2 — API-key identity model · **Accepted**
**Context.** `create_api_key` hard-codes `"role": "admin"` and `"created_by": settings.ADMIN_USERNAME` (`auth.py:276-277`); `validate_api_key` returns them verbatim (`:329-330`); `APIKeyCreate` has only `name`/`expires_days` (`:69-72`). Every CI key is a cross-tenant admin. Binding decision: role+owner, existing keys grandfathered as admin.

**Decision.**
1. `APIKeyCreate` gains `role: Literal["user","admin"] = "user"` and `owner: Optional[str] = None`. Default is `user` — new keys are least-privilege by default.
2. The stored Redis hash gains two fields: `role` and `owner`. `created_by` **changes meaning** to "the admin who minted this key" (audit provenance) and stops being the authenticated identity.
3. `validate_api_key` resolves identity as `username = key_data.get("owner") or key_data.get("created_by", "api_key")` and role as `key_data.get("role", "admin")`.
4. **Grandfathering costs zero code and zero migration.** Every key ever minted already carries `role: "admin"` in its Redis hash (written at `auth.py:277`), so legacy keys keep working with no backfill. The `.get(..., "admin")` default at `auth.py:330` already covers the theoretical role-absent hash and is **kept unchanged** — that is the grandfathering mechanism, and T-30 must add a test that pins it so nobody "tidies" the default to `user`. Identity grandfathers the same way: `owner` absent → falls back to `created_by` → `ADMIN_USERNAME`, i.e. today's exact behaviour.
5. `validate_api_key` logs at WARNING (`api_key.legacy_role_default`, with `key_id`) whenever the role default fires, so T-31's completion is observable rather than asserted.
6. `APIKeyInfo` and `list_api_keys` expose `role` and `owner` — without this T-31's verify (`zero keys lacking a role`) is unsatisfiable.

**Consequences.** Fail-open by construction until T-31 rotates production keys; that is the accepted trade for zero pipeline breakage. Flipping the default from `admin` to `user` is a **follow-up after T-31**, out of this cycle. `TokenData.username` for a key now names the owner, which changes what `ownership.record_scan_owner` indexes for key-initiated scans — intended (that is the AU-6 fix), and it means a rotated key's scans no longer appear under `admin`'s index.
**Alternatives rejected.** Invalidate-and-reissue on merge (breaks every pipeline at an unscheduled moment; S4 has not run so the blast radius is unknown). A Redis migration script stamping roles (unnecessary — the field is already present). Scopes/permission lists instead of a role (no requirement asks for them; `get_current_admin` at `auth.py:440` is a binary gate — YAGNI).

**Plan/code correction.** T-30 states `APIKeyInfo` "currently returns only `key_id`/`name`/`created_at`/`expires_at`". It also returns `last_used` (`auth.py:90`, populated at `:350`).

### ADR-2a — Bounding the fail-open window · **Accepted**
**Context.** `role-absent → admin` is a fail-open default in an authorization
path. ADR-2 accepts it so no pipeline breaks, and T-31 rotates the keys — but
T-31 has an owner (`devops-ops`) and no date, no expiry, and no forcing
function. Meanwhile all four of this cycle's new admin surfaces (audit read,
compliance thresholds, license policy, key management) are reachable by exactly
the credential this cycle exists to de-risk.
**Decision.** The default is read from config, not hardcoded:
`LEGACY_KEY_ROLE_DEFAULT`, shipping as `admin`. Once the S4 inventory reports
zero legacy keys, an operator flips it to `user` without a code change or
deploy. A startup log line states the current value at WARNING while it is
`admin`, so the window is visible in every boot log rather than buried in an
ADR.
**Note on what "legacy" means here.** `auth.py:277` writes `"role": "admin"`
explicitly on every key ever minted, so strictly no stored key *lacks* the
field — the grandfathering path is defence against partial reads and
hand-edited hashes, not against a population of role-less keys. This matters
for T-31's verify: see §7.
**Consequences.** The exposure window is closable by configuration the moment
rotation completes, instead of waiting for a code change.
**Alternatives rejected.** A hard date in code (fails closed on a day nobody
remembers). Leaving it hardcoded (the window is then unbounded by anything).

### ADR-3 — Scheduled execution mechanism · **Accepted**
**Context.** `get_celery_beat_schedule()` (`scheduler.py:464-488`) generates entries naming task `run_scheduled_scan`, which **does not exist** — the string occurs only at `scheduler.py:477`. Nothing calls the generator; `celery.conf.beat_schedule` (`tasks.py:1283-1319`) is a static dict of five entries. The beat container runs `--schedule=/tmp/celerybeat-schedule` (`docker-compose.yml:247`) and declares **no `volumes:`** (`:242-256`), so beat's own state dies with the container.

**Decision.** A **1-minute dispatcher tick**, not RedBeat and not a `Scheduler` subclass.
1. New task `dispatch_due_schedules` (queue `system`), one static beat entry `schedule: 60.0` added to `tasks.py:1283`.
2. Each tick reads schedules from Redis via `ScheduleManager.list_schedules()` (`scheduler.py:385`), evaluates each `cron_expression` with `croniter` against the previous minute boundary, and dispatches `run_scheduled_scan.apply_async(args=[name])` for matches.
3. Duplicate-fire guard: `SET schedule_fire:{name}:{YYYYMMDDHHMM} 1 NX EX 120`. Only the setter dispatches. This makes the tick safe under multiple `worker-system` replicas and under a beat restart mid-minute.
4. New task `run_scheduled_scan(schedule_name)` (queue `system`) resolves the image list and enqueues one `scan_image` per image **through `ScanRepository.create()`** (`scan_repository.py:158`), never a raw `hset`.
5. `get_celery_beat_schedule()` is deleted. Schedule state lives only in Redis (`schedule:{name}` hashes + the `scheduled_scans` set, `scheduler.py:321,336,356`).

**Consequences.** Firing granularity is one minute; sub-minute crons were never expressible anyway (`scheduler.py:473-475` requires exactly 5 fields). **Missed windows are not backfilled** — if the system-worker or beat is down for ten minutes, those firings are skipped, not replayed. Schedule edits take effect on the next tick with no beat restart (satisfies T-51). The static five beat entries keep working untouched. **Operational risk to flag at T-84:** the moment this ships, every enabled stored schedule starts firing; the operator must review `GET /api/v2/schedules` before the M5 rollout, or a forgotten daily schedule becomes a scan storm.
**Alternatives rejected.** *RedBeat* — a new dependency that takes over the whole beat schedule including the five working static entries, on a live system, for no capability we lack. *Custom `Scheduler` subclass* — must re-sync on every edit and still keeps a shelve file in a volume-less container. *Volume-mount `/tmp/celerybeat-schedule`* — persists the wrong state (beat's cursor) and does nothing about a schedule that never reaches beat.

### ADR-4 — Policy-evaluation input contract · **Accepted** (gates T-22/T-23/T-24/T-25; checkpoint C2 imports this)
**Context.** `check_scan_policies` (`routes_v2.py:2408-2449`) loads only `VulnerabilityRepository.get_raw` (`:2413`). Image name, base OS and VEX state never reach `evaluate_vulnerabilities` (`policy_engine.py:300`), which also serves `evaluate_iac_findings` (`:379`), batch gating (`routes_v2.py:247`) and `/policies/evaluate` (`:2383`).

**Decision.** A frozen dataclass in a **new module** `app/app/policy_context.py` (new file so tests and the IaC path can import it without importing the engine, and so no import cycle exists — `policy_context` imports nothing from `policy_engine`).

```python
# app/app/policy_context.py
@dataclass(frozen=True)
class ScanContext:
    scan_id: str
    image_name: str = ""                      # "" when not image-scoped (IaC)
    base_image_os: Optional[str] = None       # scan hash "base_image_os"        (tasks.py:883)
    base_image_os_id: Optional[str] = None    # scan hash "base_image_os_id"     (tasks.py:886)
    base_image_os_version: Optional[str] = None  # scan hash "base_image_os_version" (tasks.py:885)
    image_digest: Optional[str] = None        # scan hash "image_digest"
    approved_base_image: Optional[bool] = None   # None = not determined; NOT False
    vex_status: Mapping[str, str] = field(default_factory=dict)         # UPPER CVE id -> status
    vex_justification: Mapping[str, str] = field(default_factory=dict)  # UPPER CVE id -> justification
    source: str = "scan"                      # "scan" | "batch" | "iac"

def build_scan_context(scan_id: str, *, redis_client=None) -> ScanContext: ...
def iac_context() -> ScanContext:   # source="iac", image_name=""
    ...
```

Construction rules, binding:
- `build_scan_context` is the **only** constructor for image scans. It is **synchronous** (Redis `hgetall`, VEX lookups, catalog read) and **must be called from async handlers via `starlette.concurrency.run_in_threadpool`**. This is how T-25's "catalog lookup must not block the event loop" is satisfied — `gitlab_catalog.get_catalog` is a sync `httpx.Client(timeout=20.0)` (`gitlab_catalog.py:96`) and stays that way.
- `approved_base_image` is resolved **at context-build time**, never inside the engine. Tri-state: `True` approved, `False` present-and-not-approved, `None` undeterminable (catalog disabled per `GITLAB_CATALOG_ENABLED=false`, unreachable with no last-good copy, or base OS unknown). `None` means the rule does not fire — an unavailable catalog must not fail every scan.
- `vex_status` is built from `VEXManager.get_statements_for_cve` with the same product-matching rule already implemented at `vex.py:204-212`: a statement scoped to a different product never applies.
- Call sites: `routes_v2.py:2408` (`check_scan_policies`), `routes_v2.py:2365` (`evaluate_policy`, when `scan_id` is given), `routes_v2.py:219` (`batch_policy_check`, one context per scan id), and `iac_context()` for `routes_v2.py:2112`.

Engine signature (additive, default `None` = today's behaviour exactly, which is what makes T-22 behaviour-neutral):

```python
def evaluate_vulnerabilities(self, policy_id: str,
                             vulnerabilities: List[Dict[str, Any]],
                             context: Optional[ScanContext] = None) -> PolicyEvaluationResult
def evaluate_iac_findings(self, policy_id: str,
                          findings: List[Dict[str, Any]],
                          context: Optional[ScanContext] = None) -> PolicyEvaluationResult
```

Three context-gated behaviours, all no-ops when `context is None`:
- **T-23 `apply_to`:** if `policy.apply_to` is a non-empty list and no entry `fnmatch`-matches `context.image_name`, return the existing skip result shape (`policy_engine.py:311-319`) with `status="skipped"`, `passed=True`. Skipped policies still appear in the `results` array so the verdict is explainable.
- **T-24 VEX:** vulnerabilities whose CVE has `vex_status == "not_affected"` are excluded from rule matching and recorded in a new field `PolicyEvaluationResult.suppressed_by_vex: List[Dict[str,Any]] = field(default_factory=list)` (appended last, defaulted, so existing constructors are unaffected). Each entry: `{"cve_id", "justification", "product"}`.
- **T-25 scan-level rules:** `SCAN_LEVEL_FIELDS = {"approved_base_image", "base_image_os", "base_image_os_id", "image_name"}`. `_evaluate_rule` (`policy_engine.py:399`) branches: for a scan-level field it compares **once** against the context (skipping entirely when the context value is `None`) and, on a match, yields a single synthetic item `{"field": f, "value": v}`. **This branch is mandatory** — evaluating a scan-level rule per-vulnerability means an unapproved base image with zero CVEs silently passes, which is the exact failure the story exists to prevent.

**Consequences.** One context object, one builder, one threadpool boundary. `PolicyEvaluationResult` gains one field; the three response builders (`routes_v2.py:2390`, `:2435`, `:248`) may surface it but are not required to except at `/scan/{id}/policy-check` where T-24 requires the suppressing statement be named.
**Verification hook for checkpoint C2:** `from app.policy_context import ScanContext` in a failing test is sufficient to prove this ADR is concrete.
**Open, must be closed at T-25 implementation time:** the exact `catalog.json` field names used to match base OS are not verifiable from this repo (`GITLAB_CATALOG_ENABLED` defaults false, `config.py:216`, and the file is not vendored). `is_approved_base(catalog, scan_hash) -> Optional[bool]` in `gitlab_catalog.py` is the single place that knows them; pin them against a real catalog fetch before writing the rule.
**Alternatives rejected.** Extra keyword arguments on `evaluate_vulnerabilities` (three builders, three signatures — the R6 failure mode). Passing the raw Redis scan hash (untyped `Dict[str,str]`, no test can import it, and every consumer re-parses). Resolving the catalog inside the engine (puts a 20 s sync HTTP call under the event loop at `routes_v2.py:2402`).

### ADR-5 — Async contract for long operations · **Deferred (out of cycle)**
**Context.** `routes_v2.py:2018,:2055,:2092,:2128` call `task.get(timeout=60..180)` from `async def` handlers on a single-process uvicorn (`Dockerfile.api:59`).
**Decision.** Not decided this cycle. IA-4/PG-6/SC-10 stay out of scope; the stall stays.
**Consequences.** A large-repo IaC scan can freeze the API, `/health` included, for up to three minutes. The `--workers 2` mitigation is **not** adopted here — it needs a load check and no task owns it.
**Alternatives rejected.** Bolting submit+poll onto the IaC routes inside this cycle (it is a surface change to four endpoints plus storage, i.e. IA-4, which is out of scope).

### ADR-6 — Retention of record and purge · **Accepted**
**Context.** OQ-3 and the compliance-window answer both say 30 days. Postgres rows never expire; no purge task exists. `Vulnerability` and `License` have no timestamp column (`db/models.py:43-77`). `created_at` is unindexed; `scan_timestamp` is indexed (`db/models.py:26`, `1d68b1e53cac_baseline_schema.py:83`).

**Decision.**
1. New task `purge_expired_records` (queue `system`), beat entry `86400.0`, **added to `tasks.py:1283` only when `settings.RETENTION_PURGE_ENABLED` is true** — the entry is built conditionally so the shipped default schedule contains no purge (T-43's negative verify).
2. New settings: `RETENTION_PURGE_ENABLED: bool = False`, `RETENTION_DAYS: int = 30`.
3. Cutoff `now_utc() - timedelta(days=RETENTION_DAYS)`. Deletion is **batched, 1000 scan ids per transaction**, children before parents:
   - `SELECT id FROM scans WHERE scan_timestamp < :cutoff LIMIT 1000` → index scan on `ix_scans_scan_timestamp`
   - `DELETE FROM vulnerabilities WHERE scan_id IN (…)` → `ix_vulnerabilities_scan_id`
   - `DELETE FROM licenses WHERE scan_id IN (…)` → primary key
   - `DELETE FROM scans WHERE id IN (…)`
   Loop until a batch returns fewer than 1000.
4. **The NULL tail.** `scan_timestamp` is written only on completion (`tasks.py:906`) and on a cache-hit copy (`:651`). Scans that failed, were reaped, or never finished have `scan_timestamp IS NULL` in Postgres and would live forever under a strict `scan_timestamp` predicate. A second bounded pass handles them: `WHERE scan_timestamp IS NULL AND created_at < :cutoff LIMIT 1000`. This is a sequential scan. **No index is added** — the NULL set is small and `read_pg.py:76` already establishes `coalesce(scan_timestamp, created_at)` as the house pattern for this exact asymmetry. If a purge run is measured over 30 s, add `ix_scans_created_at_partial` (`CREATE INDEX … ON scans (created_at) WHERE scan_timestamp IS NULL`) as a **new Alembic revision** — specified here so the builder does not have to invent it, but **not shipped by default**.
5. `batches` purge by `created_at` (`ix_batches_created_at`). **`audit_log` is NOT purged.** An earlier draft of this ADR purged it at the same 30-day cutoff; that was wrong. SY-8 is a Must precisely because the audit trail is compliance evidence, and checkpoint C6's demo asks "who changed the threshold, and is the evidence still there" — purging at 30 days answers "no" for any action older than a month, defeating the story that motivated the escalation. The 30-day decision was about *scan* data; extending it to the audit trail was an inference, not an instruction. **Flagged to BA for sign-off:** audit_log needs its own window, and nobody has stated one. Until they do, it retains indefinitely — bounded growth is acceptable here (one row per admin mutation, not per scan).
6. Every purge run writes **one** `audit_log` row `action="retention.purge"` with per-table counts, so the purge is self-evidencing.
7. `ARTIFACT_RETENTION_DAYS` 7 → 30 (`config.py:148`). No other change: `cleanup_old_scan_artifacts` already reads the setting (`tasks.py:1477`).

**Consequences.** Redis (30-day `SCAN_RESULT_TTL`) and Postgres agree within one purge interval, satisfying SY-7's verify. **Recorded residual risk, reaffirmed twice:** a 30-day window cannot evidence an annual audit — a four-month-old scan will not exist in Redis, Postgres, or on disk. The audit trail itself is exempt (item 5) so *who did what* survives even when *what they did it to* does not. `volatile-lru` (`docker-compose.yml:357`) can still evict Redis scan data before 30 days, so Redis may be *shorter* than Postgres; the purge never makes it longer. **T-44 precondition:** quadrupling artifact retention on a host that filled twice (228 GB/46 h at `docker-compose.yml:132-133`; 63 GB of leaked scratch at `tasks.py:1519-1520`) is a capacity change — `du`/`df` evidence before the flag flips.
**Alternatives rejected.** Purging by `created_at` alone (unindexed, full scan on the largest table). A `scanned_at` column on `vulnerabilities`/`licenses` (an Alembic revision plus a `dual_write` change to age rows that already cascade correctly by `scan_id`). Postgres partitioning (an infrastructure change for a dataset that fits one table). Shipping the purge enabled (destroys the evidence T-44 exists to size).

### ADR-11a — The edge cannot complete a WebSocket handshake today · **Accepted: fix the edge first**
**Context.** Neither `app/edge/nginx.conf` nor the root `nginx.conf` contains
`proxy_set_header Upgrade $http_upgrade`, `proxy_set_header Connection "upgrade"`,
or a `map $http_upgrade $connection_upgrade` block — verified: zero matches in
either file. nginx therefore does not forward the client's `Upgrade: websocket`
as an upgrade to FastAPI. Every WebSocket in this product reaches the browser
only because the dashboard bypasses the edge entirely, connecting to
`ws://${host}:7070` (`dashboard/src/api.js:304,309`).
**Decision.** The edge WS stanza is a prerequisite of T-20, not a detail of it.
Add the `map` block and both `proxy_set_header` lines to the `/api/` location in
`app/edge/nginx.conf`. Spike S1 (T-04) must run against that exact file — testing
against a stand-in proves nothing about production.
**Consequences.** T-20's acceptance ("closes 1008 through the edge") is
unreachable until this lands, and T-20b (the dashboard client moving off the
hardcoded `:7070`) depends on it. Sequence: edge stanza → S1 → T-20 + T-20b
together.
**Alternatives rejected.** Verifying only against `127.0.0.1:7070` — that is the
bypass the plan explicitly says not to rely on, and it would let M1 pass while
production WebSockets are still either broken or unauthenticated.

### ADR-8 — `routes_v2.py` decomposition · **Accepted: DO NOT SPLIT**
**Context.** 2,906 LOC, 97 endpoints, fan-out 24 (`architecture-map.md` §3), ~7 endpoints exercised today. 13 stories land in it. The plan carries two dependency graphs pending this decision. T-11 is itself blocked on T-02, T-10, **T-20 and T-21**.

**Decision.** `routes_v2.py` is **not split** this cycle. T-11 does not run. Branch B of the plan (`03-plan.md` §4) is the executing graph. One mitigation is adopted: **every NEW endpoint added this cycle goes into a new module under `app/app/routers/`**, mounted by `main.py` on the same `/api/v2` prefix — specifically T-41 (`routers/audit.py`), T-42 (`routers/compliance_admin.py`) and T-61 (`routers/license_policy.py`). Existing endpoints do not move; no route path changes; the route-snapshot proof T-11 required is unnecessary because no existing line is touched.

**Justification.** T-11's parallelism arrives after M1 ships — roughly mid-cycle — while its cost is a mechanical move of 97 endpoints across the highest fan-out module in the system, guarded by a test suite whose own stated bar is "status-code and response-shape… a tripwire, not behavioural depth" (T-02 acceptance). Doing that in the same cycle that adds a WebSocket auth rewrite, ~27 audit call sites and an ownership check to 22 handlers in the same file trades a *merge-conflict* risk for a *silent behavioural regression* risk on production security endpoints. That is the wrong trade.

**Cost, stated plainly.** Fourteen tasks serialize into one lane: T-20 → T-21 → T-22 → T-23 → T-24 → T-25 → T-30 → T-40a → T-40b → T-40c → T-53(API) → T-63. The new-router carve-out pulls T-41, T-42 and T-61 **out** of that lane, leaving twelve. The cycle has four effective lanes (routes_v2, tasks.py, dashboard, tests/CI/ADR) instead of eight, and its length is paced by the routes_v2 lane. If that lane slips, drop in this order: **T-63** (cosmetic under ADR-1), then **T-61**. Say so at checkpoint C4, not at the end.
**Alternatives rejected.** *Split auth/policy/iac before the cycle* — see above; also collides with T-20, which the plan itself flags as an out-of-band hotfix inside `routes_v2.py`. *Split after M1* — buys parallelism for M2–M4 only, at full risk, and re-bases three in-flight branches. *Split as part of each task* — no route-snapshot proof is possible when behaviour is changing in the same commit.

### ADR-9 — Identity source · **Deferred.** AU-9/OQ-6 out of cycle; `created_by` and `audit_log.actor` may name a shared account. Recorded because OQ-5 has made AU-9 a compliance dependency for next cycle. Rejected: adding a `users` table now (a new domain = model + revision + dual-write mapper + reader + parity arm, R15, for no in-cycle story).

### ADR-10 — Monitoring topology · **Deferred.** SY-9 out of scope pending S5 (T-07). No compose overlay is built. Rejected: shipping the overlay speculatively before S5 answers whether a central Prometheus scrapes this host.

### ADR-11 — WebSocket authentication transport · **Accepted, dual-outcome**
**Context.** Both routes are bare (`routes_v2.py:1136-1140`, `:1168-1170`); `/ws/global` streams every completion payload to anyone reaching the edge. Browsers cannot set headers on a WebSocket. **Spike S1 (T-04) has not run.** Cookie is `apex_token`, HttpOnly, `SameSite=lax`, `Secure` per env (`auth.py:34,37,38,552-563`).

**Decision.** One seam, two possible fills. `websocket_manager.py` gains:

```python
async def authenticate_websocket(websocket: WebSocket) -> Optional[TokenData]
```

- **Outcome A — the edge forwards the cookie on `Upgrade` (the assumed default).** `authenticate_websocket` reads `websocket.cookies.get(AUTH_COOKIE_NAME)` and calls `verify_token`. Client: `api.js` derives the URL from `API_BASE_URL` (already origin-derived, `api.js:10-26`) with `http→ws`; no credential in the URL. **This is what the design assumes**, on the evidence that the app is same-origin behind the edge (`api.js:5-9,22`), `withCredentials` is already set on both axios instances (`:33,:41`), and `SameSite=lax` does not suppress a same-site WebSocket handshake.
- **Outcome B — the cookie does not arrive.** A ticket branch is added to the *same* function: `POST /api/v2/ws-ticket` (auth `get_current_user`) mints an opaque token stored at `ws_ticket:{ticket}` → username with TTL 30 s, consumed with `GETDEL` on first use; the client appends `?ticket=`. Nothing else changes.

Handshake protocol, binding for both outcomes:
1. `user = await authenticate_websocket(websocket)`
2. If `None`: **`await websocket.accept()` then `await websocket.close(code=1008)`**, return, send nothing. The accept-then-close order is deliberate — a pre-accept close produces an HTTP 403 on the upgrade, and T-20's own pytest asserts `WebSocketDisconnect(1008)`, which only an accepted-then-closed socket produces.
3. Only then `await manager.connect(websocket, scan_id)`.
4. `/ws/scan/{id}` performs **no ownership check** (ADR-1 / OQ-11).

Two latent bugs are fixed in the same task: `pubsub` is initialised to `None` before the `try` and the `finally` at `:1165` guards it (today it raises `UnboundLocalError` when `manager.connect` throws); and the per-connection `RedisPubSubManager` (`:1152`, `:1174`) becomes **one process-wide pump** — a module-level instance that lazily connects on the first subscriber, disconnects after the last, and fans out to per-subscriber `asyncio.Queue(maxsize=100)` with **drop-oldest** on overflow. The bound is not optional: with a shared pump and unbounded queues, one stalled browser tab blocks the pump for everyone, which is strictly worse than today's one-connection-per-tab behaviour.

**Consequences.** The ticket path is specified but **not built unless S1 returns outcome B** — no wasted work, and no second ADR either way. T-20 and T-20b must deploy together; shipping the server side alone kills live scan progress for every user (`api.js:304,:309` hardcode `ws://host:7070` with no credential). If S1 has not reported when the routes_v2 lane reaches T-20, build outcome A and treat S1 as the verification step.
**Alternatives rejected.** `Sec-WebSocket-Protocol` as a bearer channel (works, but is a bespoke protocol the edge may strip and the dashboard would have to special-case). Token in the query string permanently (lands in edge access logs). Deferring T-20 until S1 lands (this is the highest-exposure open finding — R1).

### ADR-11b — WebSocket hardening beyond authentication · **Accepted**
**Context.** Authenticating the handshake is necessary but not sufficient.
Three gaps the first draft left open:
1. **Cross-site WebSocket hijack.** Browsers do not uniformly withhold a
   `SameSite=lax` cookie from a cross-site WS `Upgrade` the way they do from a
   cross-site fetch. A page on any origin can open
   `wss://apexscanner.6dcorp.internal/api/v2/ws/global`; if the cookie rides
   along, that page receives every scan-completion payload system-wide. Under
   ADR-1 there is deliberately no per-scan ownership check, so the blast radius
   is every scan, not the attacker's own.
2. **Mid-connection expiry.** Once the handshake succeeds nothing re-checks the
   token. A revoked session keeps its firehose for the life of the connection,
   which is `SCAN_TIMEOUT`-scale. HTTP re-validates on every request; WS would
   not.
3. **Shared-pump exhaustion.** Moving to one process-wide pump fixes
   head-of-line blocking but makes every subscriber share fate. Nothing caps
   concurrent connections, so one authenticated identity can starve the pump —
   a failure mode the old one-pubsub-per-connection design did not have.
**Decision.** `authenticate_websocket()` performs, in order: (a) `Origin` header
compared against an explicit allow-list of the edge FQDN, rejecting on mismatch
or absence, before any credential check; (b) the ADR-11 credential check;
(c) a per-user and global connection cap enforced in `manager.connect`.
Connections close at token `exp` rather than running unbounded.
**Consequences.** One string comparison and one counter. Non-browser clients
(`websocat`, CI) must send an `Origin` header, which the T-20 verify must
reflect.
**Alternatives rejected.** Relying on `SameSite` alone — the inconsistency
across engines is the whole problem. Relying on the credential check alone — it
authenticates *who*, not *from where*.

### ADR-12 — Audit write path · **Accepted**
**Context.** `record_audit` (`db/audit.py:16-34`) opens a synchronous psycopg session and commits. It is called from `async def` handlers (`routes_v2.py:70,72,2219,2355,2468,2504`). T-40 adds ~27 more sites to a single-process uvicorn (`Dockerfile.api:59`) — ~27 more blocking round-trips on the one event loop. Failures are swallowed at debug (`:34`), so an audit gap is silent, and OQ-5 has made the audit log compliance evidence.

**Decision.**
1. New helper in `db/audit.py`:
   ```python
   def audit(background_tasks: BackgroundTasks, actor: Optional[str], action: str,
             target: Optional[str] = None, detail: Optional[Dict[str, Any]] = None,
             ip: Optional[str] = None) -> None:
       background_tasks.add_task(record_audit, actor, action, target, detail, ip)
   ```
   Starlette runs a non-coroutine background task in a threadpool, so this gives both after-response execution **and** loop offload — one line per call site, no new infrastructure.
2. **Rule: no async handler calls `record_audit` directly.** All ~33 sites (6 existing + ~27 new) use `audit(background_tasks, …)`. `BackgroundTasks` is added as a handler parameter where absent. A test enumerating `app.routes` asserts the direct-call form is absent from handler bodies.
3. **Exception paths are the one exemption.** Background tasks attached to a request never run when the handler raises (the login-failure audit at `routes_v2.py:70` is exactly this case). Those sites use `await run_in_threadpool(record_audit, …)` immediately before re-raising — still off the loop, still executed.
4. `db/audit.py:34` logs at **WARNING** (not debug) and increments a new Prometheus counter `scanner_audit_write_failures_total{action}`. A gap becomes alertable instead of invisible.
5. `record_audit` itself is unchanged in signature and remains the only writer, so the Celery-side callers (if any are added) keep working.

**Consequences.** The audit row is written **after** the response is sent, so a write failure cannot fail the request (see §5 — this is the deliberate decision). Under a hard API crash between response and write, a row can be lost; the WARNING + counter make that detectable, and the durability requirement in SY-8 is "readable evidence", not "two-phase commit". Ordering between two rapid mutations is by `ts` (index `ix_audit_log_ts`); `id DESC` is the paging tiebreak.
**Alternatives rejected.** `await run_in_threadpool(record_audit, …)` everywhere (correct but adds a DB round-trip to the latency of every admin mutation for no evidentiary gain, since it still cannot be transactional with a Redis-backed mutation). A Celery `system` task per audit row (makes the audit log depend on broker health and worker liveness — a broker outage would silently drop evidence, exactly the failure mode OQ-5 forbids). An async SQLAlchemy path (`db/engine.py` exists) — a second write path to the same table plus a session-lifecycle problem in `BackgroundTasks`, for a ~1 ms insert.

### ADR-13 — Runtime-tunable configuration store · **Accepted** (gates T-42, T-61)
**Context.** `compliance.py:23` and `license_compliance.py:50` hold policy numbers in module constants. OQ-5 requires thresholds be settable at runtime, persisted across a container restart. `kv_settings` already exists (`db/models.py:91`, baseline revision `:46-50`) and is unused.
**Decision.** New `app/app/settings_store.py` with `get(key, default) -> Any` and `put(key, value) -> None` over `kv_settings`, using the same sync-session-with-`None`-on-failure pattern as `read_pg.py:15-32`. Two keys this cycle: `compliance.thresholds`, `license.policy`. Values are stored as a **sparse overlay**, never a full copy — `{framework_id: {control_id: {key: value}}}` merged over `compliance.FRAMEWORKS` at read time. Reads from async handlers go through `run_in_threadpool`; the worker calls it synchronously. No caching layer.
**Consequences.** A control or framework added in code later appears automatically; a stale stored blob can never pin an obsolete framework definition. With `DATABASE_URL` empty, reads return the code defaults and writes fail 503. One extra ~1 ms threadpool read per uncached compliance call — negligible against the existing 1 h result cache (`compliance.py:15`).
**Alternatives rejected.** Redis (survives restart, but puts audit-relevant policy in the store that runs `volatile-lru`, and splits the config of record across two datastores). Full-document storage (freezes the framework definitions at write time). An in-process cache (coherent today at one uvicorn process, incoherent the moment `--workers` >1 lands — the carve-out in the plan; not worth the invalidation bug for 1 ms).

### ADR-14 — Conventions for new v2 endpoints · **Accepted**
**Context.** Four new endpoint groups land this cycle, written by different builders in different files.
**Decision.** New endpoints only: list responses use the envelope `{"items": [...], "total": int, "limit": int, "offset": int}`; paging params are `limit: int = Query(50, ge=1, le=200)` and `offset: int = Query(0, ge=0)` matching `routes_v2.py:132-133`; timestamps are ISO-8601 UTC strings via `app.time_utils.now_iso`; errors are `HTTPException(status_code, detail=<str>)`; admin gating is `Depends(get_current_admin)`, read gating `Depends(get_current_user)`; every new module uses `structlog` via `app.logging_config.get_logger`. **Existing responses are not reshaped** — `GET /api/v2/api-keys` keeps `{"total", "keys"}` (`routes_v2.py:2482`), because T-70 and every existing client depend on it.
**Consequences.** T-41's verify (`jq '.items | length'`) is satisfied by construction. The API has two list shapes; the boundary is "new this cycle" and is documented here rather than discovered.
**Alternatives rejected.** Retrofitting the envelope across 97 endpoints (that is a breaking change disguised as tidiness).

---

## 3. API contracts

All new/changed surfaces. Pydantic models live next to their handler unless stated.

### 3.1 T-41 — Audit read · NEW · `app/app/routers/audit.py`

```
GET /api/v2/audit
```
Auth: `Depends(get_current_admin)` → 401 unauthenticated, 403 non-admin.

Query: `actor: Optional[str] = Query(None)`, `action: Optional[str] = Query(None)`, `target: Optional[str] = Query(None)`, `start: Optional[datetime] = Query(None, description="inclusive, ISO-8601")`, `end: Optional[datetime] = Query(None, description="exclusive, ISO-8601")`, `limit: int = Query(50, ge=1, le=200)`, `offset: int = Query(0, ge=0)`.
`actor` and `action` are exact matches (both indexed / cheap); no `LIKE`.

```python
class AuditEntry(BaseModel):
    id: int
    ts: str                       # ISO-8601 UTC
    actor: Optional[str] = None
    action: str
    target: Optional[str] = None
    ip: Optional[str] = None
    detail: Dict[str, Any] = Field(default_factory=dict)

class AuditListResponse(BaseModel):
    items: List[AuditEntry]
    total: int
    limit: int
    offset: int
```
Handler: `async def list_audit(...) -> AuditListResponse`.
Data access — two new functions in `app/app/db/read_pg.py`, `_run`-wrapped, called via `run_in_threadpool`:
```python
def read_audit_page(actor, action, target, start, end, limit, offset) -> Optional[List[Dict[str, Any]]]
def read_audit_count(actor, action, target, start, end) -> Optional[int]
```
Order: `ts DESC, id DESC` (`ix_audit_log_ts`; `id` is the stable paging tiebreak).
**Failure is closed:** `DATABASE_URL` empty, or either function returns `None` → `HTTPException(503, "Audit log unavailable")`. Never an empty `items` list — "no evidence" and "cannot reach the evidence store" must not look identical to an auditor.

### 3.2 T-42 — Compliance thresholds · NEW · `app/app/routers/compliance_admin.py`

```
GET /api/v2/compliance/thresholds                      -> ThresholdsResponse       (get_current_user)
PUT /api/v2/compliance/thresholds/{framework_id}       -> FrameworkThresholds      (get_current_admin)
```
`framework_id ∈ {"pci-dss-4.0","soc2","hipaa","fedramp"}` (`compliance.py:23,57,81,105`) → 404 otherwise.

```python
TUNABLE_KEYS = {
    "max_critical", "max_high", "max_kev",
    "max_fixable_critical", "max_fixable_high",
    "max_scan_age_days", "max_days_unpatched", "max_db_age_days",
    "remediation_sla_critical_days", "remediation_sla_high_days",
}

class FrameworkThresholds(BaseModel):
    framework_id: str
    name: str
    controls: Dict[str, Dict[str, int]]      # control_id -> effective thresholds
    overridden: Dict[str, List[str]]         # control_id -> keys whose value is an override

class ThresholdsResponse(BaseModel):
    frameworks: List[FrameworkThresholds]

class ThresholdUpdateRequest(BaseModel):
    thresholds: Dict[str, Dict[str, int]]    # control_id -> {tunable_key: value >= 0}
```
Validation: unknown `control_id` for the framework → 400; key not in `TUNABLE_KEYS` → 400; negative value → 422. `blocked_cwe` lists (HIPAA, `compliance.py:89,101`) are **not tunable** this cycle.
Side effects of a successful PUT, both mandatory:
1. `audit(background_tasks, admin.username, "compliance.threshold.update", target=framework_id, detail={"changed": {...}, "previous": {...}}, ip=client_ip(http_request))` — the action string is pinned by T-42's verify.
2. **Invalidate the compliance result cache** — delete `compliance:*` keys (prefix at `compliance.py:16`, 1 h TTL at `:15`) using `app.trends.scan_redis_keys`. Without this, `/scan/{id}/compliance` serves pre-change verdicts for up to an hour and the change appears to have had no effect. The plan does not mention this; it is required.

The existing `GET /api/v2/compliance/frameworks` (`routes_v2.py:2589`) and `GET /api/v2/scan/{id}/compliance` (`:2601`) are **unchanged at the route layer** — `compliance.get_frameworks_list()` and the evaluators resolve effective thresholds internally via ADR-13. This is why T-42 needs zero `routes_v2.py` edits, deviating from the plan's stated file list for T-42 (`03-plan.md` T-42 says "routes_v2.py (new GET/PUT)").

### 3.3 T-30 — API keys with role and owner · CHANGED · `app/app/auth.py` + `routes_v2.py:2453`

```python
class APIKeyCreate(BaseModel):                 # auth.py:69
    name: str
    expires_days: Optional[int] = 365
    role: Literal["user", "admin"] = "user"
    owner: Optional[str] = None                # None -> the creating admin's username

class APIKeyResponse(BaseModel):               # auth.py:75
    key: str
    key_id: str
    name: str
    created_at: str
    expires_at: Optional[str] = None
    role: str                                  # NEW
    owner: str                                 # NEW

class APIKeyInfo(BaseModel):                   # auth.py:84
    key_id: str
    name: str
    created_at: str
    expires_at: Optional[str] = None
    last_used: Optional[str] = None
    role: str = "admin"                        # NEW — absent in a legacy hash => admin (ADR-2)
    owner: Optional[str] = None                # NEW — absent => falls back to created_by
```
```python
def create_api_key(name: str, expires_days: Optional[int] = 365,
                   role: str = "user", owner: Optional[str] = None,
                   created_by: Optional[str] = None) -> APIKeyResponse
def validate_api_key(raw_key: str) -> Optional[TokenData]
    # username = key_data.get("owner") or key_data.get("created_by", "api_key")
    # role     = key_data.get("role", "admin")     <- unchanged line auth.py:330
def list_api_keys() -> list[APIKeyInfo]
```
Redis hash `api_key:{sha256}` gains `role` and `owner`; `created_by` retained as minting provenance.
Endpoints: `POST /api/v2/api-keys` → `APIKeyResponse`; `GET /api/v2/api-keys` → `{"total": int, "keys": [APIKeyInfo]}` (**shape preserved**, ADR-14); `DELETE /api/v2/api-keys/{key_id}` unchanged. The create audit detail gains `{"role":…, "owner":…}`.

### 3.4 T-20 — WebSocket handshake · CHANGED · `routes_v2.py:1136,:1168` + `websocket_manager.py`

Route paths and handler signatures are unchanged (FastAPI WS routes cannot raise `HTTPException`, so auth is an in-body call, not a `Depends`):
```python
@router_v2.websocket("/ws/scan/{scan_id}")
async def websocket_scan_progress(websocket: WebSocket, scan_id: str)

@router_v2.websocket("/ws/global")
async def websocket_global(websocket: WebSocket)
```
New in `websocket_manager.py`:
```python
async def authenticate_websocket(websocket: WebSocket) -> Optional[TokenData]
```
Handshake outcomes:

| Case | Server behaviour |
|---|---|
| Valid `apex_token` cookie (outcome A) | `accept()` → `manager.connect()` → stream |
| Valid `?ticket=` (outcome B only) | ticket consumed via `GETDEL`, then as above |
| No/invalid credential | `accept()` → `close(code=1008)` → return, zero payloads |
| Redis pub/sub unavailable | `accept()` → `close(code=1011)` |

Outcome-B-only endpoint:
```
POST /api/v2/ws-ticket   ->  WsTicketResponse        (get_current_user)

class WsTicketResponse(BaseModel):
    ticket: str
    expires_in: int = 30
```
Client (T-20b, replacing `api.js:301-310`):
```js
const wsBase = API_BASE_URL.replace(/^http/, 'ws');
export const getWsUrl = (scanId) => `${wsBase}/api/v2/ws/scan/${scanId}`;
export const getGlobalWsUrl = () => `${wsBase}/api/v2/ws/global`;
```
`API_BASE_URL` is already origin-derived (`api.js:10-26`), so `https` → `wss` and the edge is used. `grep -c ":7070" dashboard/src/api.js` → 0.

### 3.5 T-61 — License policy · NEW · `app/app/routers/license_policy.py`

```
GET /api/v2/license-policy   -> LicensePolicyResponse   (get_current_user)
PUT /api/v2/license-policy   -> LicensePolicyResponse   (get_current_admin)
```
```python
class LicensePolicyResponse(BaseModel):
    categories: Dict[str, str]      # the 7 keys of license_compliance.CATEGORY_ORDER (:38-46)
    is_default: bool

class LicensePolicyUpdate(BaseModel):
    categories: Dict[str, Literal["pass", "info", "warn", "fail"]]
```
Stored at `kv_settings["license.policy"]`; defaults are `license_compliance.DEFAULT_POLICY` (`:50-58`). Worker side: `tasks.py:760` becomes `evaluate_licenses(sbom_packages, policy=load_license_policy())` — a synchronous `settings_store.get` on a Celery worker, no loop concern. PUT writes audit `license.policy.update`.
**Plan/code disagreement:** T-73's verify says "set AGPL-3.0 to fail". The engine's policy is **per category**, not per SPDX id (`license_compliance.evaluate(packages, policy: Dict[str,str])`, `:283,:289`). AGPL is `network_copyleft`, which already defaults to `fail` (`:51`). Per-license overrides are **not** built this cycle — they would require an engine change. T-73's UI edits the seven categories; the verify should be restated as "set `network_copyleft` to fail".

### 3.6 T-50/T-51/T-43 — Celery task contracts · NEW · `app/app/tasks.py`

```python
@celery.task(bind=True, name='dispatch_due_schedules')
def dispatch_due_schedules(self) -> Dict[str, Any]
    # -> {"evaluated": int, "fired": [str], "skipped_locked": [str]}

@celery.task(bind=True, name='run_scheduled_scan')
def run_scheduled_scan(self, schedule_name: str) -> Dict[str, Any]
    # -> {"schedule": str, "scan_ids": [str], "image_count": int,
    #     "new_scans": int, "skipped_duplicates": int}

@celery.task(bind=True, name='purge_expired_records')
def purge_expired_records(self) -> Dict[str, Any]
    # -> {"cutoff": iso, "scans": int, "vulnerabilities": int,
    #     "licenses": int, "batches": int, "audit_log": int}
```
`task_routes` (`tasks.py:105-114`) gains all three → `{'queue': 'system', 'routing_key': 'system'}`.
`beat_schedule` (`tasks.py:1283`) gains `dispatch-due-schedules` at `60.0` unconditionally, and `purge-expired-records` at `86400.0` **only when `settings.RETENTION_PURGE_ENABLED`**.

### 3.7 Endpoints changed in behaviour but not in shape

| Endpoint | Change |
|---|---|
| `GET /api/v2/scan/{id}/policy-check` (`routes_v2.py:2408`) | passes a `ScanContext`; results may carry `status:"skipped"` (T-23) and each result gains `suppressed_by_vex: []` (T-24) |
| `POST /api/v2/policies/evaluate` (`:2365`) | passes a `ScanContext` when `scan_id` is supplied |
| `GET /api/v2/batches/{id}/policy-check` (`:219`) | one `ScanContext` per scan id |
| `PUT /api/v2/policies/{id}` (`:2300`) | gains `http_request: Request` + `BackgroundTasks` and an `policy.update` audit row — it has **neither** today |
| `PUT /api/v2/risk-weights` (`:1405`) | audit `risk.weights.update` (RS-3, folded into T-40) |
| `DELETE /api/v2/workers/queues/{queue}`, cache invalidation, forced DB update, schedule CRUD (`:399,:471,:491,:510`), VEX CRUD, base-image CRUD | one audit row each (T-40a/b/c) |
| `GET /api/v1/scan/{id}` (`routes.py:719`) + 22 `routes_v2.py` per-scan handlers | `ownership.can_view` (T-63); report/SBOM/compare surfaces excluded (ADR-1) |

---

### ADR-15 — Audit actor IP must not be client-controlled · **Accepted**
**Context.** `client_ip()` (`db/audit.py:37-45`) returns
`request.headers["x-forwarded-for"].split(",")[0]` — the *first* entry. Both
nginx configs set XFF with `$proxy_add_x_forwarded_for`
(`nginx.conf:70,95,110`; `app/edge/nginx.conf:75`), which **appends** the edge's
`$remote_addr` to whatever the client already sent. A client sending
`X-Forwarded-For: 1.2.3.4` produces `1.2.3.4, <real-ip>` at the API, and the
audit row records `1.2.3.4`. Every "who did what from where" row this cycle adds
is trivially falsifiable — in a log that OQ-5 just designated audit evidence.
**Decision.** Read `X-Real-IP` (`nginx.conf:69`, `app/edge/nginx.conf:74`), which
the edge sets to `$remote_addr` verbatim and does not append to. Fall back to the
last XFF entry, never the first. Client-supplied XFF is not trusted.
**Consequences.** One-line change in `db/audit.py`. Correct behind this edge; if
a second proxy is ever added in front, `X-Real-IP` becomes that proxy's address
and the trust model needs restating.
**Alternatives rejected.** Trusting the first XFF entry (the current bug).
Stripping XFF at the edge (loses the real chain for debugging).

### ADR-16 — Outbound webhook targets must be allow-listed · **Accepted**
**Context.** T-52 turns a stored, admin-supplied `google_chat_webhook`
(`scheduler.py:343`) into an automatic outbound POST on every scheduled-scan
completion — no operator confirmation, and failure is silent by design so the
scan still succeeds. Schedule creation is admin-gated, which the grandfathered
keys satisfy. That is an attacker-triggerable SSRF primitive against anything
the worker can reach, with the errors swallowed.
**Decision.** Validate the webhook host against an allow-list
(`chat.googleapis.com` by default, configurable) and require `https://`, at
schedule create/update **and** at fire time. Rejection is a 422 at CRUD time and
a skipped send plus a WARNING at fire time.
**Consequences.** Applies to the existing SH-1 CRUD as well as the new T-52 path,
so it is a small change to already-shipped code.
**Alternatives rejected.** Validating only at creation (a stored row predating
the check would still fire). Egress network policy alone (correct, but out of
scope this cycle and not something the app can assert).

### ADR-17 — Compliance threshold writes are bounded and reads fail closed · **Accepted**
**Context.** Two gaps. (a) `ThresholdUpdateRequest` validates only
non-negative integers, so `max_fixable_critical: 999999` disables a control
while the framework still reports "assessed". (b) Threshold *writes* fail closed
on a DB outage but *reads* silently fall back to code defaults with
`overridden: {}` — so an auditor querying during a blip sees the default and
concludes nothing was overridden, when an override exists and is merely
unreadable. That is the same "evidence looks like its absence" failure the audit
endpoint correctly rules out.
**Decision.** (a) Each tunable key carries a documented ceiling; exceeding it is
422, so disabling a control requires an explicit out-of-band change rather than
a large integer. (b) `GET /api/v2/compliance/thresholds` returns 503 when the
store is unreachable — never code defaults presented as confirmed-current.
**Consequences.** The threshold read joins the audit read in preferring an
honest error to a plausible lie.
**Alternatives rejected.** Unbounded integers with an alert (the alerting path
is ADR-10, deferred). Serving defaults with a `stale: true` flag (callers ignore
flags).

### ADR-18 — New third-party dependency: cron evaluation · **Accepted**
**Context.** ADR-3's dispatch loop must decide whether a stored
`cron_expression` is due on each tick. `croniter` is **not** in
`app/requirements.txt` (verified: zero matches) and the first draft of this
design did not flag it as a new dependency.
**Decision.** Use `celery.schedules.crontab`'s own `is_due()` — Celery is already
a dependency, the expressions are already Celery-flavoured, and this adds no new
supply-chain surface to a security product. If a case appears that `crontab`
cannot express, add `croniter` explicitly with a pinned version and a checksum,
matching how the scanner binaries are handled.
**Consequences.** No new dependency this cycle.
**Alternatives rejected.** Adding `croniter` silently — in a product whose own
value proposition is dependency risk, an unflagged new import is the wrong
default.

## 4. Data model changes

**No Alembic revision is required this cycle.** Specifically:

| Need | Status |
|---|---|
| `kv_settings` for T-42 and T-61 | **Exists** — `db/models.py:91-95`, created in the baseline revision (`1d68b1e53cac_baseline_schema.py:46-50`). No revision |
| Purge by `scan_timestamp` (T-43) | **Indexed already** — `ix_scans_scan_timestamp` (`baseline:83`, `models.py:26`). No revision. The plan's "add the index migration if the purge scans sequentially" resolves to **no** |
| Cascade `vulnerabilities` by `scan_id` | **Indexed** — `ix_vulnerabilities_scan_id` (`baseline:100`) |
| Cascade `licenses` by `scan_id` | **Primary key** (`baseline:51-56`) |
| Purge `batches` by `created_at` | **Indexed** — `ix_batches_created_at` (`baseline:44`) |
| Purge `audit_log` by `ts`; filter by `actor` (T-41) | **Indexed** — `ix_audit_log_ts`, `ix_audit_log_actor` (`baseline:33-34`) |
| API-key `role`/`owner` (T-30) | Redis hash fields — schemaless, no migration (ADR-2) |
| `created_by` on schedules (T-53, gap G-C) | Redis hash field — no migration |

**The one conditional revision, specified but not shipped.** The purge's NULL tail (`scan_timestamp IS NULL AND created_at < cutoff`, ADR-6 §4) is a sequential scan. If a purge run is measured over 30 s in a real dataset, add exactly one revision:

```python
op.create_index("ix_scans_created_at_unfinished", "scans", ["created_at"],
                postgresql_where=sa.text("scan_timestamp IS NULL"))
```
Owner: the single named Alembic owner for the cycle (feasibility R15). Do not add it speculatively.

**No new tables, no new columns, no new domains.** IA-4 (IaC results), AU-9 (users) and CO-3 are out of scope, which is what keeps R15 dormant.

---

## 5. Error-handling strategy for the new paths

| Path | Mode | Behaviour |
|---|---|---|
| **WebSocket handshake, no/invalid credential** | **Fails closed** | `accept()` then `close(1008)`, zero payloads. No fallback to an anonymous read-only stream |
| **WebSocket, Redis pub/sub unreachable** | **Fails closed** | `close(1011)`. Never hold an accepted socket that will never receive data |
| **WebSocket, one slow subscriber** | **Degrades, locally** | Bounded `asyncio.Queue(maxsize=100)`, drop-oldest for that subscriber only. The shared pump never blocks |
| **`GET /api/v2/audit`, store unreachable** | **Fails closed** | 503, never `items: []`. "No evidence" and "cannot read the evidence store" must be distinguishable |
| **Audit *write* failure** | **Best-effort — does NOT fail the request.** Decided explicitly | Logged at **WARNING** (was debug, `db/audit.py:34`) + `scanner_audit_write_failures_total`. Rationale: the write runs after the response (ADR-12), and failing a completed mutation because its record failed would leave the system in a state the log also does not describe — strictly worse. The compliance obligation is met by making the gap **loud and countable**, not by rolling back. Deviation from a strict-evidence posture, recorded deliberately |
| **Policy rule that cannot be evaluated** | **Fails closed — unchanged** | Existing behaviour at `policy_engine.py:327-343` is preserved verbatim by T-22/23/24/25 |
| **`ScanContext` build: scan hash missing** | **Fails closed** | 404 before evaluation, matching `routes_v2.py:2414-2415` |
| **`ScanContext` build: catalog unavailable/disabled** | **Degrades** | `approved_base_image=None`; the T-25 rule does not fire. An unreachable GitLab must not fail every scan in the estate. `gitlab_catalog.get_catalog` already prefers a last-good copy (`:132-143`) |
| **`ScanContext` build: no VEX statements** | **Degrades** | Empty maps; nothing is suppressed. Fail-closed by construction |
| **Compliance threshold read, DB unavailable** | **Degrades** | Falls back to the `compliance.py:23` defaults, and the response marks `overridden: {}`. An auditor sees code defaults, never a blank framework |
| **Compliance threshold write, DB unavailable** | **Fails closed** | 503. Never accept a change that is not persisted |
| **Scheduled dispatch: duplicate tick** | **Fails closed** | `SET NX EX 120` lock; the loser does nothing |
| **Scheduled dispatch: missed window** | **Degrades — no backfill** | Skipped firings are not replayed. Logged at WARNING with the gap |
| **`run_scheduled_scan`: one image fails to enqueue** | **Degrades** | Remaining images still enqueue; failures are counted in the return value and logged |
| **Scheduled-scan notification (T-52)** | **Best-effort** | Webhook failure never fails the scan (already the behaviour at `scheduler.py:309-315`) |
| **Purge: a batch transaction fails** | **Degrades, resumes** | Per-batch transaction; the run aborts and returns partial counts. The next daily run resumes — the predicate is idempotent |
| **Purge: `RETENTION_PURGE_ENABLED=false`** | **Inert** | No beat entry exists at all; the task cannot be triggered by the schedule |
| **API key with no stored role** | **Fails open, deliberately** | Resolved as `admin` (ADR-2), WARNING logged. Closed by T-31, not by code |

---

## 6. Component interaction — the three riskiest changes

### 6.1 Policy `ScanContext` flow (T-22 → T-25)

```
Client  GET /api/v2/scan/{id}/policy-check
  │
  ▼ routes_v2.py:2408  check_scan_policies   [async, single event loop]
  1  vulns = VulnerabilityRepository(r).get_raw(scan_id)        (:2413)  -> 404 if empty
  2  ctx = await run_in_threadpool(build_scan_context, scan_id)          <-- THE loop boundary
     │   policy_context.build_scan_context  [sync, worker thread]
     │     2a  hash = r.hgetall(scan_id)
     │           image_name, image_digest,
     │           base_image_os / _os_id / _os_version   (written tasks.py:883-886)
     │     2b  vex_status = {CVE: status} via VEXManager.get_statements_for_cve (vex.py:177)
     │           product-scoped only — vex.py:204-212 rule reused verbatim
     │     2c  approved_base_image = gitlab_catalog.is_approved_base(get_catalog(), hash)
     │           GITLAB_CATALOG_ENABLED false / unreachable / OS unknown -> None
     │           get_catalog is sync httpx 20 s (gitlab_catalog.py:96) — SAFE only here
     └─> ScanContext(frozen)
  3  for policy in policy_engine.list_policies():   if not policy.enabled: continue
  4    policy_engine.evaluate_vulnerabilities(policy.id, vulns, context=ctx)
       4a  T-23  apply_to non-empty and no fnmatch(ctx.image_name) -> status="skipped",
                 passed=True, and the loop continues. overall_passed unaffected
       4b  T-24  drop vulns where ctx.vex_status[CVE]=="not_affected";
                 append each to result.suppressed_by_vex
       4c  per-vuln rules   -> _evaluate_rule -> _compare      (unchanged, :399/:486)
       4d  T-25  rule.field in SCAN_LEVEL_FIELDS -> compared ONCE against ctx;
                 ctx.approved_base_image is None -> rule does not fire;
                 match -> one synthetic item  {"field","value"}
       4e  fail-closed on rule exception  (policy_engine.py:327-343, unchanged)
  5  overall_passed = all(r.passed)      -> response + suppressed_by_vex
```
T-22 alone must change no verdict: with `context=None` every branch above is inert, which is why `pytest tests/test_policy_engine.py` passes unchanged.
**Non-obvious failure this ordering prevents:** step 4d evaluated per-vulnerability instead of once would let an unapproved base image with zero CVEs pass the gate silently.

### 6.2 Schedule firing loop (T-50 → T-53)

```
celery beat  (container celery_beat, no volumes, docker-compose.yml:242-256)
  │  static entry 'dispatch-due-schedules', every 60 s, queue system
  ▼
worker-system  dispatch_due_schedules
  1  ScheduleManager().list_schedules()            scheduler.py:385  (Redis)
  2  for each enabled schedule:
       croniter(cron_expression).matches(minute bucket)?  no -> skip
       SET schedule_fire:{name}:{YYYYMMDDHHMM} 1 NX EX 120   -> lost race -> skip
       run_scheduled_scan.apply_async(args=[name])
  ▼
worker-system  run_scheduled_scan(name)
  3  schedule = ScheduleManager().get_schedule(name)   -> gone -> log WARNING, return
  4  owner = schedule.get("created_by") or settings.ADMIN_USERNAME     [gap G-C]
  5  per image:
       dedup probe  scan_dedup:{image}      (same rule as routes_v2.py:533-543)
       scan_id = uuid4()
       ScanRepository.create(scan_id, {...,"created_by": owner,
                                       "schedule_name": name}, ttl=SCAN_RESULT_TTL)
           -> Redis hset  AND  dual_write.upsert_scan   (scan_repository.py:158-164)
       ScanRepository.record_owner(scan_id, owner)
       ScanRepository.add_to_history(image, scan_id, 100, ttl)
       scan_image.apply_async(args=[image, scan_id])    -> high_priority
  6  ScheduleManager.record_run(name, results)          scheduler.py:437  (schedule_runs:{name})
  ▼
worker-high  scan_image  ... existing pipeline ... completion
  7  T-52  webhook = schedule["google_chat_webhook"]  (scheduler.py:343, stored, never read today)
       GoogleChatNotifier(webhook).send_scan_report(...)  — failure logged, scan still completes
```
Step 5 is the parity fix: `routes_v2.py:552`, `tasks.py:1607` and `base_image_tracker.py:246,285` are converted to the same repository call, which is why `parity_check.py:46-47` stops counting new scans as `pg_missing`. Historical rows are reconciled by running `db/backfill.py`, not by this path.

### 6.3 WebSocket auth handshake (T-20 / T-20b)

```
Browser  ScanResults.js -> getWsUrl(scanId)          api.js (rewritten :301-310)
  wss://apexscanner.6dcorp.internal/api/v2/ws/scan/{id}     [origin-derived, no :7070]
  │  browser attaches cookie apex_token  (HttpOnly, SameSite=lax, same-origin)
  ▼ edge proxy: Upgrade  ──(S1 verifies the cookie survives this hop)──▶
api  routes_v2.py:1136 websocket_scan_progress
  1  user = await authenticate_websocket(ws)          websocket_manager.py (new)
       A  ws.cookies.get("apex_token") -> verify_token  (auth.py:34,237)
       B  [only if S1 = outcome B]  ws.query_params["ticket"] -> GETDEL ws_ticket:{t}
  2  user is None:
       await ws.accept();  await ws.close(code=1008);  return    # no payload, ever
       # accept-then-close is required: a pre-accept close yields HTTP 403 and
       # T-20's pytest asserts WebSocketDisconnect(1008)
  3  await manager.connect(ws, scan_id)               websocket_manager.py:47
  4  initial: r.get(f"progress:{scan_id}") -> send_text          (:1147-1149)
  5  q = await shared_pubsub.subscribe()   # ONE process-wide RedisPubSubManager,
                                           # lazily connected, refcounted;
                                           # per-subscriber Queue(maxsize=100), drop-oldest
  6  async for msg in q:  if msg["scan_id"] == scan_id: await ws.send_json(msg)
  7  finally: shared_pubsub.unsubscribe(q); manager.disconnect(ws)
       # pubsub initialised to None before the try — fixes the UnboundLocalError
       # at routes_v2.py:1165 when manager.connect throws
```
`/ws/global` is identical minus the `scan_id` filter and minus step 4. **No ownership check on either route** — ADR-1 / OQ-11. T-20 and T-20b deploy in the same release or live progress breaks for every user.

---

## 7. Plan / code disagreements found while designing

**D-0 — T-31's first verify clause is vacuous.** The plan verifies AU-6's
closure with "`GET /api/v2/api-keys` shows zero keys lacking a `role` field".
But `auth.py:277` writes `"role": "admin"` explicitly on every key ever minted,
so no stored key lacks the field — the clause is already true today, before any
rotation, and proves nothing. The second clause ("the S4 inventory is reconciled
to zero legacy keys") is the only real test. Amend T-31 to drop the first clause
and define "legacy" as *any key whose role was not deliberately set during
rotation*, tracked against the S4 inventory rather than inferred from the hash.

1. **`01-requirements.md:1160-1162` (AU-10, second criterion)** requires a non-owner be closed with 1008 on `/ws/scan/{id}`. OQ-11 and `03-plan.md` T-20's note void it. Requirements text is stale — **not** a design gap.
2. **`03-plan.md` T-30** says `APIKeyInfo` returns only `key_id`/`name`/`created_at`/`expires_at`. It also returns `last_used` (`auth.py:90`, `:350`).
3. **`03-plan.md` T-43** says "add the index migration if the purge scans sequentially". `ix_scans_scan_timestamp` already exists (`baseline:83`); the only sequential path is the `scan_timestamp IS NULL` tail, which the plan does not mention at all and which would otherwise leak every failed scan forever (§ADR-6.4).
4. **`03-plan.md` T-42** lists `routes_v2.py` as a file. Under ADR-8 it needs none — the new endpoints live in `routers/compliance_admin.py` and the existing compliance routes are unchanged.
5. **`03-plan.md` T-42** does not require compliance cache invalidation. Without it the 1 h cache at `compliance.py:15` serves pre-change verdicts (§3.2).
6. **`03-plan.md` T-53** requires stamping `created_by` on schedule-triggered scans, but schedules store no creator (`scheduler.py:326-350`). Gap G-C — flagged to BA.
7. **`03-plan.md` T-73** implies per-SPDX license granularity; `license_compliance.evaluate` is per-category (`:283,:289`). Verify wording needs restating (§3.5).
8. **`03-plan.md` headline "44 tasks"** does not reconcile with 43 backlog entries / 49 task ids (§1.3 G-A).
9. **`03-plan.md` §4** presents two dependency graphs. ADR-8 selects Branch B; Branch A and T-11 are void (G-B).agentId: ac31e0f5f8a0f12ed (use SendMessage with to: 'ac31e0f5f8a0f12ed', summary: '<5-10 word recap>' to continue this agent)
<usage>subagent_tokens: 187386
tool_uses: 48
duration_ms: 741982</usage>
