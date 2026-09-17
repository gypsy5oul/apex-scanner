# 02 — Feasibility Study

**Project:** Apex Scanner 3.0
**Status:** awaiting approval (stage 2 of 10)
**Date:** 2026-08-02
**Mode:** Brownfield. The system is built, deployed and serving users. The
question is not "can this be built" but "can the 19 gap + 5 partial stories be
delivered on this architecture, at what cost, and what is the risk of not
doing them".
**Inputs:** `01-requirements.md` (94 stories, 47 Must / 42 Should / 5 Could;
70 shipped / 5 partial / 19 gap), `architecture-map.md`, the running code.
**Assessed by:** solution-architect (technical), devops-engineer
(operational), business-analyst (business). Findings marked **[verified]**
were independently re-checked against source by the main session.

---

## Contents

- [1. Recommendation](#1-recommendation)
- [2. Technical feasibility](#2-technical-feasibility)
- [3. Operational feasibility](#3-operational-feasibility)
- [4. Business feasibility](#4-business-feasibility)
- [5. Risk register](#5-risk-register)
- [6. Spikes for the plan stage](#6-spikes-for-the-plan-stage)
- [7. ADRs required before development](#7-adrs-required-before-development)
- [8. Not feasible this cycle](#8-not-feasible-this-cycle)
- [9. Open questions blocking this stage](#9-open-questions-blocking-this-stage)

---

## 1. Recommendation

**GO WITH CONDITIONS.**

Supporting reasons:

1. **The asset is real and the gaps are bounded.** 70 of 94 stories are
   shipped and verifiable. Every gap is located to `file:line`, not inferred.
   Nothing found requires a rewrite of any subsystem.
2. **Most gap work is wiring, not construction.** Eight stories (SH-4, PG-5,
   VX-4, AC-2, LI-2, EN-4, RS-3, and half of SH-3) have their supporting code
   already written and merely unreachable — `apply_to` is persisted at
   `policy_engine.py:59` and never read; `license_compliance.evaluate` accepts
   a policy its only caller never passes (`tasks.py:760`);
   `GoogleChatNotifier.send_scan_report` is reachable only from a test endpoint
   (`routes_v2.py:1214`). Low risk, high recovery of stated capability.
3. **The severe items are small.** The three confidentiality exposures (AU-6,
   AU-8, AU-10) are concentrated in `auth.py:276-277`, one missing ownership
   assertion, and two route signatures. None is architecturally hard.
4. **Cost is dominated by decisions and test debt, not by build.** That is a
   correctable condition, not a reason to stop.

**The conditions, all of which must hold before the plan stage is scheduled:**

- **C1 — Answer OQ-11 and OQ-7 first.** They block the two highest-severity
  items (AU-8, AU-6). OQ-11 is not merely a build blocker: AU-8 and EX-3 are
  both Must and directly contradict each other on the same data, so the cycle
  cannot be *planned* until one changes. A plan built around blocked Musts
  slips in week one.
- **C2 — Answer OQ-5 (who consumes compliance output).** It is the single
  question that most changes the cycle's shape. If the answer is "audit
  evidence", SY-8 rises Should→Must, the hardcoded thresholds
  (`compliance.py:23`) must become configurable, and OQ-3 becomes a
  prerequisite rather than an input.
- **C4 — Treat WK-3 as out of cycle** (see §8) and decide it separately, since
  the only in-container fix reverses a deliberate security boundary.

C1, C2 and C4 are decisions answerable now, before a plan exists. The following
is different in kind — it is a mandate the plan stage must carry, not a gate
that can be satisfied beforehand:

- **M1 — The plan-stage estimate must include a characterization test harness
  as task zero.** 36 shipped Must stories carry a "must not regress" obligation
  against `routes_v2.py` (2,906 LOC, 97 endpoints, 7 exercised) and `tasks.py`
  (1,810 LOC, none), and every gap story lands in one of those two modules.
  That guarantee is currently close to unverifiable. This cannot be "funded
  before planning" — it is a line item the plan must not omit.

**Not blocking the GO, but ship out of band:** the first half of AU-10 —
rejecting unauthenticated WebSocket connections — needs no decision from
anyone, is a few lines, and closes a feed that currently requires no
credential at all. There is no reason for it to wait for a cycle boundary.

---

## 2. Technical feasibility

### 2.1 Change shape of the 24 gap/partial stories

| Shape | Count | Stories |
|---|---|---|
| Localized and independent | 4 | EN-4, SY-9 (app side done), RS-3, DB-2 |
| Cross-cutting, one decision then many call sites | 3 | AU-8 (27 handlers, enumerated below), SY-8 (~40 admin-gated routes), AU-10 |
| Blocked on an architectural decision | 17 (8 decision groups) | PG-5+VX-4+AC-2, SH-3+SH-4+SH-6, IA-4+PG-6+SC-10, WK-3+WK-4, AU-6+AU-9, SY-6+SY-7, LI-2, CO-3 |

4 + 3 + 17 = 24, reconciling against the MoSCoW table's 19 gap + 5 partial.

**The dominant constraint is file collision, not complexity.** 13 of the 24
stories edit `routes_v2.py` — AU-6, AU-8, AU-10, SY-8, PG-5, VX-4, AC-2, IA-4,
PG-6, LI-2, RS-3, CO-3, SH-6 (13), and SC-10 lands in `routes.py` +
`orchestrator.py` + `tasks.py` rather than `routes_v2.py`, so it does not
collide. One file, 2,906 LOC, 97 endpoints, no test
file. Either it is decomposed into domain routers first (ADR-8) or those 13
serialize. `tasks.py` is the second collision point (SH-4, SH-6, IA-4, SY-7,
and the SC-3 defect fix).

**AU-8's blast radius is 27 handlers, wider than stage 1 recorded.** The
requirements story names 9 `/api/v2` routes plus `routes.py:719`. The full set
of per-scan handlers taking `scan_id` with no ownership assertion is 22 in
`routes_v2.py` — `:858, :893, :987, :1021, :1053, :1103, :1137, :1233, :1254,
:1278, :1299, :1324, :1359, :1754, :1817, :1848, :2408, :2516, :2549, :2607,
:2809, :2851` (verified: each is a `scan_id`-keyed handler) — plus 5 in
`routes.py` (`:719, :748, :1012, :1032, :1063`), plus the static serves at
`main.py:138,143`. The stage-1 count of 9 understates the work; use 27.
`ownership.py` has no `can_view` helper today (`ownership.py:37-54` is
record/list only), so one must be added and threaded through all of them.

**PG-5, VX-4 and AC-2 are one story wearing three hats.** All three need
context that `check_scan_policies` never loads: it reads only
`VulnerabilityRepository.get_raw` at `routes_v2.py:2413`, so `image_name`
(PG-5), base OS (AC-2) and VEX suppressions (VX-4) are all absent from the
evaluation input. Each would change `policy_engine.evaluate_vulnerabilities`
(`policy_engine.py:300`), which also serves IaC evaluation (`:379`), batch
gating (`routes_v2.py:219`) and IaC-with-policy (`:2112`). Three builders
would invent three different context-passing schemes. One ADR, then one
builder.

### 2.2 Integration risks

1. **The regression guarantee is thin, though not absent. [verified —
   corrected]** Counting the routes actually exercised by `client.get/post`
   calls across `app/tests/*.py`: **7 of `routes_v2.py`'s 97 endpoints** are
   touched (`/api/v2/auth/status`, `/auth/verify`, `/auth/logout`, `/batches`,
   `/batches/{id}`, `/policies`, `/workers/status`) and 4 of `routes.py`'s 13
   (`/api-info`, `/history/{image}`, `/scans/recent`, `/stats`) — roughly
   **11 of 115 endpoints total**. An earlier draft of this document claimed
   "97 of 115 untested" and tagged it `[verified]`; that was wrong on both
   counts and is corrected here. The direction is unchanged — the large
   majority of endpoints have no test — but the specific figure was not
   verified when the tag was applied.
   `conftest.py:49-63` provides fakeredis only — no authenticated-client
   fixture, no `dependency_overrides` — so every new `routes_v2` test must
   hand-mint a JWT. This is the largest hidden cost in the cycle and nobody has
   budgeted it.

2. **One IaC scan can freeze the entire API. [verified]** `Dockerfile.api:59`
   runs `uvicorn` with no `--workers` — one process, one event loop.
   `iac_scan_content_endpoint` is `async def` (`routes_v2.py:2006`) and calls
   `task.get(timeout=60)` at `:2018`, a synchronous kombu drain executed on the
   event-loop thread. Same pattern at `:2055` (120 s), `:2092` (180 s), `:2128`
   (60 s). One large-repo IaC scan stalls every other HTTP request, both
   WebSocket pumps, and `/health` for up to three minutes. NFR-P5 records the
   worker-side effect but not this one. **IA-4 is therefore an availability
   fix, not just a storage story.**

3. **The Postgres read cutover moves blocking I/O onto that same loop.**
   `read_pg` is sync SQLAlchemy (`read_pg.py:15-32`), reached from `async def`
   handlers via `ScanRepository.get` (`scan_repository.py:31-36`). Flipping
   `READ_FROM_POSTGRES` today converts every scan read into a blocking DB call
   in the event loop. SY-6 cannot be "just a flag flip" until the read path is
   async or offloaded.

4. **Two silent dual-write bypasses, and they block the cutover sign-off.
   [verified]** `routes_v2.py:552` writes a scan hash with a raw `hset`,
   skipping `ScanRepository` and therefore skipping dual-write entirely; same
   at `tasks.py:1607` (the reaper) and `base_image_tracker.py:246,285`.
   `parity_check.py:46-47` counts each as `pg_missing`. SH-6 is therefore not only
   a tenancy fix — it closes a parity hole that will otherwise block the OQ-4
   cutover. Any new write path added by a gap story must go through a
   repository or it re-opens the same hole.

5. **Dual-write is cheap for fields, expensive for domains.**
   `dual_write.scan_row` stores the whole Redis hash verbatim as `detail`
   JSONB (`dual_write.py:79`), so a new scan *field* propagates with no
   migration. A new *domain* — IaC results (IA-4), license policy (LI-2), user
   accounts (AU-9) — has no table and costs five shared files each: model,
   Alembic revision, `dual_write` mapper, `read_pg` reader, `parity_check` arm.
   Those five files are shared across all three stories, so they serialize or
   the migration heads conflict.

6. **SC-10 has no interruption point.** `run_all_scans` sizes a
   ThreadPoolExecutor per invocation (`orchestrator.py:151-153`) and timeouts
   are deliberately never retried (`orchestrator.py:109-116`). A `Future`
   already inside a scanner subprocess cannot be cancelled through the
   executor. SC-10 needs a cooperative revoke plus a subprocess kill, not
   `future.cancel()`.

7. **AU-10 is a lifecycle rewrite, not a decorator.** FastAPI WebSockets cannot
   raise `HTTPException`. Two pre-existing bugs to fix in passing:
   `finally: await pubsub.disconnect()` (`routes_v2.py:1165`) raises
   `UnboundLocalError` if `manager.connect` throws, and each connection builds
   its own `RedisPubSubManager` (`:1152`, `:1174`) — one Redis connection per
   browser tab.

---

## 3. Operational feasibility

### 3.1 The config-only datastore swap is half true [verified]

The project records that bundled Postgres and Redis are temporary. For
Postgres the claim holds: `docker-compose.yml:29` wraps
`${DATABASE_URL:-...}`, and every DB path reads `settings.DATABASE_URL` with no
hardcoded host.

For Redis it does not. `docker-compose.yml:23` sets
`REDIS_URL: redis://redis:6379/0` as a **bare literal with no `${...}`
wrapper**, so it overrides anything set in `.env` — even though `config.py:17`
and `effective_redis_url` (`config.py:225-240`) fully support an external host,
password and TLS. Flower compounds it: `--broker=redis://redis:6379/0`
(`docker-compose.yml:326`) is hardcoded independently, so a Redis migration
silently leaves Flower pointed at an absent container.

Goal G10 in the requirements claims config-only for both. **Fix
`docker-compose.yml:23` and `:326` before the migration, or it is not a
config-only swap.** Bind mounts (`/opt/scanner-reports`, `/opt/scanner-sboms`,
`/opt/scanner-tmp`, the scanner caches) also assume one host with a shared
local filesystem; a multi-host topology needs a network filesystem, and nothing
in code anticipates that.

### 3.2 CI/CD can deliver the work; it does not gate on security

Pipeline is validate → build → test → scan → publish → deploy
(`.gitlab-ci.yml:24-30`). Deploy is scripted — `docker compose up -d --no-build`
plus `alembic upgrade head` and an nginx reload (`:264-271`) — but both publish
and deploy are `when: manual` on `main` (`:194`, `:229`), so a human clicks to
ship.

- **Test gate is real:** pytest is `allow_failure: false` (`:138`) and publish
  and deploy both need it. Its *coverage* is the problem, not its enforcement.
- **The image self-scan cannot block:** `allow_failure: true` (`:145`,
  "non-blocking until the Trivy DB mirror is confirmed on runners"). Harbor's
  own `auto_scan` is the only enforced scan gate and it is post-publish.
- **Rollback is re-run-based, not scripted.** Images are SHA-tagged (`:34`) and
  the deploy job prints "re-run deploy on the previous good pipeline" (`:281`).
  The health-check loop (`:272-280`) fails the job but does not revert.

### 3.3 Monitoring (SY-9): the config exists, the services do not

`prometheus.yml` targets `api:8000` (exists), `redis-exporter:9121` (absent)
and `nginx:80` (absent — the edge proxy service is named `edge`).
`grafana/provisioning/datasources/prometheus.yml:7` points at
`http://prometheus:9090`, which nothing serves.

Smallest credible path: a `docker-compose.monitoring.yml` overlay — same
pattern as the existing edge overlay — adding `prom/prometheus` on
`127.0.0.1:9090` mounting the existing root `prometheus.yml`, and
`grafana/grafana` on `127.0.0.1:3000` mounting the existing (already correct,
merely unconsumed) provisioning directory. Drop the two dead scrape jobs. No
new secrets; `ENABLE_METRICS=true` is already set (`docker-compose.yml:75`).
Cost ≈ +1 vCPU / +1.5 GB and a retention volume. **Blocked on spike S5:** if 6D
runs a central Prometheus that can scrape the host, this is another team's
change, not ours.

### 3.4 Credentials and access for the gap work

Only one gap story needs a posture change. **WK-3/WK-4 require raising
`docker-proxy`'s `POST` from `0` (`docker-compose.yml:271`)**, which is
precisely the boundary NFR-SEC7 closes. `IMAGES` and `EXEC` can stay `0`.
Everything else is additive and cheap: EN-4 needs two new env vars
(`KEV_FEED_URL`, `EPSS_FEED_URL`) and a route to an internal mirror; AC-2
reuses the existing `GITLAB_TOKEN`/`GITLAB_CA_CERT`; SH-4 reuses the
already-stored per-schedule `google_chat_webhook` (`scheduler.py:343`); AU-9
via Keycloak reuses the OIDC client secret already budgeted by the separate
Keycloak initiative. No gap story needs Docker socket write access on workers
or new registry credentials.

### 3.5 Declared footprint

Sum of declared compose limits ≈ **28.75 vCPU / 28.65 GB**, dominated by
`worker-high` ×3 (12 vCPU / 12 GB) and `worker-batch` ×2 (8 / 8). These are
declared ceilings, not measured usage — nothing here measures actual
consumption. **Two services declare no limits at all:** `scheduler`
(`docker-compose.yml:242-256`) and `dashboard` (`:441-455`), so NFR-S5's
"no container exceeds its limit" only checks the ten services that have one.
Gap work adds ≈ +1 vCPU / +1.5 GB for monitoring.

### 3.6 Operational risks specific to deploying this work

- Any new worker-side code (SH-3's `run_scheduled_scan`, WK-3 actuation) runs
  as **uid 0** with write access to the shared `/opt/scanner-tmp` bind mount
  (`worker-entrypoint.sh:54`). A defect there has host-filesystem blast radius.
- The shared `/tmp` exists *because* private per-worker scratch caused a
  228 GB / 46 h disk-fill (`docker-compose.yml:132-133`) and separately 81
  leaked directories / 63 GB (`tasks.py:1519-1520`). New worker tasks increase
  contention on the single hourly reaper. Do not reintroduce private `/tmp`.
- `pg-backup` dumps stay on the same host with no off-host copy and no restore
  test anywhere in the repo. SY-6/SY-7 increase reliance on Postgres as the
  durable record without fixing this.

---

## 4. Business feasibility

**All day-figures below are estimated from code inspection. No team velocity,
team size, or historical cycle-time data was available. Treat them as relative
sizing, not commitments.**

### 4.1 Cost drivers

| Group | Stories | Dominant driver | Band |
|---|---|---|---|
| A. Tenancy/authz | AU-6, AU-8, AU-10, SH-6 | **User decision, not code** | S–M, 4–9 d — unbounded until OQ-7 + OQ-11 |
| B. Wire existing code | SH-3, SH-4, PG-5, VX-4, AC-2, LI-2, EN-4, RS-3 | Engineer-days, low risk | M, 8–16 d |
| C. Data platform | SY-6, SY-7, SY-8, SY-9 | Infrastructure + coordination | M–L, 12–25 d |
| D. Autoscaler | WK-3, WK-4 | Security tradeoff + cross-team | M, 5–12 d + security review |
| E. New surface | PG-6, IA-4, CO-3, SC-10 | Design cost | L, 15–30 d |
| F. Regression safety | — | **Largest hidden driver; unbudgeted** | L, 15–30 d |

Groups A and D are not primarily engineer-day problems. Costing them as such
produces a plan that stalls.

### 4.2 Timeline

**One cycle cannot absorb 47 Must.** 11 of the 47 are not shipped; the other 36
are regression obligations against two untested modules. Sum of bands ≈
**60–120 estimated engineer-days** before any Should work.

Defensible cut, anchored on business risk rather than technical convenience:

- **In cycle (7 Must):** AU-6, AU-10, AU-8/EX-3, PG-5, VX-4, SY-7, SH-3.
- **Demote to Should:** SY-9 (ops-response cost, not exposure), SY-6 (no stated
  deadline; flag defaults false so nothing is at risk by waiting), WK-3 (no
  demand target exists — OQ-2), SH-4 (convenience once SH-3 fires).
- **Non-deferrable:** group F, interleaved with each fix rather than appended
  after.

### 4.3 Exposure if the severe gaps are not closed

**AU-6 — every API key is a cross-tenant administrator.** `create_api_key`
hardcodes `"role": "admin"` and `"created_by": ADMIN_USERNAME`
(`auth.py:276-277`), and `validate_api_key` returns that role verbatim
(`auth.py:330`). There is no scope, role or owner parameter on `APIKeyCreate`
(`auth.py:69-72`). Every key issued to every CI pipeline therefore satisfies
`get_current_admin`. Any pipeline holding a key can read every other team's
scans, purge worker queues, delete policies, create and revoke other keys, and
force database updates. Exposed: every team on the platform, to any single
team's CI system, and to anyone who can read a CI variable, a job log, or a
forked `.gitlab-ci.yml`. Keys default to 365-day expiry (`auth.py:72,285`), so
a key leaked today remains a full admin credential for a year. There is no way
to issue a read-only key.

**AU-8 — scan detail is not owner-checked.** `get_scan_result`
(`routes.py:719-733`) verifies authentication and nothing else; it never
compares `created_by` to the caller, unlike history (`routes.py:957`) or
batches (`routes_v2.py:180,228`). Nine `/api/v2` per-scan enrichment routes
share the omission. Any authenticated user who obtains a scan id gets the
complete vulnerability inventory, SBOM, dependency graph, AI triage and
compliance assessment for another team's image. Ids are UUIDv4, but they are
not secret — they appear in dashboard URLs, CI job output and report
filenames, and are streamed to anyone by the unauthenticated global WebSocket
below. This is the difference between tenancy and a list filter.

**AU-10 — WebSockets stream vulnerability data to anonymous clients.** Neither
route takes an auth dependency; both signatures are bare
(`routes_v2.py:1136-1140`, `:1168-1170`). `/api/v2/ws/global` pushes every
scan-completion payload to any client that can open a socket to the edge, with
no credential and no tenancy filter. Anyone with network reach to
`apexscanner.6dcorp.internal` obtains a live map of which images 6D is scanning
and what is wrong with them. Compounding factor: **the hole is invisible to the
obvious audit.** FastAPI omits `APIWebSocketRoute` from `openapi.json`, so an
OpenAPI-driven authentication sweep reports full coverage while both routes are
open. A control that reports "pass" while failing is worse than an absent one.

**PG-5** — the strict production policy fails every sandbox scan, so teams
route around a gate that fails everything. **VX-4** — a CVE formally triaged
`not_affected` still fails every subsequent release, so the entire shipped VEX
feature produces no business outcome. **SH-3/SH-4** — six schedule endpoints
persist records nothing consumes; anyone who created a schedule believes
recurring assessment is happening, and if a compliance control was ever
evidenced by "we scan nightly", that statement is currently false.

### 4.4 Regulatory — hinges entirely on OQ-5

Four frameworks are hardcoded with numeric thresholds (`compliance.py:23`).
Nothing records who set those numbers or who receives the output.

If compliance output is internal hygiene, the current state is acceptable. **If
it is audit evidence, three defects become material:** (1) the report and SBOM
files an auditor would be handed expire in 7 days (`config.py:148`), Postgres
is unbounded, and `volatile-lru` (`docker-compose.yml:357`) may evict scan data
before the 30-day Redis TTL; (2) the audit log has no read path at all — no
endpoint, no export, only direct SQL — writes are best-effort and swallowed at
debug level (`db/audit.py:34`), and coverage is 6 actions, excluding policy
*update*, schedule CRUD, VEX CRUD, risk-weight change, queue purge and cache
invalidation; (3) attribution is weak at the root — only two local identities
exist, so `created_by` and `audit_log.actor` may name a shared account rather
than a person, and every API key is attributed to the admin user.

**Escalation rule:** if OQ-5 returns "audit evidence", SY-8 rises Should→Must,
OQ-3 must be answered before SY-7 can be built, the hardcoded thresholds must
become configurable, and AU-9/OQ-6 becomes a compliance dependency.

### 4.5 Decision latency

Partitioning strictly the 11 not-shipped Must stories — SH-3, SH-4, PG-5, VX-4,
WK-3, AU-6, AU-8, AU-10, SY-6, SY-7, SY-9:

- **Blocked on a decision (5):** AU-6 (OQ-7), AU-8 (OQ-11), SY-6 (OQ-4), SY-7
  (OQ-3), SH-3/SH-4 (OQ-8 — whether these are defects or deliberate descoping
  changes their priority, not their buildability).
- **Proceeding regardless (5):** PG-5, VX-4, AU-10 (first criterion only —
  see below), WK-3 (buildable but recommended out of cycle, §8), SY-9 (blocked
  on spike S5, not on a user decision).

So **5 of the 11 not-shipped Musts are parked on five sentences from one
person**, and the parked set contains the two highest-severity items. EX-3 is
`Must | shipped` and is affected by OQ-11 only in that its acceptance criterion
may have to change — it is not idle work. The Should-priority stories (SH-6,
RS-3, EN-4, IA-4, LI-2, AC-2, SY-8) are all unblocked but are not part of the
Must accounting.

**Longest chain:** OQ-11 → AU-8's ownership rule → AU-10's second half; and
separately OQ-7 → AU-6 → interacts with OQ-6 → AU-9. Three sequential human
decisions gate the whole tenancy model. At a week each, tenancy work cannot
start for three weeks regardless of engineering capacity. That is the largest
schedule risk in the cycle and it costs nothing to remove.

**AU-10 splits usefully:** rejecting unauthenticated connections needs no
decision and kills the anonymous feed immediately. Only per-scan tenancy
filtering waits on OQ-11.

---

## 5. Risk register

Likelihood and impact are High/Medium/Low. Ordered by exposure.

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R1 | Anonymous WebSocket feed is discovered and used to map unpatched surface across the estate (`routes_v2.py:1136`, `:1168`) | High — no credential required, and any OpenAPI-driven audit reports it as covered | High | Ship AU-10 first criterion out of band, ahead of the cycle. Independently, stop relying on openapi-derived auth sweeps (NFR-SEC2 rewritten in stage 1) |
| R2 | A leaked CI key is used for cross-tenant admin access (`auth.py:276-277`) | Medium — requires a key to leak, but keys live 365 days in CI configs and job logs | High | AU-6 behind OQ-7; run spike S4 first to learn whether existing keys can simply be invalidated |
| R3 | A gap-story change silently regresses one of the 70 shipped behaviours | High — 97 of 115 endpoints untested, 14 stories land in one 2,906-LOC file | High | C3: characterization harness as task zero, interleaved per fix, not appended |
| R4 | An IaC scan of a large repo stalls the whole API for up to 3 minutes (`routes_v2.py:2018`, `Dockerfile.api:59`) | Medium — needs a large repo, but is a normal user action | High | Fold the availability fix into IA-4 via ADR-5 (submit+poll); interim mitigation is `--workers` >1 |
| R5 | Redis migration breaks because `REDIS_URL` is hardcoded in compose (`docker-compose.yml:23`, `:326`) | High if attempted as a config-only swap, as the requirements claim | Medium | Fix both lines now, before the migration is scheduled. One-line change each |
| R6 | Parallel builders conflict in `routes_v2.py` / `tasks.py`, or three of them invent three policy-context schemes | High without ADR-4 and ADR-8 | Medium | ADR-4 then one builder for PG-5+VX-4+AC-2; ADR-8 decides whether to split the file first |
| R7 | Postgres read cutover moves blocking I/O onto the single event loop (`read_pg.py:15-32`) | Medium — only if the flag is flipped before the read path is async | High | Spike S2 before any cutover; split SY-6 so the flag flip is next cycle |
| R8 | Compliance output turns out to be audit evidence and the retention/audit gaps become findings | Medium — unknown until OQ-5 | High | C2: answer OQ-5 before the plan stage. Escalation rule in §4.4 |
| R9 | New write paths added by gap stories bypass the repositories and widen the parity hole (`routes_v2.py:552`, `tasks.py:1607`) | Medium | Medium | Make "all writes go through a repository" a review gate; close the three existing bypasses with SH-6 |
| R10 | WK-3 is fixed by relaxing `docker-proxy POST` without scoped review, reversing NFR-SEC7 | Low if C4 holds; High if the story is handed to a builder as written | High | C4: keep WK-3 out of cycle; if taken, allow-list by compose label rather than a blanket `POST: 1` |
| R11 | Host disk fills again as new worker tasks increase scratch contention | Low — reaper and watchdog are in place — but precedent exists twice | High | Do not reintroduce private `/tmp`; verify the hourly reaper still covers any new scratch path |
| R12 | Postgres host loss with no tested restore (`docker-compose.yml:416-433`) | Low | High | Out of scope for this cycle, but SY-6/SY-7 raise the cost of the gap — flag to platform ops now |
| R13 | The concurrent HTTPS + Keycloak SSO initiative and this cycle both modify `auth.py`, the edge proxy and the OIDC/cookie path — the same surface ADR-9, AU-9, AU-10 and spike S1 depend on | High — both are active now | Medium | Assign single ownership of `auth.py` and the edge config for the duration, or define an explicit hand-off point. Run S1 jointly, since the cookie-on-WebSocket-upgrade question belongs to both |
| R14 | This document inherits stage-1's agent-derived `file:line` labels and priorities as fact. One error was already found in review (SC-10 attributed to `routes_v2.py`; it is not there), and the AU-8 handler count was understated by 17 | Medium — two errors found in one review pass | Medium | Spot-check the story list against source before stage 3 commits to it; treat any single stage-1 citation as provisional until re-verified at implementation time |
| R15 | Adding IaC results, license policy and user accounts as new domains in parallel produces conflicting Alembic heads — each needs a model, revision, `dual_write` mapper, `read_pg` reader and `parity_check` arm, and those five files are shared | Medium — only if IA-4, LI-2 and AU-9 are scheduled together | Medium | Serialize the migration-touching stories, or have one builder own all Alembic revisions in the cycle |

---

## 6. Spikes for the plan stage

All time-boxed. Only listed where reading the code cannot answer the question.

| # | Question | Method | Box |
|---|---|---|---|
| S1 | Does the edge proxy forward the HttpOnly auth cookie on the WebSocket `Upgrade`, and does it survive SameSite? Browsers cannot set headers on WS, so cookie-vs-ticket decides AU-10's whole design | Connect a browser and `websocat` through `apexscanner.6dcorp.internal` to `/api/v2/ws/global` with and without a cookie; inspect what reaches the app | 1 d |
| S2 | What does `parity_check` report against the **production** dataset, and what is `read_pg` latency at real row counts? | `docker exec -w /app fastapi_scanner python -m app.db.parity_check` on prod; time `read_scan_detail` over the real `scans` table | 2 d |
| S3 | Which WK-3 actuation option works without weakening NFR-SEC7 — proxy `POST:1` + Docker SDK, a host-side agent polling a Redis desired-replicas key, or Swarm/systemd? | Prototype each on the stage host; measure scale-up latency and resulting Docker API surface | 2 d |
| S4 | How many API keys exist in production, who holds them, and which routes do they call? Decides whether AU-6 is a breaking change or a no-op | Enumerate `api_keys:index` (`auth.py:294`) and `last_used` (`:326`) on prod Redis; cross-reference edge access logs by `X-API-Key` | 1 d |
| S5 | Does 6D operate a central Prometheus that can scrape this host, or must SY-9 ship Prometheus+Grafana in-compose? | Ask platform ops; if central, test one scrape through the edge | 0.5 d |

Total 6.5 days. Deliberately **not** spikes, because they are answerable by
reading source: VEX-into-policy composition, IaC storage shape, license-policy
storage, the cron-firing mechanism, dedup semantics.

---

## 7. ADRs required before development

| # | Decision | Blocks | Note |
|---|---|---|---|
| ADR-1 | Tenancy boundary for scan data (needs OQ-11) | AU-8, EX-3, SY-8 scope, DB-2 | Branch (b) "reports stay shared" makes AU-8 cosmetic — the same findings remain readable at `/reports/{scan_id}.html`. Do not spend a sprint on it under that branch |
| ADR-2 | API-key identity model (needs OQ-7, informed by S4) | AU-6, AU-8, PG-6 | If S4 shows only CI keys hitting scan routes, invalidate-and-reissue is simplest |
| ADR-3 | Scheduled-execution mechanism | SH-3, SH-4, SH-6 | A 1-minute beat tick that polls Redis and dispatches adds no dependency and needs no beat restart on schedule edit. Note the beat shelve at `/tmp/celerybeat-schedule` is in a container with no volumes — state must live in Redis regardless |
| ADR-4 | Policy-evaluation input contract | PG-5, VX-4, AC-2, BA-3, IA-3 | Without it, three builders patch `policy_engine.py:300` three ways |
| ADR-5 | Async contract for long operations | IA-4, PG-6, SC-10, R4 | Submit+poll fixes the event-loop stall *and* gives IA-4 its scan id |
| ADR-6 | Retention of record + Postgres purge (needs OQ-3) | SY-7, SY-6 phase 4 | `volatile-lru` means Redis and PG will disagree under any branch |
| ADR-7 | Autoscaler actuation and per-pool scaling (needs S3) | WK-3, WK-4, NFR-SEC7 | Closing WK-3 as won't-do is defensible under OQ-2 = current load |
| ADR-8 | Decompose `routes_v2.py` | Parallelization of 14 stories | Splitting only the touched domains (auth/tenancy, policy, iac) converts a 14-way serialization into ~4 disjoint file sets |
| ADR-9 | Identity source (needs OQ-6) | AU-9, DB-2, strength of `created_by` | SSO branch closes AU-9 by configuration and adds no tables |
| ADR-10 | Monitoring topology (needs S5) | SY-9 | |

---

## 8. Not feasible this cycle

- **WK-3 (Must, gap) — autoscaler actuation.** Three independent blockers
  (`autoscaler.py:186-191`, no volumes at `docker-compose.yml:290-315`,
  `POST: 0` at `:271`), and the only in-container fix weakens NFR-SEC7. Host
  infrastructure work, not application work. **Recommend demoting from Must**
  and deciding via ADR-7 + S3. Under OQ-2 = current load, closing it as
  won't-do is defensible.
- **SY-6 (Must, partial) — Postgres read cutover.** Not achievable as written:
  the read path is sync-on-the-event-loop, a partial PG dataset silently falls
  through to Redis rather than erroring, and no parity pass has ever been
  recorded. **Split the story** — an async read path plus a scheduled parity
  check plus a recorded pass is deliverable; the flag flip is next cycle.
- **SY-9 (Must, partial) — metrics collected.** App side is done. The remainder
  is deployment topology this repo cannot decide (S5). Feasible as an
  in-compose overlay; not feasible if the answer is "scrape from central",
  because that is another team's change.
- **AU-8 and EX-3 cannot both be Must.** They contradict each other on the same
  data. Not an architecture blocker — a scope contradiction that must be
  resolved before stage 3.

---

## 9. Open questions blocking this stage

Unchanged from stage 1 and still unanswered. **Four block Must work directly**
— OQ-11, OQ-7, OQ-3, OQ-4 — plus OQ-8, which determines whether SH-3/SH-4 are
defects or descoping. OQ-4 → SY-6 was missed in the stage-1 gate summary, which
stated four; the direct count is four but the membership differs. OQ-5 is
listed below as a fifth because of its escalation effect, but it is a
transitive blocker, not a direct one.

| OQ | Blocks | Effect if unanswered |
|---|---|---|
| **OQ-11** report tenancy | AU-8, EX-3 | Cycle cannot be *planned* — two Musts contradict |
| **OQ-7** API-key roles | AU-6 | Highest-exposure item stays open |
| **OQ-5** compliance consumers | SY-8 priority, OQ-3, threshold configurability | Resizes the cycle. **Transitive, not direct:** OQ-5 blocks no Must story by itself — it reaches Must work only by escalating SY-8 (Should→Must) and by making OQ-3 a prerequisite of SY-7. Counted here because that escalation changes the cycle's shape more than any direct blocker |
| **OQ-3** retention of record | SY-7 | Purge cannot be specified |
| **OQ-4** cutover deadline | SY-6 | Cannot tell if this cycle or next |

The remaining six — OQ-1 root workers, OQ-2 target scale, OQ-6 identity source,
OQ-8 schedules descoped or defective, OQ-9 compare/search admin-only, OQ-10
registry list — shape priorities but do not block Must work.
