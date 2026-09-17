# Apex Scanner — End-to-End Architecture Map

Generated from the Genesis code graph (`docs/sdlc/graph.json`, 119 files, 1152
symbols, 492 edges, 0 parse errors) plus AST extraction of route/task tables.
Every `file:line` below comes from the graph or from an AST parse of the named
file — nothing is from memory.

---

## 1. System topology (`app/docker-compose.yml`)

| Service | Role | Bind |
|---|---|---|
| `api` | FastAPI (uvicorn) — all HTTP + WebSocket | `127.0.0.1:7070` → 8000 |
| `worker-high` | Celery — `high_priority,default` | — |
| `worker-batch` | Celery — `batch,low_priority,default` | — |
| `worker-system` | Celery — `system` | — |
| `scheduler` | `celery beat` (`app.tasks.celery`) | — |
| `autoscaler` | `python -m app.autoscaler` — scales workers on queue depth | — |
| `docker-proxy` | `tecnativa/docker-socket-proxy` — brokers Docker socket to workers | — |
| `flower` | Celery UI | `127.0.0.1:5555` |
| `redis` | `redis:7-alpine` — authoritative store | — |
| `postgres` | `postgres:16-alpine` — migration target | — |
| `pg-backup` | periodic dump sidecar | — |
| `dashboard` | React build served by nginx | `127.0.0.1:3001` → 8080 |

Shared volume `/opt/scanner-reports:/var/www/html/reports` is mounted into
`api` and all three workers — workers write HTML reports/SBOMs, API serves them.

Everything binds to loopback; the FQDN edge proxy (`apexscanner.6dcorp.internal`)
terminates TLS in front.

---

## 2. Backend module inventory (`app/app/`, 19,121 LOC Python)

### Entry / transport
| Module | LOC | Purpose |
|---|---|---|
| `main.py` | 333 | FastAPI app, middleware, static report/SBOM mounts, health endpoints, startup/shutdown |
| `routes.py` | 1216 | `/api/v1` router — 13 endpoints (core scan/compare/search) |
| `routes_v2.py` | 2906 | `/api/v2` router — 97 endpoints (everything enterprise) |
| `websocket_manager.py` | 294 | Live scan-progress fan-out |

### Execution
| Module | LOC | Purpose |
|---|---|---|
| `tasks.py` | 1810 | Celery app, queue/route config, beat schedule, all scan tasks |
| `scanners/orchestrator.py` | 462 | Parallel scanner execution, retry, merge, dedup |
| `scanners/base.py` | 113 | `BaseScanner` ABC |
| `scanners/grype_scanner.py` | 222 | Grype |
| `scanners/trivy_scanner.py` | 217 | Trivy |
| `scanners/syft_scanner.py` | 264 | Syft SBOM |
| `scanners/normalization.py` | 23 | Shared output normalizers |
| `scanner_errors.py` | 136 | Raw scanner stderr → user-facing message |
| `iac_scanner.py` | 379 | Trivy misconfig (Dockerfile/K8s/TF/Helm) — worker-only |
| `autoscaler.py` | 352 | Queue-depth worker scaling |
| `worker_monitor.py` | 327 | Worker/queue introspection |
| `updater.py` | 635 | Vuln DB + scanner binary auto-update |
| `scheduler.py` | 488 | Cron scheduled scans + Google Chat notify |

### Analysis / enrichment
`enrichment.py` (592, EPSS + CISA KEV) · `cvss_enrichment.py` (395) ·
`risk_scoring.py` (636) · `remediation.py` (503) · `policy_engine.py` (529) ·
`compliance.py` (420, PCI-DSS/SOC2/HIPAA) · `dependency_analyzer.py` (463) ·
`license_compliance.py` (358) · `vex.py` (339, OpenVEX 0.2.0) ·
`trends.py` (385) · `ai_triage.py` (431) · `base_image_tracker.py` (356) ·
`gitlab_catalog.py` (143) · `export.py` (470, PDF/CSV)

### Auth / tenancy
`auth.py` (573) — JWT + API keys + bcrypt; `ownership.py` (54) — per-user scan
tagging and indexes; `oidc.py` (209) — Keycloak authorization-code BFF.

### Cross-cutting
`config.py` (304, Pydantic Settings) · `logging_config.py` (112, structlog) ·
`metrics.py` (230, Prometheus) · `time_utils.py` (34, tz-aware helpers)

### Data layer
| Module | LOC | Purpose |
|---|---|---|
| `repositories/scan_repository.py` | 230 | Scan reads/writes, Redis→PG switch |
| `repositories/batch_repository.py` | 115 | Batch domain |
| `repositories/vulnerability_repository.py` | 95 | Per-scan vuln lists |
| `repositories/license_repository.py` | 45 | Per-scan license JSON |
| `db/models.py` | 95 | ORM: `scans`, `vulnerabilities`, `batches`, `licenses`, `audit_log`, `kv_settings` |
| `db/dual_write.py` | 211 | Phase 2 — mirror Redis writes into PG (best-effort) |
| `db/read_pg.py` | 221 | Phase 3 — read back from PG (sync, best-effort) |
| `db/parity_check.py` | 153 | Phase 3/4 — Redis vs PG diff before read cutover |
| `db/backfill.py` | 75 | One-time idempotent Redis→PG backfill |
| `db/engine.py` / `db/sync_engine.py` | 70 / 47 | Async + sync SQLAlchemy engines |
| `db/audit.py` | 45 | Append-only who-did-what |

---

## 3. Coupling (measured)

Highest fan-in (internal importers):
`app.config` 38 · `app.logging_config` 27 · `app.time_utils` 13 ·
`app.db.dual_write` 5 · `app.trends` 4 · `app.db.read_pg` 4

Highest fan-out (distinct internal modules imported):
`routes_v2.py` 24 · `tasks.py` 17 · `routes.py` 8 · `main.py` 6

Graph `impact app/app/scanners/base.py` → `grype_scanner.py`,
`trivy_scanner.py`, `syft_scanner.py`, `scanners/__init__.py`. That is the
complete set of `BaseScanner` subclass sites.

Symbol density (graph): `routes_v2.py` 109 symbols, `api.js` 96,
`routes.py` 35, `enrichment.py` 29, `auth.py` 24.

---

## 4. HTTP surface — 115 endpoints

### `main.py` (unprefixed, 5)
```
GET  /reports/{filename:path}   serve_report      :138   (auth-gated)
GET  /sboms/{filename:path}     serve_sbom        :143   (auth-gated)
GET  /                          health_check      :152
GET  /health                    detailed_health   :190
GET  /health/scanners           scanner_health    :220
```
`main.py:147-148` mounts `router` then `router_v2`.

### `/api/v1` — `routes.py:330`, 13 endpoints
`POST /scan` `:451` · `POST /scan/batch` `:564` · `GET /scan/batch/{batch_id}` `:663` ·
`GET /scan/{scan_id}` `:719` · `GET /compare/{id1}/{id2}` `:748` ·
`GET /vulnerabilities/search` `:827` · `GET /history/{image_name:path}` `:933` ·
`GET /reports/{scan_id}` `:1012` · `GET /sbom/{scan_id}` `:1032` ·
`GET /sbom/{scan_id}/download/{format}` `:1063` · `GET /scans/recent` `:1087` ·
`GET /stats` `:1140` · `GET /api-info` `:1179`

### `/api/v2` — `routes_v2.py:42`, 97 endpoints, by domain
| Domain | Count | Range |
|---|---|---|
| Auth (login/logout/verify/status/config/OIDC) | 8 | `:54`–`:320` |
| Batches | 3 | `:131`–`:219` |
| Schedules | 6 | `:399`–`:510` |
| Base images | 8 | `:586`–`:823` |
| Scan enrichment (cvss/licenses) | 2 | `:858`–`:893` |
| Trends | 4 | `:915`–`:969` |
| Export (csv/sbom-csv/pdf/detailed-pdf) | 4 | `:987`–`:1103` |
| WebSocket (`/ws/scan/{id}`, `/ws/global`) | 2 | `:1137`, `:1169` |
| Dependency graph / remediation / risk | 9 | `:1233`–`:1405` |
| System (tool versions, db status, updates) | 6 | `:1428`–`:1520` |
| Workers (status/queues/autoscaler/purge) | 9 | `:1540`–`:1710` |
| Enrichment + KEV + EPSS | 9 | `:1754`–`:1925` |
| Cache | 2 | `:1948`–`:1959` |
| IaC scan (content/files/repo/with-policy) | 4 | `:2006`–`:2112` |
| Policies | 7 | `:2201`–`:2408` |
| API keys | 3 | `:2460`–`:2494` |
| AI triage | 3 | `:2516`–`:2581` |
| Compliance | 2 | `:2595`–`:2607` |
| VEX | 8 | `:2683`–`:2851` |
| Approved base images | 1 | `:2891` |

---

## 5. Async execution model (`tasks.py`)

### Queues (`tasks.py:92`)
`high_priority` (x-max-priority 10) · `default` (5) · `batch` (3) ·
`low_priority` (1) · `system`. Default queue: `default` (`:100`).

### Routing (`tasks.py:105`)
```
scan_image, scan_image_priority     -> high_priority
batch_scan_images                   -> batch
scan_base_images                    -> low_priority
update_vulnerability_databases      -> system
check_system_status                 -> system
update_kev_database                 -> system
cleanup_old_scan_artifacts          -> system
```

### Tasks (11)
`scan_image` · `batch_scan_images` · `scan_base_images` · `reap_stale_scans` ·
`check_system_status` · `cleanup_old_scan_artifacts` · `update_kev_database` ·
`update_vulnerability_databases` (in `updater.py`) · `scan_iac_content`
(`:1626`) · `scan_iac_files` · `scan_iac_repo` (`:1764`)

### Beat schedule (`tasks.py:1283`)
| Task | Interval | Queue |
|---|---|---|
| `scan_base_images` | 24 h | `low_priority` |
| `update_vulnerability_databases` | 3 h | `system` |
| `update_kev_database` | 6 h | `system` |
| `cleanup_old_scan_artifacts` | 1 h | `system` |
| `reap_stale_scans` | 10 min | `system` |

---

## 6. Scan pipeline, end to end

```
Browser  ScanPage.js -> startScan()  [api.js -> POST /api/v1/scan]
  |
  v  routes.py:451 start_scan — auth, mint scan_id, enqueue
Redis  <- Celery high_priority
  |
  v  tasks.py:604 scan_image(image_name, scan_id, skip_cache=True)
     1. get_redis_client()
     2. optional digest cache probe (check_digest_cache) — copies prior scan
        to the new scan_id, marks cache_hit, returns early
     3. ScannerOrchestrator()                       orchestrator.py:22
     4. run_all_scans()                             orchestrator.py:127
          ThreadPoolExecutor, one future per enabled scanner (:153)
          _run_with_retry per scanner (:71) — timeouts deliberately NOT
          retried (:109) so a retry can't outlive the task budget
          _collect (:232) -> merge_results (:247) -> _dedup_key (:331)
          -> _merge_both (:343) -> _deduplicate_vulnerabilities (:386)
          -> _calculate_severity_counts (:434) / _calculate_fixable_counts (:450)
     5. hard-fail guard: vuln scanners failed AND sbom_packages == 0 -> mark failed
     6. ScanRepository.save()   -> Redis hash (+ PG dual-write)
        VulnerabilityRepository.save_raw()
     7. enrichment (EPSS/KEV) then license compliance, then HTML report render
     8. WebSocket broadcast to /api/v2/ws/scan/{scan_id} and /ws/global
  |
  v  Browser ScanResults.js polls GET /api/v1/scan/{scan_id} + v2 enrichment calls
```

Scanner selection is flag-driven: `ENABLE_GRYPE` / `ENABLE_TRIVY` /
`ENABLE_SYFT` (`config.py:98,102,106`).

---

## 7. Data layer — Redis authoritative, Postgres shadow

Redis key namespaces in use: `vulns:` · `batch:` · `schedule:` ·
`api_keys:` / `api_key:` · `vex:` · `scan_dedup:` · `kev:` · `epss:` ·
`user_scans:` · `user_batches:` · `schedule_runs:` · `scanners_requested:`

Access path: **routes/tasks → repository → Redis (write) + `dual_write` (mirror
to PG)**. Reads go to Redis unless `READ_FROM_POSTGRES` (`config.py:31`) is set,
in which case `ScanRepository._pg()` (`scan_repository.py:21`) routes to
`read_pg.py`. Migration phases are labelled in the docstrings:

- Phase 0 — repository layer wrapping Redis verbatim ✅
- Phase 1 — PG schema (`db/models.py`) ✅
- Phase 2 — dual-write (`db/dual_write.py`) ✅
- Phase 3 — PG reads + `parity_check.py` behind `READ_FROM_POSTGRES`
- Phase 4 — audit log (`db/audit.py`)

Alembic migrations: `db/migrations/versions/1d68b1e53cac_baseline_schema.py`,
`3263093159e3_add_batches_detail.py`.

---

## 8. Auth

`auth.py` implements three parallel methods resolved by `get_current_user`
(`:377`), with `get_current_admin` (`:440`) and `get_optional_admin` (`:460`)
as the privilege gates:

1. **JWT** — `create_access_token` (`:215`) / `verify_token` (`:237`); cookie
   helpers `set_auth_cookie` (`:552`) / `clear_auth_cookie` (`:565`)
2. **API keys** — `create_api_key` (`:264`), `_hash_api_key` (`:259`),
   `validate_api_key` (`:307`), `revoke_api_key` (`:359`)
3. **Basic** — `authenticate_user` (`:144`), bcrypt

Brute-force control: `check_rate_limit` (`:178`), `record_failed_login`
(`:197`), `clear_login_attempts` (`:207`). Startup guard
`validate_credentials_or_die` (`:95`).

OIDC (`oidc.py`) runs the code exchange server-side (BFF), gated by
`OIDC_ENABLED` (`config.py:203`).

Per-user tenancy: `ownership.py` maintains `user_scans:` / `user_batches:`
indexes; non-admins see only their own, admins see all.

---

## 9. Frontend (`dashboard/src`)

`index.js` → `App.js` → `AuthContext` + `ThemeContext` → `ProtectedRoute` →
page. Routes (`App.js:76-145`): `/login` public; everything else guarded.

`/` Dashboard · `/scan` · `/scan/:scanId` · `/batch` · `/batches` ·
`/batches/:batchId` · `/history` · `/iac-scan` · `/approved-base-images` ·
`/compare` · `/search` · `/trends` · `/policies` · `/schedules` ·
`/base-images` · `/base-images/:imageName/:tag` · `/compliance` ·
`/dependency-graph` · `/vex` · `/workers` · `/system`

`api.js` (96 symbols, 95 exports) is the single HTTP boundary: two axios
instances, `api` → `${API_BASE_URL}/api/v1` (`:28`) and `apiV2` →
`${API_BASE_URL}/api/v2` (`:36`), both carrying the same request/`on401Response`
interceptors (`:57-61`). No page may create its own instance.

Page → API binding:

| Page | api.js functions |
|---|---|
| Dashboard | `getStats`, `getRecentScans` |
| ScanPage | `startScan` |
| ScanResults | `getScanResult`, `getDependencyGraph`, `getRemediationPlan`, `getQuickWins`, `getRiskScore`, `exportCsv`, `exportExecutivePdf`, `getEnrichedVulnerabilities`, `getKevMatches`, … |
| Batches / BatchDetail / BatchScan | `getBatches`, `getBatchDetail`, `getBatchPolicyCheck`, `startBatchScan`, `getPolicies` |
| History | `getImageHistory`, `getRecentScans` |
| Compare | `compareScans` |
| Search | `searchVulnerabilities` |
| Trends | `getGlobalTrends`, `getTopVulnerable`, `getVulnDistribution`, `getImageTrends` |
| BaseImages / BaseImageDetail | `getBaseImages`, `registerBaseImage`, `compareBaseImages`, `scanAllBaseImages`, `deleteBaseImage`, `updateBaseImage`, `getBaseImageDetails`, `getBaseImageHistory` |
| ApprovedBaseImages | `getApprovedBaseImages` |
| Schedules | `getSchedules`, `createSchedule`, `deleteSchedule`, `runScheduleNow`, `testNotification` |
| Compliance | `getComplianceFrameworks`, `getComplianceAssessment` |
| DependencyGraph | `getDependencyGraph`, `getPackageImpact` |
| VexManagement | `listVexStatements`, `createVexStatement`, `updateVexStatement`, `deleteVexStatement`, `importVexDocument` |
| WorkerMonitor | `getWorkersStatus`, `getQueueStats`, `getAutoscalerStatus`, `getScalingHistory`, `pingWorkers`, `purgeQueue`, `getWorkersHealth` |
| SystemStatus | `getToolVersions`, `getDbStatus`, `triggerDbUpdate`, `refreshSystemStatus`, `getUpdateHistory`, `getSystemNotifications` |
| Login | `getAuthConfig`, `getSsoLoginUrl` |
| IacScan, Policies | raw `apiV2` |

Shared components: `Navbar`, `Sidebar`, `PageHeader`, `SortableTable`,
`SeverityChip`, `VulnerabilityChart`, `AITriagePanel`, `LoadingSkeletons`,
`Motion`, `AuroraBackground`, `ApexLogo`, `Feedback`, `ProtectedRoute`.
Severity colors resolve through `theme/tokens.js` only.

---

## 10. Tests (`app/tests/`, 18 files)

`test_api.py` · `test_auth.py` · `test_batches_api.py` · `test_scanners.py` ·
`test_enrichment.py` · `test_policy_engine.py` · `test_ownership.py` /
`test_ownership_api.py` · `test_report_auth.py` · `test_iac_security.py` ·
`test_scratch_cleanup.py` · `test_scan_result_failed.py` ·
`test_dual_write_mappers.py` · repository tests ×4 (scan/batch/vuln/license) ·
`conftest.py`

Concentration: `test_enrichment.py` 49 symbols, `test_policy_engine.py` 44,
`test_scanners.py` 44, `test_auth.py` 30, `test_api.py` 29. The heaviest
production modules — `routes_v2.py` (2906 LOC, 97 endpoints) and `tasks.py`
(1810 LOC) — have no dedicated test file.

---

## Graph coverage caveats

These are real limits of the v1 code graph, not gaps in the code:

- `imports app/app/tasks.py` returns **no imports found** — the graph resolves
  only *relative* Python imports, and `tasks.py` imports with absolute
  `app.*` paths. 188 such imports are recorded as `unresolvedImports`. The
  Python import figures in §3 come from a separate AST pass, not the graph.
- `calls` edges are same-file and plain-name only. `self.foo()` / `obj.foo()`
  never resolve, so the scan-pipeline call chain in §6 is read from source,
  not from graph edges.
- Route tables, Celery task names, beat schedule, compose services, and React
  routes are AST/grep extractions — the graph indexes symbols, not decorators.
- `dual_write_scan` returns `no data` — no such symbol. The dual-write entry
  points are `upsert_scan` / `upsert_batch` / `upsert_license` / `upsert_vulns`.
