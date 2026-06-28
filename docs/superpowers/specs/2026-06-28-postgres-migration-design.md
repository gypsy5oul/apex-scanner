# Postgres Datastore Migration — Design

**Date:** 2026-06-28
**Status:** Design for review → phased plan to follow
**Decision:** Bundle a Postgres container in the stack (self-hosted on this host).

## Problem

Redis is currently the *only* datastore (scan records, vulnerabilities, batches,
policies, schedules, VEX, base-images, API keys — all as Redis
hashes/lists/zsets). Consequences: no durable audit trail or retention
guarantee (compliance blocker), eviction can silently drop data, no SQL for
tenancy/reporting, and Redis is a coupled SPOF (broker **and** datastore).

## Goal

Make **Postgres the system of record** for durable data; demote **Redis to
broker + hot cache**. Incremental, dual-write migration — no big-bang cutover,
no downtime, reversible at each phase.

## Data Split (from the live key inventory)

**→ Postgres (durable system of record):**
- Scan records (`<scan_id>` hashes), per-scan vulnerabilities (`vulns:<id>`),
  per-scan license results (`licenses:<id>`), per-scan enrichment summary.
- Batches (`batch:<id>`), image history (derive via `WHERE image_name=`).
- Trends (`image_trend:`, `trend:` — or recompute from scans).
- Policies, schedules, VEX statements, base-image catalog, API keys.
- Small singletons: `tool_versions`, `last_updates`, `update_history`, `notifications`.
- **NEW: `audit_log`** (who did what — policy/schedule/api-key/admin actions).

**→ Redis (ephemeral, unchanged):**
- Celery broker + result backend (`_kombu.*`, `celery-task-meta-*`).
- Enrichment caches (`epss:`, `kev:`, `enrichment:`, `digest_cache:`) — TTL'd, regenerable.
- `cve_index:` (10k keys) → **replaced by a SQL query** (`WHERE cve_id=`), removed from Redis.
- `scan_dedup:` (SET NX lock), rate-limit counters, `progress:` (WebSocket pub/sub),
  `worker:health:`, `autoscaler:`, per-user indexes (`user_scans`/`user_batches` →
  become SQL `WHERE created_by=` + index).

## Infrastructure (bundled)

`docker-compose.yml` gains a `postgres` service:
- Image `postgres:16-alpine` (digest-pinned), named volume `pg-data`.
- Env from gitignored `app/.env`: `POSTGRES_USER/PASSWORD/DB`, app `DATABASE_URL`.
- `healthcheck: pg_isready`; API/workers gain `depends_on: postgres: service_healthy`.
- Bound to `127.0.0.1` (like Redis); resource limits + log rotation matching the others.
- **Backups:** a daily `pg_dump` (cron or a small sidecar) to a separate volume/path,
  retained N days. (HA/replication is a later phase; out of scope for v1.)

App layer:
- `SQLAlchemy 2.x` (async) + `asyncpg` driver; `Alembic` for migrations.
- New `app/db/` package: `engine.py` (async engine/session), `models.py`
  (SQLAlchemy models), `migrations/` (Alembic).
- Config: `DATABASE_URL` in `config.py` (`postgresql+asyncpg://…`).

## Schema (first cut)

Hybrid: typed columns for what we query/filter; `JSONB` for the long tail.

- **`scans`** — `id (uuid pk)`, `image_name`, `status`, `created_by`, `created_at`,
  `scan_timestamp`, severity counts (`critical/high/medium/low/...`),
  `total_packages`, `report_url`, `sbom_report_url`, `scan_quality`,
  `kev_matches`, `high_risk_vulns`, `image_digest`, `batch_id (fk null)`,
  `detail JSONB` (scanner metadata, base-image info, etc.). Indexes:
  `(created_by)`, `(image_name)`, `(scan_timestamp desc)`, `(status)`.
- **`vulnerabilities`** — `id pk`, `scan_id fk`, `cve_id`, `severity`,
  `package_name`, `package_version`, `cvss_score`, `epss_score`, `in_kev`,
  `fix_available`, `risk_priority`, `data JSONB` (full record). Indexes:
  `(scan_id)`, `(cve_id)`, `(severity)`. **Replaces `cve_index:`** via
  `SELECT scan_id FROM vulnerabilities WHERE cve_id=?`.
- **`batches`** — `id pk`, `created_by`, `created_at`, `total_images`,
  `status`, `image_list JSONB`. (Scans link via `scans.batch_id`.)
- **`licenses`** — `scan_id fk`, `status`, counts, `data JSONB`.
- **`policies`**, **`schedules`**, **`vex_statements`**, **`base_images`** —
  typed key columns + `JSONB` body.
- **`api_keys`** — `key_hash pk`, `name`, `created_by`, `role`, `created_at`, `expires_at`.
- **`audit_log`** — `id pk`, `ts`, `actor (username)`, `action`, `target`,
  `detail JSONB`, `ip`. (Append-only.)
- **`kv_settings`** — `key pk`, `value JSONB` for `tool_versions`/`last_updates`/etc.

## Repository / Service Layer (Phase 0 — the prerequisite)

Today Redis keys are read/written ad-hoc across `routes.py`, `routes_v2.py`,
`tasks.py`. **Before any DB work**, encapsulate data access behind repositories
so storage is swappable in one place:
- `app/repositories/` — `ScanRepository`, `VulnerabilityRepository`,
  `BatchRepository`, `PolicyRepository`, `ScheduleRepository`,
  `VexRepository`, `BaseImageRepository`, `ApiKeyRepository`, `AuditRepository`.
- Each exposes typed methods (`get_scan(id)`, `list_scans(owner, limit)`,
  `record_scan(...)`, `search_by_cve(cve)`, …) and **initially wraps the
  existing Redis calls** — no behavior change, fully covered by the existing
  tests. Routes/tasks call repositories instead of `redis_client.*`.

This is independently valuable (kills the "god-file" data-access sprawl the
architecture review flagged) and is the seam the migration plugs into.

## Phased Rollout (each phase ships independently, reversible)

- **Phase 0 — Repositories** wrap current Redis access. No DB yet. *(~1 week, low risk.)*
- **Phase 1 — Stand up Postgres** (compose service, `app/db/`, models, Alembic
  baseline). App boots with an idle DB connection. No reads/writes yet.
- **Phase 2 — Dual-write + backfill.** Repository write methods write to **both**
  Redis and Postgres. A one-time `backfill_to_postgres` script copies existing
  Redis data. Reads still from Redis. Validate parity under real traffic.
- **Phase 3 — Flip reads to Postgres**, repository by repository (scans → vulns →
  batches → policies/schedules/vex/base-images/api-keys), verifying parity each step.
- **Phase 4 — Stop durable writes to Redis.** Redis keeps only broker + caches +
  ephemeral locks. Remove `cve_index:` (now a SQL query). Add the **audit log**
  and SQL-backed retention. Per-user tenancy becomes a `WHERE created_by=` clause.
- **Phase 5 — Backups + (later) HA.** Daily `pg_dump`, tested restore runbook.
  PG replication is a future enhancement.

## Migration / Backfill

- `backfill_to_postgres` (idempotent): SCAN each Redis namespace, upsert into PG.
  Run during Phase 2; re-runnable. Ownerless/legacy scans backfill with
  `created_by=NULL` (admin-visible, matching current tenancy behaviour).
- Celery result backend: stays on Redis (or moves to PG later — not required).

## Risks & Mitigations

- **Dual-write divergence** → repositories own both writes in one method; a
  parity-check script samples Redis vs PG during Phase 2.
- **Schema churn** → Alembic migrations; JSONB columns absorb shape changes
  without migrations for the long-tail fields.
- **Performance** → indexed key columns for hot filters; JSONB GIN index only
  if needed.
- **Rollback** → until Phase 4, Redis remains authoritative; flip reads back at
  any point. Phase 4 is the point of no return — gated on a parity sign-off.

## Non-Goals (v1)

- PG high-availability / replication (Phase 5+).
- Moving the Celery broker off Redis.
- Re-architecting enrichment caches (they stay in Redis by design).

## Effort

~3–4 weeks for Phases 0–4. Phase 0 (repositories) is ~1 week and independently
valuable even if the rest is deferred.
