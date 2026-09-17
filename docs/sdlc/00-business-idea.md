# 00 — Business Idea

**Project:** Apex Scanner
**Version at init:** 3.0 (`app/app/main.py:29`)
**Date:** 2026-08-01
**Requested by:** vishnu.raveendran (vishnu.prakash@6dtech.co.in)
**Mode:** Brownfield — the system is already built, deployed, and in use. SDLC
is being adopted retroactively over a running codebase, not to build from zero.

## The idea

Apex Scanner is an enterprise-grade container security scanning platform:
"Peak Vulnerability Detection." Teams point it at a container image (or a
batch of images, an IaC repo, or a scheduled base-image set) and get a
correlated, enriched, policy-checked vulnerability verdict rather than raw
scanner output.

It runs multiple scan engines in parallel — Grype and Trivy for
vulnerabilities, Syft for SBOM — then deduplicates and merges their findings
into one result set. On top of that merged set it layers threat intelligence
(CISA KEV, EPSS exploit-prediction), CVSS v3.1 exploitability detail, a
weighted custom risk score, AI-assisted triage, remediation plans and quick
wins, license compliance, dependency-path analysis, compliance-framework
mapping (PCI-DSS, SOC2, HIPAA), and OpenVEX exploitability statements.

Results reach users through a React dashboard (21 routes), a 115-endpoint
REST API across `/api/v1` and `/api/v2`, live WebSocket scan progress, and
HTML/PDF/CSV reports. Policy gates let a scan pass or fail on defined severity
thresholds so the platform can act as a CI/CD security gate, not just a report
generator.

Two capabilities the README advertises are **not** wired up in the shipped
code, verified during stage 1 and corrected here:

- **Cron schedules do not fire.** `scheduler.get_celery_beat_schedule()`
  (`scheduler.py:464`) has no callers anywhere in `app/`; `tasks.py:1283`
  installs a static beat schedule instead. The six `/api/v2/schedules`
  endpoints persist records that nothing consumes. The generated entries also
  target a task named `run_scheduled_scan` that is never defined.
- **Scheduled scans send no Google Chat notification.**
  `GoogleChatNotifier.send_scan_report` (`scheduler.py:26`) is reachable only
  from `POST /api/v2/test-notification` (`routes_v2.py:1214`). No
  scan-completion path calls it; the per-schedule `google_chat_webhook` field
  is stored and never read.

Whether these were descoped deliberately or are defects is open question OQ-8
in `01-requirements.md`.

## Why it exists

Single-scanner output is noisy, inconsistent between engines, and gives no
sense of which findings actually matter. Apex Scanner's premise is that
correlation across engines plus exploit-likelihood enrichment plus
organizational policy is what turns a CVE list into a decision.

## Current state at init

- ~19,100 LOC Python backend (FastAPI + Celery), React/MUI frontend
- 12-service Docker Compose deployment, all ports loopback-bound behind a
  TLS edge proxy at `apexscanner.6dcorp.internal`
- Redis is the authoritative datastore; a phased Postgres migration is in
  flight (phases 0–2 complete, 3–4 behind the `READ_FROM_POSTGRES` flag)
- 18 test files; GitLab CI pipeline (validate → build → test → scan → publish)
- Full structural map: `docs/sdlc/architecture-map.md`

## Known constraints carried into the SDLC

- Bundled Postgres and the current Redis are temporary — a centralized
  Postgres and a production Redis cluster are planned, so `DATABASE_URL` and
  `REDIS_URL` must stay env-driven and the swap must be config-only.
- Containers currently run as root; the Docker socket is brokered to workers
  via `docker-socket-proxy`.
- The two heaviest modules, `routes_v2.py` (2,906 LOC, 97 endpoints) and
  `tasks.py` (1,810 LOC), have no dedicated test file.
