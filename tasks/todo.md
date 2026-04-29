# Apex Scanner v3.0 — Comprehensive Architecture Review & Enhancement Plan

**Date:** 2026-03-03
**Reviewer:** Senior Python Developer / Security Architect
**Scope:** Full codebase audit — architecture, security, Python engineering, DevSecOps, SBOM, scalability

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Architecture Review](#2-architecture-review)
3. [Security & DevSecOps Assessment](#3-security--devsecops-assessment)
4. [Python Engineering Review](#4-python-engineering-review)
5. [Vulnerability Intelligence & Accuracy](#5-vulnerability-intelligence--accuracy)
6. [SBOM Strategy & Compliance](#6-sbom-strategy--compliance)
7. [Scalability & Performance](#7-scalability--performance)
8. [Frontend Assessment](#8-frontend-assessment)
9. [Infrastructure & Deployment](#9-infrastructure--deployment)
10. [New Feature Recommendations](#10-new-feature-recommendations)
11. [Prioritized Action Items](#11-prioritized-action-items)

---

## 1. Executive Summary

**Overall Assessment: B+ (Strong foundation, needs hardening for enterprise)**

Apex Scanner is a well-conceived multi-scanner vulnerability detection platform with thoughtful architecture choices. The codebase demonstrates a clear understanding of container security fundamentals — multi-scanner correlation, EPSS/KEV enrichment, digest-based caching, and SBOM multi-format support are all excellent decisions.

**What's Done Well:**
- Multi-scanner orchestration with deduplication and confidence scoring
- Security-first startup validation (refuses insecure defaults)
- EPSS + CISA KEV enrichment pipeline
- Structured JSON logging with contextual metadata
- Prometheus metrics integration
- Digest-based scan caching to avoid redundant work
- API versioning (v1/v2) for backward compatibility
- Flexible auth: JWT + API Keys + Basic Auth (CI/CD friendly)
- Redis-as-primary-store is a bold but valid choice for this use case

**Critical Gaps:**
- All core containers run as root (highest-priority fix)
- No test suite exists (zero automated tests)
- No database for durable state (Redis-only is a risk at enterprise scale)
- Docker socket mounted to workers = container breakout risk
- No scanner binary integrity verification (supply chain risk)
- Frontend stores JWT in localStorage (XSS vulnerability)
- No CI/CD pipeline defined
- `datetime.utcnow()` used throughout (deprecated in Python 3.12+)

---

## 2. Architecture Review

### 2.1 Current Architecture (Text Diagram)

```
                    ┌──────────────┐
                    │   Dashboard  │
                    │  (React/MUI) │
                    │   :3001      │
                    └──────┬───────┘
                           │ HTTP
                    ┌──────┴───────┐
                    │    NGINX     │
                    │  (Rate Limit)│
                    └──────┬───────┘
                           │
                    ┌──────┴───────┐
                    │  FastAPI API │
                    │   :7070      │
                    └──────┬───────┘
                           │ Celery Tasks
              ┌────────────┼────────────┐
              │            │            │
        ┌─────┴────┐ ┌────┴─────┐ ┌────┴─────┐
        │ Worker   │ │ Worker   │ │ Worker   │
        │ (High)   │ │ (Batch)  │ │ (System) │
        │ Grype    │ │ Grype    │ │ DB Update│
        │ Trivy    │ │ Trivy    │ │ Cleanup  │
        │ Syft     │ │ Syft     │ │          │
        └─────┬────┘ └────┬─────┘ └────┬─────┘
              │            │            │
              └────────────┼────────────┘
                           │
                    ┌──────┴───────┐
                    │    Redis     │
                    │  (Broker +   │
                    │   Results +  │
                    │   Cache)     │
                    └──────────────┘
```

### 2.2 Architectural Strengths

**S1. Multi-Scanner Correlation** — Running Grype and Trivy in parallel with deduplication by `{CVE}:{package}` key is textbook vulnerability management. The confidence scoring (high for both, medium for single) provides actionable triage guidance.

**S2. Redis as Hub** — Using Redis for task broker, result cache, and data store reduces operational complexity. For small-to-medium deployments, this is the right tradeoff. The LRU eviction with 30-day TTL prevents unbounded growth.

**S3. Queue Prioritization** — Separate queues (`high_priority`, `default`, `batch`, `low_priority`, `system`) with dedicated workers is a mature pattern that prevents batch jobs from starving interactive scans.

**S4. Stateless API Design** — The API server itself is stateless (all state in Redis), which means horizontal scaling of the API layer is trivial.

### 2.3 Architectural Concerns

**C1. Redis as Sole Data Store (MEDIUM-HIGH RISK)**
- Redis LRU eviction can silently drop scan results under memory pressure
- `allkeys-lru` policy means ANY key can be evicted, including active scan results
- No data durability guarantee beyond AOF/RDB snapshots
- **Recommendation:** For enterprise, add PostgreSQL for durable scan history and policy storage. Keep Redis for cache/broker only. Short-term: switch to `volatile-lru` eviction policy (only evicts keys with TTL set).

**C2. No API Gateway / Service Mesh (LOW RISK now, HIGH at scale)**
- NGINX handles rate limiting, but there's no circuit breaking, request tracing, or service discovery
- **Recommendation:** At enterprise scale, consider Envoy/Istio sidecar or API gateway (Kong, APISIX)

**C3. Tight Coupling Between API and Task Definitions**
- `routes.py` and `routes_v2.py` are 43KB and 67KB respectively — monolithic route files
- Business logic is mixed into route handlers
- **Recommendation:** Extract service layer (e.g., `services/scan_service.py`, `services/policy_service.py`). Routes should only handle HTTP concerns.

**C4. No Event-Driven Architecture for Cross-Cutting Concerns**
- Enrichment, report generation, notifications happen inline in the scan task
- **Recommendation:** Use Celery chains or signals for post-scan pipeline: `scan → enrich → score → report → notify`

---

## 3. Security & DevSecOps Assessment

### 3.1 CRITICAL Findings (Fix Immediately)

**SEC-01: All Core Containers Run as Root**
- `Dockerfile.api` and `Dockerfile.worker` have no `USER` directive
- Scanner binaries (Grype, Trivy, Syft) execute as root
- Celery workers process untrusted image content as root
- **Impact:** Container escape vulnerability. A compromised scanner process has full host access via Docker socket
- **Fix:** Add non-root user to Dockerfiles:
  ```dockerfile
  RUN groupadd -r scanner && useradd -r -g scanner -d /home/scanner scanner
  USER scanner
  ```
  Adjust file permissions for reports/sboms directories accordingly.

**SEC-02: Docker Socket Mounted to Workers**
- `/var/run/docker.sock` is mounted to all workers
- Combined with root execution, this is effectively `--privileged`
- A vulnerability in any scanner binary gives full Docker API access
- **Impact:** Complete host compromise
- **Fix Options (ordered by preference):**
  1. Use image export via `docker save` in a sidecar, pass tar to workers (no socket needed)
  2. Use Docker credential helper + `skopeo` for registry-only access
  3. At minimum, use Docker socket proxy (tecnativa/docker-socket-proxy) to restrict API calls to image inspection only

**SEC-03: Scanner Binary Supply Chain Risk**
- `Dockerfile.worker` downloads Grype, Trivy, Syft from GitHub with `curl` — no checksum verification
- If GitHub releases are compromised or MITM'd, malicious binaries enter the pipeline
- **Impact:** Supply chain compromise of all scanned images
- **Fix:**
  ```dockerfile
  # Add checksum verification
  RUN curl -sSfL ... -o grype.tar.gz \
      && echo "EXPECTED_SHA256  grype.tar.gz" | sha256sum -c - \
      && tar -xzf grype.tar.gz
  ```
  Also consider: cosign signature verification for Anchore/Aqua releases

**SEC-04: JWT Token in localStorage (Frontend)**
- `AuthContext.js` stores JWT in `localStorage.setItem('auth_token', token)`
- localStorage is accessible to any JavaScript running on the page
- **Impact:** XSS attack → complete account takeover
- **Fix:** Use `httpOnly` + `Secure` + `SameSite=Strict` cookies for token storage. Add CSRF token.

### 3.2 HIGH Findings

**SEC-05: `datetime.utcnow()` Usage (Deprecated)**
- Used in `auth.py:212,218,261,312,316`, `enrichment.py`, and throughout
- `datetime.utcnow()` is deprecated in Python 3.12+ and returns naive datetime (no timezone info)
- Can cause token expiration bugs in environments with timezone offsets
- **Fix:** Replace all with `datetime.now(timezone.utc)`

**SEC-06: No Request Signing / HMAC for Webhook Notifications**
- `scheduler.py` sends scan results to Google Chat/Slack webhooks
- No HMAC signature or verification on outgoing webhooks
- **Impact:** Webhook URL leak = attacker can spoof notifications
- **Fix:** Add HMAC-SHA256 signing with configurable secret

**SEC-07: CORS Allows Credentials with Explicit Origins**
- CORS is configured with `allow_credentials=True`
- Combined with explicit origin list, this is acceptable but needs audit
- Ensure no wildcard origins creep in (currently prevented)

**SEC-08: Rate Limiting Bypass via X-Forwarded-For**
- `check_rate_limit()` uses `request.client.host`
- Behind NGINX, this could be the proxy IP, not the real client
- **Fix:** Use `X-Real-IP` header from NGINX (already configured in proxy_set_header) via a trusted proxy middleware

**SEC-09: No Content Security Policy (CSP) Headers**
- Neither NGINX config nor FastAPI sets CSP headers
- **Fix:** Add to NGINX:
  ```
  add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';" always;
  add_header X-Content-Type-Options "nosniff" always;
  add_header X-Frame-Options "DENY" always;
  add_header Referrer-Policy "strict-origin-when-cross-origin" always;
  ```

### 3.3 MEDIUM Findings

**SEC-10: API Key Revocation is O(N) Linear Scan**
- `revoke_api_key()` iterates ALL key hashes in `api_keys:index` to find matching key_id
- At scale (thousands of keys), this is slow and blocks Redis
- **Fix:** Maintain a reverse index: `api_key_id:{key_id} → key_hash`

**SEC-11: No Audit Logging**
- Authentication events are logged, but no structured audit trail for:
  - Policy changes
  - Schedule modifications
  - API key creation/revocation
  - Admin actions
- **Fix:** Add audit event emitter with structured fields (who, what, when, result)

**SEC-12: Sensitive Data in Error Responses**
- Some exception handlers return `str(e)` which may leak internal paths or stack traces
- **Fix:** Sanitize all 5xx error responses, log full details server-side

**SEC-13: No Input Validation on Image Names**
- `BaseScanner.validate_image_name()` exists but is not consistently enforced
- Specially crafted image names could trigger command injection in scanner subprocesses
- **Fix:** Validate at API entry point before task submission. Use allowlist regex.

---

## 4. Python Engineering Review

### 4.1 Code Quality

**Overall: B (Good patterns, needs refactoring for scale)**

**Strengths:**
- Pydantic v2 for settings and request validation
- Structured logging with structlog
- Type hints used consistently
- Clean scanner abstraction (BaseScanner → GrypeScanner, TrivyScanner, SyftScanner)
- Thread-safe parallel execution with ThreadPoolExecutor

**Issues:**

**PY-01: Monolithic Route Files**
- `routes.py` is 43KB (~1200 lines), `routes_v2.py` is 67KB (~1800 lines)
- Business logic mixed with HTTP handling
- **Fix:** Extract into service layer:
  ```
  app/services/
  ├── scan_service.py
  ├── enrichment_service.py
  ├── policy_service.py
  ├── export_service.py
  └── schedule_service.py
  ```

**PY-02: No Test Suite**
- Zero automated tests in the entire codebase
- No `tests/` directory, no `pytest.ini`, no `conftest.py`
- **This is the single biggest risk for long-term maintainability**
- **Fix (phased):**
  1. Phase 1: Unit tests for scanner parsers (pure functions, easy to test)
  2. Phase 2: Integration tests for auth module
  3. Phase 3: API endpoint tests with FastAPI TestClient
  4. Phase 4: End-to-end scan workflow tests

**PY-03: No Dependency Injection**
- Redis client obtained via `get_redis_client()` global function
- Makes unit testing hard (can't mock Redis)
- **Fix:** Use FastAPI's dependency injection:
  ```python
  async def get_redis(request: Request) -> redis.Redis:
      return request.app.state.redis
  ```

**PY-04: Inconsistent Logging**
- `orchestrator.py` uses `logging.getLogger(__name__)` (stdlib)
- Rest of app uses `structlog` via `get_logger(__name__)`
- **Fix:** Standardize on structlog everywhere

**PY-05: No `__all__` Exports**
- Modules don't define `__all__`, making public API unclear
- Minor but matters for large codebases

**PY-06: `time.sleep()` in Async Context**
- `_run_with_retry()` uses `time.sleep(_RETRY_DELAY_SECONDS)` — blocks the thread
- Acceptable in ThreadPoolExecutor context but not ideal
- **Fix:** If moving to async workers, use `asyncio.sleep()`

### 4.2 Design Pattern Recommendations

**Pattern 1: Repository Pattern for Data Access**
```python
class ScanRepository:
    def __init__(self, redis: redis.Redis):
        self.redis = redis

    def save(self, scan_id: str, result: dict, ttl: int) -> None: ...
    def get(self, scan_id: str) -> Optional[dict]: ...
    def get_recent(self, limit: int = 20) -> List[str]: ...
    def get_history(self, image: str) -> List[str]: ...
```
This abstracts Redis and makes it trivial to swap in PostgreSQL later.

**Pattern 2: Strategy Pattern for Scanner Selection**
- Already partially implemented via `BaseScanner`
- Could be extended to support runtime scanner selection per scan request

**Pattern 3: Pipeline Pattern for Post-Scan Processing**
```python
# Instead of monolithic scan_image task:
pipeline = chain(
    scan_image.s(image_name, scan_id),
    enrich_vulnerabilities.s(),
    calculate_risk_scores.s(),
    generate_report.s(),
    notify_subscribers.s(),
)
```

---

## 5. Vulnerability Intelligence & Accuracy

### 5.1 What's Done Well

- **EPSS Integration** — Using FIRST.org EPSS API for exploit probability is excellent. 24hr cache is appropriate.
- **CISA KEV Integration** — Cross-referencing with Known Exploited Vulnerabilities catalog provides immediate actionability.
- **Multi-Scanner Deduplication** — `{CVE}:{package_name}` key prevents double-counting.
- **Confidence Scoring** — "both_scanners" = high confidence is a good signal.

### 5.2 Accuracy Concerns

**VUL-01: Deduplication Key Doesn't Account for Version**
- Key is `{CVE}:{package_name}` but ignores `package_version`
- If the same CVE affects `openssl 1.1.1` and `openssl 3.0.2` in different layers, they'll be merged
- **Fix:** Use `{CVE}:{package_name}:{package_version}` as dedup key

**VUL-02: No False Positive Suppression**
- No mechanism for users to mark vulnerabilities as false positive or accepted risk
- Critical for enterprise workflows where security teams triage findings
- **Fix:** Add vulnerability suppression/exception API:
  ```
  POST /api/v2/suppressions
  {
    "cve_id": "CVE-2024-1234",
    "package_name": "openssl",
    "reason": "Not exploitable in our configuration",
    "expires_at": "2026-06-01",
    "approved_by": "security-team"
  }
  ```

**VUL-03: No VEX (Vulnerability Exploitability eXchange) Support**
- VEX is becoming the standard for communicating vulnerability status
- **Fix:** Support VEX document import/export (OpenVEX format)

**VUL-04: CVSS Score Source Inconsistency**
- Grype and Trivy may report different CVSS scores for the same CVE
- Current merge takes Grype's score when both scanners find the same CVE
- **Fix:** Take the highest CVSS score, or better: prefer NVD authoritative score

**VUL-05: No Reachability Analysis**
- Vulnerabilities are reported even if the affected code path is never executed
- This is the #1 source of false positives in container scanning
- **Fix (advanced):** Integrate with tools like Endor Labs or Semgrep for call-graph analysis. Short-term: add a "reachable" field defaulting to "unknown"

### 5.3 Enrichment Improvements

- **NVD API v2 Integration** — Add NVD API as a secondary CVSS source (you have `cvss_enrichment.py` but it could be more robust)
- **Exploit-DB / Metasploit Cross-Reference** — Flag CVEs with known public exploits
- **Package EOL Tracking** — Flag packages past end-of-life (e.g., Python 2.x, Node.js 16.x)

---

## 6. SBOM Strategy & Compliance

### 6.1 Current State

- **Formats:** SPDX-JSON, CycloneDX-JSON, Syft-JSON (good coverage)
- **Generator:** Syft (Anchore) — solid choice
- **Storage:** File-based in `/var/www/html/sboms/`
- **Statistics:** Package counts, types, licenses extracted

### 6.2 Gaps & Recommendations

**SBOM-01: No SBOM Lifecycle Management**
- SBOMs are generated and stored but not tracked across image versions
- No diff between SBOM versions (what packages were added/removed)
- **Fix:** Add SBOM diff endpoint:
  ```
  POST /api/v2/sbom/diff
  { "scan_id_old": "...", "scan_id_new": "..." }
  ```

**SBOM-02: No SBOM Attestation**
- SBOMs lack cryptographic attestation (who generated it, when, integrity)
- Required for NIST SSDF and EO 14028 compliance
- **Fix:** Sign SBOMs using in-toto attestation format with cosign

**SBOM-03: No SBOM Ingestion**
- System can only generate SBOMs, not consume them
- Enterprise users may want to upload pre-existing SBOMs for vulnerability scanning
- **Fix:** Add `POST /api/v2/sbom/upload` that scans a provided SBOM against vulnerability databases

**SBOM-04: No License Compliance Engine**
- Unique licenses are extracted but not evaluated
- No policy for "block copyleft licenses in production" or similar
- **Fix:** Add license policy rules to the policy engine:
  ```json
  {
    "field": "license",
    "operator": "not_in",
    "value": ["GPL-2.0", "GPL-3.0", "AGPL-3.0"],
    "action": "fail"
  }
  ```

**SBOM-05: SBOM Format Compliance Validation**
- No validation that generated SBOMs conform to their respective specs
- **Fix:** Validate SPDX output against the SPDX schema, CycloneDX against CycloneDX schema

**SBOM-06: Align with NTIA Minimum Elements**
- Verify all SBOMs include: supplier, component name, version, unique identifier, dependency relationship, author, timestamp
- These are the NTIA "minimum elements" required for federal procurement

---

## 7. Scalability & Performance

### 7.1 Current Capacity

Based on the architecture:
- **Single worker:** ~8 concurrent scans (high-priority) or ~12 (batch)
- **Default deployment:** ~32 concurrent scans across all workers
- **Max scaling:** 10 batch workers × 12 concurrency = 120 concurrent scans
- **Bottleneck:** Redis memory (2GB default), scanner binary I/O

### 7.2 Scaling Concerns

**SCALE-01: Redis Memory Ceiling**
- With `allkeys-lru` eviction and 2GB max, scan results can be evicted under load
- Each scan result is ~50-500KB depending on vulnerability count
- 2GB ≈ 4,000-40,000 cached results
- **Fix:** Add PostgreSQL for persistent storage, use Redis only for hot cache

**SCALE-02: Scanner Binary Contention**
- Grype and Trivy share filesystem databases within each container
- Under high concurrency, database reads may contend
- Trivy's `per-scan cache symlink` (trivy_scanner.py) is a good workaround
- **Fix:** Pre-load databases into tmpfs (RAM disk) for faster access

**SCALE-03: No Horizontal Partitioning**
- All scan results go to a single Redis instance
- **Fix:** Redis Cluster or Redis Sentinel for HA. Alternatively, partition by scan_id prefix.

**SCALE-04: Synchronous Report Generation**
- HTML/PDF report generation happens within the scan task
- For large scans (1000+ vulnerabilities), report generation can take 5-10 seconds
- **Fix:** Offload report generation to a separate Celery task

**SCALE-05: No Connection Pooling for External APIs**
- EPSS and KEV enrichment use httpx/requests without connection pooling
- **Fix:** Use `httpx.AsyncClient` with connection pool for all external API calls

### 7.3 Performance Recommendations

1. **Scan Deduplication at Submission** — Before creating a Celery task, check if the same image:tag is already being scanned. Return the existing scan_id.
2. **Result Streaming** — For batch scans of 50 images, stream results via WebSocket instead of polling.
3. **Database Index Optimization** — If moving to PostgreSQL, ensure indexes on `image_name`, `scan_date`, `severity`.
4. **Image Layer Caching** — Cache layer-level results, reuse for images sharing base layers.

---

## 8. Frontend Assessment

### 8.1 Architecture

**React 18 + Material-UI v5 + Context API** — appropriate for this dashboard.

### 8.2 Issues

**FE-01: No TypeScript** — Large dashboard with 28 JS files has no type safety. Bugs will increase as complexity grows.

**FE-02: ScanResults.js is 56.8KB** — Single component file with all result display logic. Split into sub-components.

**FE-03: No Frontend Tests** — No test files, no testing libraries in package.json.

**FE-04: Two Chart Libraries** — Both `chart.js` (react-chartjs-2) and `recharts` are used. Pick one.

**FE-05: Polling Instead of WebSocket** — Most pages use `setInterval` for polling. WebSocket infrastructure exists but isn't leveraged for dashboard updates.

**FE-06: No Error Boundaries** — A crash in any component brings down the entire app.

**FE-07: No Loading Skeletons** — Flash of empty content before data loads.

**FE-08: `@mui/x-data-grid` Installed but Not Used** — Dead dependency.

---

## 9. Infrastructure & Deployment

### 9.1 Docker Issues

**INFRA-01: No Multi-Stage Build for Worker**
- `Dockerfile.worker` uses `python:3.9` (full image, ~900MB)
- No separation of build dependencies from runtime
- **Fix:** Use multi-stage build, install scanners in build stage, copy binaries to slim runtime

**INFRA-02: Python 3.9 is EOL (October 2025)**
- Python 3.9 reached end-of-life
- No security patches will be issued
- **Fix:** Upgrade to Python 3.12+ (current stable)

**INFRA-03: No `.dockerignore`**
- Missing in `/opt/new-grype-scanner-v1/app/`
- `__pycache__`, `.env`, `.git` may be included in build context
- **Fix:** Add `.dockerignore` with standard Python exclusions

**INFRA-04: Hardcoded IP in Health Check Script**
- `check-scanner-health.sh` has `http://10.0.2.121:7070/` hardcoded
- **Fix:** Use environment variable or Docker service name

**INFRA-05: No CI/CD Pipeline**
- No GitHub Actions, GitLab CI, or Jenkins pipeline
- No automated testing, linting, or security scanning of the scanner itself
- **Fix:** Add `.github/workflows/ci.yml` with:
  - Linting (ruff/flake8)
  - Type checking (mypy)
  - Unit tests (pytest)
  - Docker build verification
  - Trivy scan of own Docker images (scan the scanner!)

**INFRA-06: Timezone Hardcoded**
- `TZ: Asia/Kolkata` is hardcoded in docker-compose.yml
- **Fix:** Make configurable via environment variable

**INFRA-07: No Kubernetes Manifests**
- Docs reference Kubernetes but no manifests exist
- **Fix:** Add Helm chart or Kustomize manifests for K8s deployment

---

## 10. New Feature Recommendations

### 10.1 High Priority (Enterprise Must-Haves)

**FEAT-01: Vulnerability Exception/Suppression Management**
- Allow security teams to accept risk, defer, or mark false positives
- Track exceptions with expiry dates and approval workflows
- Required for any enterprise vulnerability management program

**FEAT-02: Integration with Ticketing Systems**
- JIRA, ServiceNow, GitHub Issues integration
- Auto-create tickets for Critical/High vulnerabilities
- Track remediation status

**FEAT-03: Compliance Reporting Dashboard**
- Map vulnerabilities to compliance frameworks (PCI-DSS, SOC2, HIPAA, FedRAMP)
- Show compliance posture over time
- Generate compliance-ready reports

**FEAT-04: Registry Scanning (Continuous Monitoring)**
- Continuously scan images in Docker registries (Harbor, ECR, GCR, ACR)
- Auto-discover new images and tags
- Alert on new vulnerabilities in previously scanned images

**FEAT-05: Notification Channels**
- Currently only Google Chat webhooks
- Add: Slack, Microsoft Teams, PagerDuty, email (SMTP), generic webhook
- Configurable notification rules (e.g., "only Critical", "only KEV matches")

### 10.2 Medium Priority (Competitive Differentiators)

**FEAT-06: AI/ML-Assisted Vulnerability Triage**
- Use LLM to summarize remediation steps for non-security engineers
- Auto-classify vulnerability exploitability based on image context
- Generate natural-language risk summaries for executive reports
- This is a genuine differentiator in 2026

**FEAT-07: Runtime Security Integration**
- Correlate scan-time vulnerabilities with runtime behavior (Falco, Sysdig)
- Show "this vulnerability is actually being exercised in production"
- Bridge the gap between static scanning and runtime truth

**FEAT-08: Policy-as-Code (OPA/Rego)**
- Current policy engine is custom-built
- Add OPA (Open Policy Agent) integration for standard policy-as-code
- Enterprises already have OPA policies — leverage existing investments

**FEAT-09: Image Signing & Verification Gate**
- Integrate with Sigstore/cosign to verify image signatures
- Block scanning of unsigned images
- Sign scan results as attestations

**FEAT-10: Dependency Graph Visualization**
- Build interactive dependency tree from SBOM
- Show which packages introduce which vulnerabilities
- Identify "most dangerous dependency" hotspots

### 10.3 Lower Priority (Nice-to-Haves)

**FEAT-11: Custom Scanner Plugin System**
- Allow users to add custom scanners beyond Grype/Trivy/Syft
- Plugin interface with standard input/output format

**FEAT-12: Multi-Tenant Support**
- Team/organization isolation
- Per-team policies, scan quotas, and API keys

**FEAT-13: Vulnerability SLA Tracking**
- Define SLAs (e.g., "Critical must be remediated within 7 days")
- Track SLA compliance per team/image
- Dashboard showing overdue vulnerabilities

**FEAT-14: Dockerfile Best Practice Scanning**
- Extend IaC scanning to check Dockerfile best practices
- Detect: running as root, using :latest, unnecessary packages, etc.
- Score Dockerfiles for security posture

**FEAT-15: GitOps Integration**
- Watch Git repositories for image reference changes
- Auto-trigger scans when deployments change
- Comment scan results on pull requests

---

## 11. Prioritized Action Items

### Phase 0: Critical Security (Week 1-2)
- [ ] SEC-01: Add non-root users to all Dockerfiles
- [ ] SEC-02: Remove Docker socket from workers (use socket proxy)
- [ ] SEC-03: Add checksum verification for scanner binary downloads
- [ ] SEC-04: Move JWT from localStorage to httpOnly cookies
- [ ] INFRA-02: Upgrade Python 3.9 → 3.12

### Phase 1: Foundation (Week 3-4)
- [ ] PY-02: Add pytest framework + first 20 unit tests (scanner parsers + auth)
- [ ] INFRA-05: Add CI/CD pipeline (GitHub Actions)
- [ ] PY-01: Extract service layer from routes (scan_service, policy_service)
- [ ] SEC-05: Replace all `datetime.utcnow()` with `datetime.now(timezone.utc)`
- [ ] INFRA-03: Add `.dockerignore` files
- [ ] SEC-09: Add security headers to NGINX

### Phase 2: Data Durability (Week 5-8)
- [ ] C1: Add PostgreSQL for persistent scan history + policy storage
- [ ] PY-03: Implement dependency injection for Redis/DB
- [ ] SCALE-01: Configure Redis volatile-lru (only evict TTL keys)
- [ ] VUL-01: Fix deduplication key to include package version
- [ ] VUL-02: Implement vulnerability suppression/exception API

### Phase 3: Enterprise Features (Week 9-16)
- [ ] FEAT-01: Vulnerability exception management
- [ ] FEAT-02: JIRA/ticketing integration
- [ ] FEAT-04: Registry continuous scanning
- [ ] FEAT-05: Multi-channel notifications (Slack, Teams, email)
- [ ] SBOM-01: SBOM diff and lifecycle tracking
- [ ] SBOM-04: License compliance engine
- [ ] SEC-11: Structured audit logging

### Phase 4: Advanced Intelligence (Week 17+)
- [ ] FEAT-06: AI/ML-assisted vulnerability triage
- [ ] FEAT-07: Runtime security correlation
- [ ] FEAT-08: OPA/Rego policy-as-code
- [ ] VUL-03: VEX support
- [ ] FEAT-09: Cosign image signature verification
- [ ] FEAT-10: Dependency graph visualization
- [ ] FEAT-13: SLA tracking

---

## Review Section

### Architecture Score Card

| Category | Score | Notes |
|----------|-------|-------|
| Security Posture | C+ | Root containers, Docker socket exposure |
| Code Quality | B | Good patterns, no tests |
| Scalability | B+ | Well-designed queues, Redis ceiling |
| Feature Completeness | A- | Impressive for v3.0 |
| Operational Maturity | B- | No CI/CD, no tests, good monitoring |
| Documentation | B+ | Good docs, missing API schema |
| SBOM Compliance | B | Multi-format, missing attestation |
| Vulnerability Intelligence | A- | EPSS+KEV is ahead of many tools |

### Key Architectural Decisions to Make

1. **PostgreSQL vs Redis-only** — When to introduce SQL persistence
2. **Docker socket elimination** — Architectural approach for image access
3. **TypeScript migration** — Whether to invest in frontend type safety
4. **Kubernetes-first** — Whether to optimize for K8s deployment
5. **Multi-tenancy** — Whether the product needs tenant isolation

---

*End of review. Recommendations are prioritized by risk × effort × value. Start with Phase 0 (security hardening) — everything else builds on a secure foundation.*
