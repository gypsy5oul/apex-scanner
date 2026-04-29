# Apex Scanner

<div align="center">

<!-- Logo/Banner -->
<img src="https://img.shields.io/badge/▲-APEX%20SCANNER-blue?style=for-the-badge&labelColor=1a1a2e&color=4361ee" alt="Apex Scanner" height="60"/>

<br/>
<br/>

<h3>Peak Vulnerability Detection</h3>

<p>Enterprise-grade container security scanning platform with multi-engine correlation, threat intelligence, AI-assisted triage, compliance reporting, and OpenVEX support.</p>

<br/>

[![License](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat-square&logo=docker&logoColor=white)](docker-compose.yml)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react&logoColor=white)](https://reactjs.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![UBI 9](https://img.shields.io/badge/Base-UBI%209-EE0000?style=flat-square&logo=redhat&logoColor=white)](https://catalog.redhat.com/software/base-images)

<br/>

[Features](#-features) • [Quick Start](#-quick-start) • [API](#-api-documentation) • [Configuration](#-configuration) • [Contributing](#-contributing)

</div>

<br/>

---

<br/>

## ✨ Features

<table>
<tr>
<td width="50%">

### 🔍 Multi-Engine Scanning
- **Grype + Trivy + Syft** running in parallel
- **Cross-validation** between Grype and Trivy
- **Confidence scoring** based on detection overlap
- **Secret detection** via Trivy
- **SBOM generation** in SPDX, CycloneDX, and Syft JSON
- **SBOM deduplication** by name:version:type

</td>
<td width="50%">

### 🎯 Threat Intelligence
- **EPSS scoring** — exploit probability predictions
- **CISA KEV integration** — known exploited vulnerabilities
- **Risk prioritization** — high-risk vulnerabilities surfaced first
- **AI-assisted triage** via Claude API (optional)
- **Auto-updated** vulnerability databases

</td>
</tr>
<tr>
<td width="50%">

### 📋 Compliance & VEX
- **OpenVEX v0.2.0** — full CRUD, import/export
- **Vulnerability suppression** with justifications
- **PCI-DSS 4.0** controls
- **SOC 2 Type II** controls
- **HIPAA Security Rule** controls
- **FedRAMP (Moderate)** controls

</td>
<td width="50%">

### 🛠️ Actionable Remediation
- **Quick Wins** — maximum impact with minimum effort
- **Auto-generated fix scripts** (yum, apt, npm, pip…)
- **Dependency graph** visualization
- **Base image recommendations**
- **Per-package remediation guidance**

</td>
</tr>
<tr>
<td width="50%">

### 🏢 Enterprise Ready
- **Multi-method auth** — JWT, API keys, Basic Auth
- **RBAC** — admin & user roles
- **Real-time dashboard** with WebSocket updates
- **Scheduled scans** via Celery Beat
- **Batch scanning** with prioritized worker queues
- **HTML, PDF, CSV reports**

</td>
<td width="50%">

### ⚡ Performance
- **Digest-based caching** — avoid redundant scans
- **Single-pass SBOM** generation
- **Parallel scanner execution** with retry
- **Auto-updating Grype DB** on stale detection
- **Tiered worker queues** — high/default/batch/low/system
- **Horizontal worker scaling** via Docker Compose

</td>
</tr>
</table>

<br/>

---

<br/>

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- 4 GB RAM minimum (8 GB recommended)
- 20 GB disk space (scanner DBs + image layers)

### Installation

```bash
# Clone the repository
git clone https://github.com/gypsy5oul/apex-scanner.git
cd apex-scanner

# Generate an admin password hash
python -c "import bcrypt; print(bcrypt.hashpw(b'YourStrongPassword', bcrypt.gensalt()).decode())"

# Copy environment template and fill in ADMIN_PASSWORD_HASH and JWT_SECRET_KEY
cp .env.example .env
$EDITOR .env

# Start all services
cd app
docker-compose up -d

# Wait for services to initialize (services pre-download Grype/Trivy DBs at build time)
```

### Access Points

| Service | URL | Description |
|:--------|:----|:------------|
| 🖥️ **Dashboard** | http://localhost:3001 | React web interface |
| 📚 **API Docs** | http://localhost:7070/docs | Swagger UI |
| 🔌 **REST API v1** | http://localhost:7070/api/v1 | Core scan endpoints |
| 🔌 **REST API v2** | http://localhost:7070/api/v2 | AI Triage, Compliance, VEX, etc. |
| 📊 **Metrics** | http://localhost:7070/metrics | Prometheus exporter |
| 🌸 **Flower** | http://localhost:5555 | Celery worker monitoring |

### Authentication

Apex Scanner enforces authentication on all endpoints. **Default plaintext passwords are rejected at startup** — you must provide a bcrypt hash via `ADMIN_PASSWORD_HASH`.

Three auth methods are supported:

```bash
# 1. JWT Bearer token (after login)
curl -X POST http://localhost:7070/api/v1/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"YourPassword"}'

# 2. API Key (recommended for CI/CD)
# Generate via /api/v1/api-keys (admin only) or programmatically
curl -H "X-API-Key: apex_..." http://localhost:7070/api/v1/scans

# 3. HTTP Basic Auth
curl -u admin:YourPassword http://localhost:7070/api/v1/scans
```

<br/>

---

<br/>

## 🏗️ Architecture

```
                              ┌─────────────────┐
                              │   Dashboard     │
                              │   (React 18)    │
                              └────────┬────────┘
                                       │
                                       ▼
┌──────────────┐             ┌─────────────────┐             ┌──────────────────┐
│   Clients    │────────────▶│    FastAPI      │────────────▶│  Celery Workers  │
│  (API/Web)   │◀────────────│   (Python 3.12) │◀────────────│  high · default  │
└──────────────┘             └────────┬────────┘             │  batch · low     │
                                      │                      │  system          │
                            ┌─────────┼──────────┐           └──────┬───────────┘
                            ▼         ▼          ▼                  │
                      ┌─────────┐ ┌────────┐ ┌──────────┐           ▼
                      │  Redis  │ │Reports │ │  SBOMs   │     ┌──────────────┐
                      │  Cache  │ │Storage │ │ Storage  │     │  Scanners    │
                      └─────────┘ └────────┘ └──────────┘     │  Grype 0.110 │
                                                              │  Trivy 0.69  │
                                                              │  Syft  1.42  │
                                                              │  Skopeo 1.20 │
                                                              └──────┬───────┘
                                                                     │
   ┌───────────┬──────────────┬────────────┬──────────────┬─────────┼───────────┐
   ▼           ▼              ▼            ▼              ▼         ▼           ▼
┌──────┐ ┌─────────┐ ┌─────────────┐ ┌──────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐
│ EPSS │ │  KEV    │ │ Digest      │ │  AI      │ │ OpenVEX │ │Compliance│ │ Celery  │
│Scores│ │Database │ │ Cache       │ │ Triage   │ │  Store  │ │ Engine   │ │  Beat   │
└──────┘ └─────────┘ └─────────────┘ └──────────┘ └─────────┘ └──────────┘ └─────────┘
                                       (Claude)                                (Cron)
```

**Scanner stack:** Grype `0.110.0`, Trivy `0.69.3`, Syft `1.42.3`, Skopeo `1.20.0`
**Runtime:** Red Hat UBI 9 minimal (multi-stage build, non-root)

<br/>

---

<br/>

## 📖 API Documentation

> All endpoints require authentication. Examples use `X-API-Key` for brevity.

### Trigger a Scan

```bash
curl -X POST "http://localhost:7070/api/v1/scan" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: apex_..." \
  -d '{"image_name": "registry.example.com/myapp:v1.0"}'
```

**Response:**
```json
{
  "scan_id": "abc123-...",
  "status": "in_progress",
  "message": "Multi-scanner analysis initiated successfully"
}
```

### Get Scan Results

```bash
curl -H "X-API-Key: apex_..." \
  "http://localhost:7070/api/v1/scan/{scan_id}"
```

### Threat Intelligence (v2)

```bash
# KEV-matched (actively exploited) vulnerabilities
curl -H "X-API-Key: apex_..." \
  "http://localhost:7070/api/v2/scan/{scan_id}/kev-matches"

# Quick wins remediation
curl -H "X-API-Key: apex_..." \
  "http://localhost:7070/api/v2/scan/{scan_id}/quick-wins"

# EPSS-enriched results
curl -H "X-API-Key: apex_..." \
  "http://localhost:7070/api/v2/scan/{scan_id}/enriched"
```

### AI-Assisted Triage

```bash
# Check if AI Triage is enabled (requires ANTHROPIC_API_KEY)
curl -H "X-API-Key: apex_..." \
  "http://localhost:7070/api/v2/ai-triage/status"

# Get AI risk classification + executive summary for a scan
curl -H "X-API-Key: apex_..." \
  "http://localhost:7070/api/v2/scan/{scan_id}/ai-triage"

# Get AI-generated remediation guide
curl -H "X-API-Key: apex_..." \
  "http://localhost:7070/api/v2/scan/{scan_id}/ai-remediation"
```

### Compliance Reporting

```bash
# List supported frameworks (PCI-DSS 4.0, SOC2, HIPAA, FedRAMP)
curl -H "X-API-Key: apex_..." \
  "http://localhost:7070/api/v2/compliance/frameworks"

# Evaluate a scan against all frameworks
curl -H "X-API-Key: apex_..." \
  "http://localhost:7070/api/v2/scan/{scan_id}/compliance"
```

### VEX (OpenVEX) Statements

```bash
# List all VEX statements
curl -H "X-API-Key: apex_..." \
  "http://localhost:7070/api/v2/vex/statements"

# Create a "not_affected" VEX statement
curl -X POST -H "X-API-Key: apex_..." \
  -H "Content-Type: application/json" \
  -d '{
    "vulnerability_id": "CVE-2024-12345",
    "product_id": "pkg:npm/example@1.0.0",
    "status": "not_affected",
    "justification": "vulnerable_code_not_in_execute_path"
  }' \
  "http://localhost:7070/api/v2/vex/statements"

# Export OpenVEX document for a scan
curl -H "X-API-Key: apex_..." \
  "http://localhost:7070/api/v2/vex/document/{scan_id}"

# Get vulnerabilities enriched with VEX status
curl -H "X-API-Key: apex_..." \
  "http://localhost:7070/api/v2/scan/{scan_id}/vex-enriched"
```

> 📚 **Full Documentation:** Visit `/docs` for interactive Swagger UI or `/redoc` for ReDoc.

<br/>

---

<br/>

## ⚙️ Configuration

### Required Environment Variables

| Variable | Description |
|:---------|:------------|
| `ADMIN_USERNAME` | Admin username (default: `admin`) |
| `ADMIN_PASSWORD_HASH` | **Required.** Bcrypt hash of admin password. Plaintext defaults are rejected. |
| `JWT_SECRET_KEY` | **Required.** Random secret for JWT signing |
| `REDIS_PASSWORD` | Redis authentication password |

### Optional Environment Variables

| Variable | Default | Description |
|:---------|:--------|:------------|
| `USER_USERNAME` | (empty) | Optional non-admin user (empty = disabled) |
| `USER_PASSWORD_HASH` | (empty) | Bcrypt hash for the non-admin user |
| `API_KEY_ENABLED` | `true` | Enable API key authentication |
| `JWT_EXPIRATION_HOURS` | `24` | JWT token lifetime |
| `LOGIN_MAX_ATTEMPTS` | `5` | Max failed logins before lockout |
| `LOGIN_LOCKOUT_SECONDS` | `900` | Lockout duration |
| `SCAN_RESULT_TTL` | `2592000` | Scan result retention in Redis (30 days) |
| `ARTIFACT_RETENTION_DAYS` | `7` | SBOM/report file retention |
| `ANTHROPIC_API_KEY` | (empty) | Enables AI-assisted triage when set |
| `ENABLE_GRYPE` / `ENABLE_TRIVY` / `ENABLE_SYFT` | `true` | Per-scanner toggles |
| `SCAN_TIMEOUT` | `300` | Per-scan timeout in seconds |

### Scaling for High Volume

```bash
# Scale batch workers for parallel scanning
docker-compose up -d --scale worker-batch=4

# Workers consume from prioritized queues:
# - high_priority    (interactive scans)
# - default          (standard scans)
# - batch            (bulk scans)
# - low_priority     (background reprocessing)
# - system           (cleanup, maintenance)
```

<br/>

---

<br/>

## 🗺️ Roadmap

- [x] Multi-method authentication (JWT + API Keys + Basic Auth)
- [x] OpenVEX v0.2.0 support
- [x] Compliance Reports (PCI-DSS 4.0, SOC 2, HIPAA, FedRAMP)
- [x] AI-assisted vulnerability triage
- [x] Dependency graph visualization
- [x] UBI 9 multi-stage Docker builds (non-root)
- [ ] Policy Engine (pass/fail security gates)
- [ ] GitHub Actions integration
- [ ] GitLab CI integration
- [ ] LDAP/OIDC authentication
- [ ] Kubernetes Admission Controller
- [ ] IaC scanning (Terraform, CloudFormation)
- [ ] CIS & NIST compliance frameworks

<br/>

---

<br/>

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

```bash
# Fork the repository
# Create your feature branch
git checkout -b feature/amazing-feature

# Commit your changes
git commit -m 'Add amazing feature'

# Push to the branch
git push origin feature/amazing-feature

# Open a Pull Request
```

<br/>

---

<br/>

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

<br/>

---

<br/>

<div align="center">

### 🔗 Links

[Report Bug](https://github.com/gypsy5oul/apex-scanner/issues) • [Request Feature](https://github.com/gypsy5oul/apex-scanner/issues) • [Documentation](https://github.com/gypsy5oul/apex-scanner/wiki)

<br/>

**Made with ❤️ for the security community**

<br/>

**[⬆ Back to Top](#apex-scanner)**

</div>
