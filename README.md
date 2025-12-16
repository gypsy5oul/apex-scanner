# Apex Scanner

<div align="center">

<!-- Logo/Banner -->
<img src="https://img.shields.io/badge/▲-APEX%20SCANNER-blue?style=for-the-badge&labelColor=1a1a2e&color=4361ee" alt="Apex Scanner" height="60"/>

<br/>
<br/>

<h3>Peak Vulnerability Detection</h3>

<p>Enterprise-grade container security scanning platform with multi-engine correlation, threat intelligence, and actionable remediation.</p>

<br/>

[![License](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat-square&logo=docker&logoColor=white)](docker-compose.yml)
[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react&logoColor=white)](https://reactjs.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)

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

### 🔍 Core Scanning
- **Multi-Engine Detection** - Higher detection rate with cross-validation
- **Confidence Scoring** - Results validated across multiple engines
- **SBOM Generation** - SPDX and CycloneDX formats
- **Secret Detection** - Find leaked credentials in images

</td>
<td width="50%">

### 🎯 Threat Intelligence
- **EPSS Scoring** - Exploit probability predictions
- **CISA KEV Integration** - Known exploited vulnerabilities
- **Risk Prioritization** - Focus on what matters most
- **Real-time Updates** - Automatic threat feed updates

</td>
</tr>
<tr>
<td width="50%">

### 🛠️ Actionable Remediation
- **Quick Wins Analysis** - Maximum impact with minimum effort
- **Auto-Generated Scripts** - Ready-to-run fix commands
- **Package Manager Support** - yum, apt, npm, pip, and more
- **Dependency Analysis** - Understand vulnerability chains

</td>
<td width="50%">

### 🏢 Enterprise Ready
- **Modern Dashboard** - Real-time WebSocket updates
- **Scheduled Scans** - Cron-based automation
- **Batch Scanning** - Parallel multi-image scanning
- **PDF/HTML Reports** - Executive-ready reporting

</td>
</tr>
</table>

<br/>

---

<br/>

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- 4GB RAM minimum
- 10GB disk space

### Installation

```bash
# Clone the repository
git clone https://github.com/gypsy5oul/apex-scanner.git
cd apex-scanner

# Copy environment template
cp .env.example .env

# Start all services
cd app
docker-compose up -d

# Wait for services to initialize (about 30 seconds)
```

### Access Points

| Service | URL | Description |
|:--------|:----|:------------|
| 🖥️ **Dashboard** | http://localhost:3001 | Web Interface |
| 📚 **API Docs** | http://localhost:7070/docs | Swagger UI |
| 🔌 **REST API** | http://localhost:7070/api/v2 | API Endpoints |
| 📊 **Metrics** | http://localhost:7070/metrics | Prometheus |

### Default Credentials

```
Username: admin
Password: scanner@admin
```

> ⚠️ **Security Note:** Change these credentials in production by setting `ADMIN_USERNAME` and `ADMIN_PASSWORD` in your `.env` file.

<br/>

---

<br/>

## 🏗️ Architecture

```
                              ┌─────────────────┐
                              │   Dashboard     │
                              │   (React UI)    │
                              └────────┬────────┘
                                       │
                                       ▼
┌──────────────┐             ┌─────────────────┐             ┌──────────────┐
│   Clients    │────────────▶│    FastAPI      │────────────▶│    Celery    │
│  (API/Web)   │◀────────────│      API        │◀────────────│   Workers    │
└──────────────┘             └────────┬────────┘             └──────┬───────┘
                                      │                             │
                             ┌────────┴────────┐                    │
                             │                 │                    ▼
                        ┌────┴────┐      ┌─────┴─────┐      ┌──────────────┐
                        │  Redis  │      │  Reports  │      │   Scanning   │
                        │  Cache  │      │  Storage  │      │   Engines    │
                        └─────────┘      └───────────┘      └──────────────┘
                                                                    │
                                               ┌────────────────────┼────────────────────┐
                                               ▼                    ▼                    ▼
                                        ┌────────────┐      ┌────────────┐      ┌────────────┐
                                        │    EPSS    │      │    KEV     │      │   Digest   │
                                        │   Scores   │      │  Database  │      │   Cache    │
                                        └────────────┘      └────────────┘      └────────────┘
```

<br/>

---

<br/>

## 📖 API Documentation

### Scan an Image

```bash
curl -X POST "http://localhost:7070/api/v1/scan" \
  -H "Content-Type: application/json" \
  -d '{"image_name": "nginx:latest"}'
```

**Response:**
```json
{
  "scan_id": "abc123-...",
  "status": "in_progress",
  "message": "Scan initiated"
}
```

### Get Scan Results

```bash
curl "http://localhost:7070/api/v1/scan/{scan_id}"
```

### Get High-Risk Vulnerabilities (KEV Matches)

```bash
curl "http://localhost:7070/api/v2/scan/{scan_id}/kev-matches"
```

### Get Quick Wins Remediation

```bash
curl "http://localhost:7070/api/v2/scan/{scan_id}/quick-wins"
```

### Get EPSS-Enriched Results

```bash
curl "http://localhost:7070/api/v2/scan/{scan_id}/enriched"
```

> 📚 **Full Documentation:** Visit `/docs` or `/redoc` for complete API reference.

<br/>

---

<br/>

## ⚙️ Configuration

### Environment Variables

| Variable | Default | Description |
|:---------|:--------|:------------|
| `ADMIN_USERNAME` | admin | Admin username |
| `ADMIN_PASSWORD` | scanner@admin | Admin password |
| `JWT_SECRET_KEY` | (auto) | JWT signing key |
| `REDIS_URL` | redis://redis:6379/0 | Redis connection |
| `SCAN_TIMEOUT` | 300 | Scan timeout (seconds) |

### Scaling for High Volume

```bash
# Scale workers for parallel scanning
docker-compose up -d --scale worker-batch=4
```

<br/>

---

<br/>

## 🗺️ Roadmap

- [ ] Policy Engine (pass/fail security gates)
- [ ] GitHub Actions Integration
- [ ] GitLab CI Integration
- [ ] LDAP/OIDC Authentication
- [ ] Kubernetes Admission Controller
- [ ] IaC Scanning (Terraform, CloudFormation)
- [ ] Compliance Reports (CIS, NIST, PCI-DSS)

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

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

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
