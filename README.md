# Apex Scanner

<div align="center">

```
    ▲
   ╱█╲      APEX SCANNER
  ╱███╲     Peak Vulnerability Detection
 ╱█████╲
```

**The only open-source vulnerability scanner that combines multi-engine scanning with threat intelligence (EPSS/KEV) and actionable remediation.**

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker)](docker-compose.yml)
[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?logo=python)](https://python.org)
[![React](https://img.shields.io/badge/React-18-61DAFB?logo=react)](https://reactjs.org)

[Features](#features) • [Quick Start](#quick-start) • [Screenshots](#screenshots) • [API](#api-documentation) • [Contributing](#contributing)

</div>

---

## Why Apex Scanner?

Most vulnerability scanners give you a list of CVEs. **Apex Scanner** tells you which ones actually matter and how to fix them.

| Feature | Apex Scanner | Trivy | Grype | Snyk |
|---------|-------------|-------|-------|------|
| Multi-Scanner Correlation | ✅ | ❌ | ❌ | ❌ |
| EPSS Scoring | ✅ | ❌ | ❌ | ✅ |
| CISA KEV Integration | ✅ | ❌ | ❌ | ✅ |
| Quick Wins Remediation | ✅ | ❌ | ❌ | ❌ |
| Remediation Scripts | ✅ | ❌ | ❌ | ❌ |
| Web Dashboard | ✅ | ❌ | ❌ | ✅ |
| Self-Hosted | ✅ | ✅ | ✅ | ❌ |
| Cost | **Free** | Free | Free | $$$$ |

---

## Features

### Core Scanning
- **Multi-Scanner Detection** - Combines Grype + Trivy for ~95% detection rate
- **Cross-Validation** - Confidence scoring based on scanner agreement
- **SBOM Generation** - SPDX, CycloneDX, and Syft formats
- **Secret Detection** - Find leaked credentials in images

### Threat Intelligence
- **EPSS Scoring** - Exploit Prediction Scoring System for exploitation probability
- **CISA KEV** - Known Exploited Vulnerabilities catalog integration
- **Risk Prioritization** - Critical/High/Medium/Low based on real-world threat data

### Actionable Remediation
- **Quick Wins Analysis** - Which single update fixes the most vulnerabilities
- **Auto-Generated Scripts** - Ready-to-run remediation commands
- **Package Manager Support** - yum, apt, npm, pip, and more

### Enterprise Features
- **Modern React Dashboard** - Real-time scanning with WebSocket updates
- **Scheduled Scans** - Cron-based automation
- **Batch Scanning** - Scan multiple images in parallel
- **Trend Analysis** - Track vulnerability trends over time
- **PDF/HTML Reports** - Executive-ready reporting
- **REST API** - Full API with OpenAPI documentation
- **Prometheus Metrics** - Production monitoring

---

## Quick Start

### Prerequisites
- Docker & Docker Compose
- 4GB RAM minimum
- 10GB disk space

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/apex-scanner.git
cd apex-scanner

# Copy environment template
cp .env.example .env

# Edit configuration (optional)
nano .env

# Start all services
cd app
docker-compose up -d

# Wait for services to initialize
sleep 30

# Verify installation
curl http://localhost:7070/
```

### Access Points

| Service | URL | Description |
|---------|-----|-------------|
| Dashboard | http://localhost:3001 | Web UI |
| API Docs | http://localhost:7070/docs | Swagger UI |
| API | http://localhost:7070/api/v2 | REST API |
| Flower | http://localhost:5555 | Celery monitoring |
| Metrics | http://localhost:7070/metrics | Prometheus |

### Default Credentials

```
Username: admin
Password: scanner@admin
```

> ⚠️ **Change these in production!** Set `ADMIN_USERNAME` and `ADMIN_PASSWORD` in your `.env` file.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         APEX SCANNER                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌──────────┐     ┌──────────┐     ┌──────────┐                │
│   │  React   │────▶│  FastAPI │────▶│  Celery  │                │
│   │Dashboard │◀────│   API    │◀────│ Workers  │                │
│   └──────────┘     └──────────┘     └────┬─────┘                │
│        │                │                │                       │
│        │           ┌────┴────┐     ┌─────┴─────┐                │
│        │           │  Redis  │     │  Scanners │                │
│        │           └─────────┘     ├───────────┤                │
│        │                           │   Grype   │                │
│        │                           │   Trivy   │                │
│        │                           │   Syft    │                │
│        │                           └───────────┘                │
│        │                                                         │
│        ▼                                                         │
│   ┌──────────────────────────────────────────┐                  │
│   │            Threat Intelligence            │                  │
│   │  ┌─────────┐  ┌─────────┐  ┌──────────┐  │                  │
│   │  │  EPSS   │  │  CISA   │  │  Digest  │  │                  │
│   │  │ Scores  │  │   KEV   │  │  Cache   │  │                  │
│   │  └─────────┘  └─────────┘  └──────────┘  │                  │
│   └──────────────────────────────────────────┘                  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## API Documentation

### Scan an Image

```bash
# Start a scan
curl -X POST "http://localhost:7070/api/v1/scan" \
  -H "Content-Type: application/json" \
  -d '{"image_name": "nginx:latest"}'

# Response
{
  "scan_id": "abc123-...",
  "status": "in_progress",
  "message": "Scan initiated"
}
```

### Get Scan Results

```bash
curl "http://localhost:7070/api/v1/scan/abc123-..."
```

### Get KEV Matches (High Priority)

```bash
curl "http://localhost:7070/api/v2/scan/abc123-.../kev-matches"
```

### Get Quick Wins

```bash
curl "http://localhost:7070/api/v2/scan/abc123-.../quick-wins"
```

### Get EPSS Enriched Vulnerabilities

```bash
curl "http://localhost:7070/api/v2/scan/abc123-.../enriched"
```

See full API documentation at `/docs` or `/redoc`.

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ADMIN_USERNAME` | admin | Admin username |
| `ADMIN_PASSWORD` | scanner@admin | Admin password |
| `JWT_SECRET_KEY` | (random) | JWT signing key |
| `REDIS_URL` | redis://redis:6379/0 | Redis connection |
| `ENABLE_GRYPE` | true | Enable Grype scanner |
| `ENABLE_TRIVY` | true | Enable Trivy scanner |
| `ENABLE_SYFT` | true | Enable Syft SBOM |
| `SCAN_TIMEOUT` | 300 | Scan timeout (seconds) |

### Scaling Workers

```bash
# Scale batch workers for high-volume scanning
docker-compose up -d --scale worker-batch=4
```

---

## Updating Scanner Tools

Check current versions:
```bash
docker exec app-worker-high-1 grype version
docker exec app-worker-high-1 trivy version
docker exec app-worker-high-1 syft version
```

Update versions in `Dockerfile.worker` and rebuild:
```bash
docker-compose build worker-high worker-batch worker-system
docker-compose up -d worker-high worker-batch worker-system
```

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Backend | FastAPI, Celery, Redis |
| Frontend | React 18, Material-UI |
| Scanners | Grype, Trivy, Syft |
| Database | Redis |
| Monitoring | Prometheus, Flower |
| Container | Docker, Docker Compose |

---

## Roadmap

- [ ] Policy Engine (pass/fail gates)
- [ ] GitHub Actions Integration
- [ ] GitLab CI Integration
- [ ] LDAP/OIDC Authentication
- [ ] Kubernetes Admission Controller
- [ ] IaC Scanning (Terraform, CloudFormation)
- [ ] Compliance Reports (CIS, NIST)

---

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) first.

```bash
# Fork the repo
# Create your feature branch
git checkout -b feature/amazing-feature

# Commit your changes
git commit -m 'Add amazing feature'

# Push to the branch
git push origin feature/amazing-feature

# Open a Pull Request
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- [Grype](https://github.com/anchore/grype) - Vulnerability scanner by Anchore
- [Trivy](https://github.com/aquasecurity/trivy) - Security scanner by Aqua Security
- [Syft](https://github.com/anchore/syft) - SBOM generator by Anchore
- [FIRST EPSS](https://www.first.org/epss/) - Exploit Prediction Scoring System
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) - Known Exploited Vulnerabilities

---

<div align="center">

**[⬆ Back to Top](#apex-scanner)**

Made with ❤️ for the security community

</div>
