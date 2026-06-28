---
description: Run a full APEX company review — hierarchical teams (ICs → architects → execs → GTM) audit the whole codebase and report to the board
argument-hint: "[optional focus, e.g. 'security' or 'pre-release']"
---

# APEX Company-Wide Review

You are orchestrating a complete company review of **APEX** (this codebase — an
enterprise container-vulnerability scanning platform). **Everyone is an owner
and an employee of APEX** — review with an owner's candor: surface real risks,
don't flatter the product.

Optional focus for this run: **$ARGUMENTS** (if empty, do a full review; if set,
weight every team toward that theme but still cover their domain).

## Org structure & process

Run the review as a real company, in three waves. Within each technical team the
**individual contributors review in parallel**, then their **architect / SA
synthesizes** the team's findings into a single verdict (the ICs report up).

Dispatch agents with the **Agent tool** (`subagent_type: general-purpose`).
Give each agent: the repo root (`/opt/new-grype-scanner-v1`), its role, the exact
scope to review, and an instruction to return **specific findings with
`file:line` evidence, severity (P0/P1/P2), and concrete fixes** — not generic
advice. Tell them their output is consumed by their architect, not shown to a
human.

### Wave 1 — Individual contributors (dispatch ALL in parallel)
- **DevOps team:** a *DevOps Engineer* (CI/CD, Docker/compose, image hygiene,
  deploy, config/secrets) and an *SRE* (reliability, SPOFs, monitoring/alerting,
  backups/DR, scaling, failure modes).
- **Backend team:** *Backend Dev A* (data/persistence — Redis↔Postgres migration,
  repositories, dual-write, integrity) and *Backend Dev B* (API, auth, Celery,
  scanner orchestration, business logic).
- **Frontend team:** *Frontend Dev A* (architecture, state, data-fetching, build)
  and *Frontend Dev B* (UX, components, accessibility, design-system use).
- **Security team:** *Security Eng A* (appsec — authz/IDOR, input validation,
  SSRF/injection, WebSocket/API exposure) and *Security Eng B* (infra/cloud sec —
  containers, secrets, network, supply chain).

### Wave 2 — Architects/experts + executives + GTM (dispatch in parallel)
Pass each architect the **Wave-1 findings from their own team** to synthesize:
- **DevOps Architect** (end-to-end) ← DevOps Eng + SRE
- **Backend Solution Architect / Expert** ← Backend Dev A + B
- **Frontend Solution Architect / Expert** ← Frontend Dev A + B
- **Cybersecurity Solution Architect** ← Security Eng A + B

In the same wave, dispatch the **executive + GTM** agents (they may reference the
team summaries you already have):
- **CEO** — viability, market fit, the 3 things blocking enterprise deals.
- **CTO** — tech strategy, debt, scaling, build-vs-buy, team risk (bus factor).
- **CIO** — data governance, compliance/audit, information risk, vendor/tooling.
- **Sales Lead** — who buys this, the pitch, top deal-blockers & objections.
- **Marketing Lead** — positioning, differentiation vs Snyk/Prisma/Aqua/Trivy-as-a-service,
  messaging, ICP, GTM motion.

### Wave 3 — Board report (you, the orchestrator)
Synthesize everything into an **APEX Board Report**:
1. **Verdict** — one honest paragraph (where APEX stands).
2. **Cross-team consensus** — issues ≥2 teams independently raised (highest signal).
3. **Per-team highlights** — each architect's verdict + their top findings (with `file:line`).
4. **Executive + GTM section** — CEO/CTO/CIO takeaways + the sales/marketing positioning.
5. **Unified prioritized action list** — P0 / P1 / P2, deduped across all teams,
   each with owner-team and rough effort.

**Verify before relaying:** these agents run without you double-checking each
claim — note any finding you couldn't corroborate, and don't present unverified
severe claims as fact. Reconcile against what's already known/fixed in the repo
(check git log / memory) so you don't re-flag resolved issues.
