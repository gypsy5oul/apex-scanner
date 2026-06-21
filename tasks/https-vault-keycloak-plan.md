# Plan: FQDN + HTTPS (Vault PKI) → then Keycloak SSO

Status: PLANNING — nothing implemented yet. Awaiting Phase-0 prerequisites.

## Decisions (locked)
- **FQDN:** `apexscanner.6dcorp.internal` (under `*.6dcorp.internal`, allowed by the Vault role)
- **Topology:** dedicated **nginx edge reverse proxy** on `:443`, single HTTPS origin
- **Same-origin:** the SPA and API are served under one origin, so report/SBOM (http→https) mixed-content and CORS both disappear; cookie auth (`withCredentials`) keeps working with no special handling

## Current state (verified)
- App is two origins today: dashboard nginx (`:3001`→8080, static React) + FastAPI (`:7070`→8000).
- React API base is **baked at build time**: `api.js` → `REACT_APP_API_URL` then axios baseURL `/api/v1` and `/api/v2`. Fallback is `http://<host>:7070`.
- `ScanResults` builds report URLs from `REACT_APP_API_URL` (else `http://<host>:7070`).
- Backend serves: API at `/api/v1`, `/api/v2`; files at `/reports/*`, `/sboms/*`; docs at `/docs`, `/redoc`, `/openapi.json`. CORS is env-driven (`CORS_ORIGINS`, `allow_credentials=True`).
- SPA routes (/, /scan, /history, /compliance, /vex, …) — **no collision** with `/api`, `/reports`, `/sboms`, `/docs`, `/health`.
- Host: `vault` CLI installed; `vault.6dcorp.internal` resolves (10.0.20.110). **CA cert `/opt/vault/cert/6d-corp.pem` is NOT present yet.**

## Routing map (edge proxy → upstreams, all on the compose network)
| Path | Upstream |
|------|----------|
| `/api/`                         | `fastapi:8000` |
| `/reports/`, `/sboms/`          | `fastapi:8000` |
| `/docs`, `/redoc`, `/openapi.json` | `fastapi:8000` (optional; can lock down) |
| `/` (everything else, SPA)      | `dashboard:8080` |
| `:80` any                       | 301 → `https://apexscanner.6dcorp.internal$request_uri` |

---

## Phase 0 — Prerequisites (BLOCKERS, need infra/you)
1. **DNS A record** `apexscanner.6dcorp.internal` → this host's IP (proper DNS, not client `/etc/hosts`, for a real rollout).
2. **CA cert** placed at `/opt/vault/cert/6d-corp.pem` (copy from the Vault host / runbook source). Needed for `VAULT_CACERT`.
3. **Real AppRole creds** — the runbook's `role_id`/`secret_id` are samples ("replace with ours"). Confirm the actual values issued to us (treat as secrets; never commit).
4. Confirm host `:443`/`:80` are free (no other service bound).

## Phase 1 — FQDN + HTTPS (Vault PKI + auto-renew)
1. **Validate issuance** (runbook §1) as a throwaway test:
   `vault write pki_int/issue/6dcorp-internal common_name=apexscanner.6dcorp.internal ttl=720h` → confirm cert + chain + key returned and chain verifies against the CA.
2. **Edge proxy service** (`apexscanner_edge`, image `nginx:stable` or `ubi9/nginx`) added to `app/docker-compose.yml`:
   - Publishes host `80:80` and `443:443`.
   - On the internal compose network; reaches `dashboard:8080` and `fastapi:8000` by service name.
   - Mounts the rendered cert dir read-only (e.g. host `/etc/ssl/apexscanner` → container `/etc/nginx/certs`).
   - nginx server block: TLS 1.2/1.3, `ssl_certificate /etc/nginx/certs/fullchain.pem`, `ssl_certificate_key /etc/nginx/certs/key.pem`, HSTS + security headers, the routing map above, websocket/upgrade headers, sane `client_max_body_size`, `proxy_read_timeout` for long scans.
   - Separate `:80` server doing the 301 redirect.
3. **Cert delivery via Vault Agent** (runbook §2) on the **host**:
   - Creds in `/etc/vault-agent/{role_id,secret_id}` (0600).
   - **Two** template stanzas (nginx needs cert and key as separate files — the runbook's single combined PEM is for haproxy):
     - `fullchain.pem` = `.Data.certificate` + `range .Data.ca_chain`
     - `key.pem` = `.Data.private_key`
     - rendered into host `/etc/ssl/apexscanner/` (0600), `common_name=apexscanner.6dcorp.internal`, `ttl=720h`.
   - Reload command: `docker exec apexscanner_edge nginx -s reload` (or `docker kill --signal=HUP apexscanner_edge`).
   - systemd unit `vault-agent.service` (runbook §2d), `enable --now`.
4. **Frontend → same-origin rebuild:**
   - Set `DASHBOARD_API_URL=https://apexscanner.6dcorp.internal` (so `REACT_APP_API_URL` bakes to the FQDN; baseURL becomes `https://apexscanner.6dcorp.internal/api/v1` — same origin as the page).
   - Sanity-check `api.js` and `ScanResults` report-URL builder resolve to the FQDN over https (fix the `http://<host>:7070` fallbacks to be scheme-relative / same-origin).
   - Rebuild + redeploy the dashboard image.
5. **Compose hardening:**
   - `CORS_ORIGINS=https://apexscanner.6dcorp.internal` (or disable CORS entirely — same-origin no longer needs it).
   - Stop publishing raw `3001`/`7070` on all interfaces — bind to `127.0.0.1` only (or drop host ports; edge reaches them internally). Only `80`/`443` exposed publicly.
6. **Verify:** `curl --cacert /opt/vault/cert/6d-corp.pem https://apexscanner.6dcorp.internal/health`; browser load, login (cookie), run a scan, open report/SBOM (https, no mixed-content); `journalctl -u vault-agent -f` shows login + render; force a renew and confirm nginx reloads.

### Rollback
Edge is additive; raw `:3001`/`:7070` can be re-exposed instantly by reverting the compose hardening. Frontend rebuild is one image revert. Vault Agent is a `systemctl disable --now`.

---

## Phase 2 — Keycloak SSO (detailed plan AFTER Phase 1 is stable)
HTTPS is a hard prerequisite (OIDC redirect URIs must be https). High-level shape:
- **Keycloak:** realm + confidential/public client for the app; map a Keycloak group/role → app `admin`.
- **Frontend:** adopt `keycloak-js` (or `oidc-client-ts`); replace the in-house `/login` page + cookie flow with the OIDC redirect/PKCE flow; attach the access token to API calls.
- **Backend:** rewrite `auth.py` to validate Keycloak-issued JWTs (JWKS from the realm), map claims → roles; retire the in-house JWT/password path. Decide fate of **API keys** (keep as a service-to-service mechanism, or move to Keycloak service accounts).
- **Migration:** map existing users → Keycloak users (or federate LDAP/AD if that's the source of truth); communicate cutover.
- Will produce its own runbook once Phase 1 lands.

## Open questions for Phase 2 (later)
- Identity source of truth — Keycloak-local users, or LDAP/AD federation?
- Keep API-key auth for automation, or replace with Keycloak service accounts?
- Single client or separate clients for SPA vs API?
