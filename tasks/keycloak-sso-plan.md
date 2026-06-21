# Plan: Keycloak SSO (OIDC) — hybrid with local admin retained

Status: PLANNING. HTTPS edge (Phase 1) is live, which OIDC requires.

## Goal / shape (per requirements)
- **Add OIDC login via Keycloak** as the **default/primary** option on the login page.
- **Keep the existing local login** (bcrypt admin/user + JWT cookie) as a **separate, secondary** path — also serves as break-glass if Keycloak is unavailable.
- Keep **API keys** for automation (unchanged).

## Keycloak (already provisioned)
- Host: `keycloak.6dcorp.in` → `10.0.20.110`  (note: `.in`, not `.internal`)
- Realm: `6D-CORP-INFRA`  → issuer `https://keycloak.6dcorp.in/realms/6D-CORP-INFRA`
- Client: `apex-scanner` (confidential — has a client secret), groups claim = `groups`
- Secrets (admin pw, client secret) are held OUT of git — they go in env/host config only.

## Chosen approach: Backend-for-Frontend (server-side OIDC)
The app is already **httpOnly-cookie** based and same-origin behind the edge, so the cleanest, most secure fit is: the **FastAPI backend** runs the OIDC authorization-code flow, and on success **mints the same app session cookie** it already issues for local login.

Why this over SPA-side (`keycloak-js`):
- Both local + SSO end in the **same** httpOnly cookie → `get_current_user` and all 47 guarded routes stay unchanged downstream.
- **No tokens in the browser** (confidential client secret + tokens stay server-side) → no localStorage/XSS exposure.
- Works same-origin behind the edge with no CORS.

### Flow
1. User clicks **"Sign in with 6D SSO"** → browser GETs `/api/v1/auth/oidc/login`.
2. Backend builds the authorize URL (state + nonce in a short signed cookie) → 302 to Keycloak.
3. User authenticates at Keycloak → 302 back to `/api/v1/auth/oidc/callback?code=…`.
4. Backend validates `state`, exchanges `code` (with client secret) for tokens, **validates the ID token** (signature via realm JWKS, `iss`, `aud=apex-scanner`, `exp`, `nonce`).
5. Backend reads `preferred_username`/`email` + the `groups` claim → **maps group → role** (admin vs user) → calls the existing `create_access_token()` → **`set_cookie()`** (same httpOnly cookie) → 302 to `/`.
6. The SPA loads authenticated; `AuthContext` reads identity from `/api/v1/auth/me`.

## Backend changes
- **Config/env** (NOT committed — set on the `api` service): `OIDC_ENABLED=true`,
  `OIDC_ISSUER=https://keycloak.6dcorp.in/realms/6D-CORP-INFRA`,
  `OIDC_CLIENT_ID=apex-scanner`, `OIDC_CLIENT_SECRET=***`,
  `OIDC_REDIRECT_URI=https://apexscanner.6dcorp.internal/api/v1/auth/oidc/callback`,
  `OIDC_GROUPS_CLAIM=groups`, `OIDC_ADMIN_GROUP=/devops`, `OIDC_DEFAULT_ROLE=user`.
  (Match the admin group leniently — accept `/devops` or `devops` depending on how
  the group mapper emits the claim. **Confirmed:** members of `devops` → admin, all
  other authenticated SSO users → user.)
- **New `app/app/oidc.py`** — Authlib (`authlib`) OAuth client against the realm's discovery doc; helpers to validate the ID token via JWKS and map `groups → role`.
- **New routes** in `routes_v2.py`: `GET /auth/oidc/login`, `GET /auth/oidc/callback`; extend `/auth/logout` to optionally hit Keycloak's RP-initiated `end_session_endpoint` for SSO sessions.
- **`GET /api/v1/auth/config`** (public) → `{ "oidc_enabled": true, "oidc_login_url": "/api/v1/auth/oidc/login" }` so the frontend shows the SSO button only when enabled (graceful degrade).
- **`GET /api/v1/auth/me`** → `{username, role, auth_method}` for `AuthContext` (confirm it exists; add if not — the OIDC redirect path has no JSON login response for the SPA to read).
- `get_current_user` / `get_optional_admin` / API keys / local login / rate-limit: **unchanged**.
- **TLS trust:** the `api` container must trust Keycloak's cert for token-exchange + JWKS. Mount `/opt/vault/cert/6d-corp.pem` into `api` and set `SSL_CERT_FILE`/`REQUESTS_CA_BUNDLE` (or Authlib `verify`) — assuming Keycloak's cert chains to the 6D Root CA (to confirm).
- **DNS for the container:** add `extra_hosts: ["keycloak.6dcorp.in:10.0.20.110"]` to the `api` service so the backend resolves Keycloak.

## Frontend changes
- **`Login.js`**: on mount, GET `/api/v1/auth/config`. If `oidc_enabled`:
  - Primary, prominent button **"Sign in with 6D SSO"** → `window.location.href = oidc_login_url`.
  - Secondary **"Use a local account"** link/toggle that reveals the existing username/password form (current local login, unchanged).
- **`AuthContext`**: both flows finish with the cookie set; keep deriving identity from `/auth/me`. Minimal change — works for local and SSO alike.
- **`ProtectedRoute`**: unchanged (role-based; role comes from `AuthContext`).

## Prerequisites (Keycloak / infra side — needed before implementing)
1. In the `apex-scanner` client: enable **Standard Flow**, register **Valid Redirect URI**
   `https://apexscanner.6dcorp.internal/api/v1/auth/oidc/callback` and **post-logout redirect**
   `https://apexscanner.6dcorp.internal/`. (Web origins can stay `+` or the FQDN.)
2. Confirm a **group membership mapper** puts `groups` into the **ID token** (claim name `groups`).
3. **Decide which group = admin** (e.g. `/apex-admins`) and what non-admin SSO users get (`user`, or deny). ← OPEN QUESTION
4. Confirm Keycloak's TLS cert **chains to the 6D Root CA** (so the backend can verify it) — or provide its CA.
5. `keycloak.6dcorp.in` reachable from the host/`api` container (extra_hosts entry above).
6. Client secret + admin pw stored in env/secret store, never committed.

## Rollout / rollback
- All backend changes are **additive and flag-gated** (`OIDC_ENABLED`); local auth is untouched.
- Deploy backend → register redirect URI → test SSO end-to-end (admin-group user → admin, normal user → user) → ship the frontend dual-login.
- **Rollback:** `OIDC_ENABLED=false` hides the SSO button and disables the routes; local login keeps working. Zero impact on existing sessions/API keys.

## Decisions / verified (2026-06-21)
- ✅ **Admin group = `devops`** → `admin`; all other authenticated SSO users → `user` (not denied).
- ✅ **Keycloak TLS chains to the 6D Root CA** (`/opt/vault/cert/6d-corp.pem`) — discovery verified, `tls_verify 0`. Backend uses that CA bundle.
- ✅ **Client `apex-scanner`**: confidential, Standard Flow enabled, `redirectUris=['*']` (callback already allowed — recommend tightening to the exact callback URL post-rollout). `end_session_endpoint` exists (single-logout available).
- ✅ Endpoints (from discovery): authorize/token/jwks/end_session under `…/realms/6D-CORP-INFRA/protocol/openid-connect/*`.

## Remaining minor decisions (sensible defaults — change if you prefer)
- **Logout scope (default):** clear the app session cookie only. Optional `OIDC_RP_LOGOUT=true` to also hit Keycloak's `end_session_endpoint` (single sign-out).
- **Local login visibility (default):** shown via a secondary "Use a local account" toggle on the login page (break-glass + admin). Can hide behind `/login?local=1` if you'd rather.
- ✅ **VERIFIED:** client-level group-membership mapper, claim `groups`, **on the ID token**, `full_path=false` → emits **names** (`["devops",…]`). So `OIDC_ADMIN_GROUP=devops` (name match) and no extra `scope=groups` is needed.
