"""
Keycloak OIDC (authorization-code) integration — server-side BFF.

The backend runs the OIDC code flow and mints the app's existing httpOnly
session cookie, so SSO and local login share one session model and all the
existing route guards keep working unchanged. Group claim -> role mapping
happens here (admin group -> admin, everyone else -> default role).

Hybrid by design: this module is additive and gated on OIDC_ENABLED; the
in-house local login / API keys are untouched.

Uses only existing deps (httpx + PyJWT) — no Authlib.
"""
import json
import time
import secrets
from typing import Optional, Tuple
from urllib.parse import urlencode

import httpx
import jwt
from jwt.algorithms import RSAAlgorithm

from app.config import settings
from app.logging_config import get_logger

logger = get_logger(__name__)

STATE_COOKIE_NAME = "apex_oidc_state"
STATE_TTL_SECONDS = 600  # 10 minutes to complete the login round-trip


def is_enabled() -> bool:
    """True only when OIDC is on AND fully configured."""
    return bool(
        settings.OIDC_ENABLED
        and settings.OIDC_ISSUER
        and settings.OIDC_CLIENT_ID
        and settings.OIDC_CLIENT_SECRET
        and settings.OIDC_REDIRECT_URI
    )


def login_url() -> str:
    return "/api/v2/auth/oidc/login"


# --- Keycloak endpoints (derived from the issuer; matches the discovery doc) ---
def _ep(path: str) -> str:
    return settings.OIDC_ISSUER.rstrip("/") + path


def authorize_endpoint() -> str:
    return _ep("/protocol/openid-connect/auth")


def token_endpoint() -> str:
    return _ep("/protocol/openid-connect/token")


def jwks_uri() -> str:
    return _ep("/protocol/openid-connect/certs")


def end_session_endpoint() -> str:
    return _ep("/protocol/openid-connect/logout")


def _verify():
    # httpx `verify`: a CA bundle path (Keycloak's CA) or True for system trust.
    return settings.OIDC_CA_CERT or True


# --- Stateless CSRF state + nonce, signed with the app's JWT secret ---
def make_state() -> Tuple[str, str, str]:
    """Return (state, nonce, signed_cookie_value)."""
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    signed = jwt.encode(
        {"state": state, "nonce": nonce, "exp": int(time.time()) + STATE_TTL_SECONDS},
        settings.JWT_SECRET_KEY,
        algorithm="HS256",
    )
    return state, nonce, signed


def read_state(signed: str) -> Optional[dict]:
    try:
        return jwt.decode(signed, settings.JWT_SECRET_KEY, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        return None


def build_authorize_url(state: str, nonce: str) -> str:
    params = {
        "client_id": settings.OIDC_CLIENT_ID,
        "response_type": "code",
        "scope": "openid profile email",
        "redirect_uri": settings.OIDC_REDIRECT_URI,
        "state": state,
        "nonce": nonce,
    }
    return authorize_endpoint() + "?" + urlencode(params)


async def exchange_code(code: str) -> dict:
    """Exchange the authorization code for tokens (confidential client)."""
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": settings.OIDC_REDIRECT_URI,
        "client_id": settings.OIDC_CLIENT_ID,
        "client_secret": settings.OIDC_CLIENT_SECRET,
    }
    async with httpx.AsyncClient(verify=_verify(), timeout=10.0) as client:
        resp = await client.post(token_endpoint(), data=data)
        resp.raise_for_status()
        return resp.json()


# --- JWKS cache + ID-token validation ---
_jwks_cache = {"data": None, "exp": 0.0}


async def _get_jwks(force: bool = False) -> dict:
    now = time.time()
    if not force and _jwks_cache["data"] and _jwks_cache["exp"] > now:
        return _jwks_cache["data"]
    async with httpx.AsyncClient(verify=_verify(), timeout=10.0) as client:
        resp = await client.get(jwks_uri())
        resp.raise_for_status()
        data = resp.json()
    _jwks_cache["data"] = data
    _jwks_cache["exp"] = now + 3600
    return data


async def validate_id_token(id_token: str, nonce: Optional[str]) -> dict:
    """Validate signature (JWKS/RS256), iss, aud, exp, and nonce."""
    kid = jwt.get_unverified_header(id_token).get("kid")

    def _find(jwks):
        return next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)

    jwks = await _get_jwks()
    jwk = _find(jwks)
    if jwk is None:  # possible key rotation — refresh once
        jwk = _find(await _get_jwks(force=True))
    if jwk is None:
        raise ValueError("no matching JWKS key for token kid")

    key = RSAAlgorithm.from_jwk(json.dumps(jwk))
    claims = jwt.decode(
        id_token,
        key,
        algorithms=["RS256"],
        audience=settings.OIDC_CLIENT_ID,
        issuer=settings.OIDC_ISSUER,
        options={"require": ["exp", "iat"]},
    )
    if nonce and claims.get("nonce") != nonce:
        raise ValueError("OIDC nonce mismatch")
    return claims


def map_role(claims: dict) -> str:
    """Admin if the user is in the configured admin group, else the default role."""
    groups = claims.get(settings.OIDC_GROUPS_CLAIM) or []
    if isinstance(groups, str):
        groups = [groups]
    # Keycloak may emit names ("devops") or paths ("/devops"); normalize both.
    normalized = {str(g).strip("/").lower() for g in groups}
    admin_group = settings.OIDC_ADMIN_GROUP.strip("/").lower()
    return "admin" if admin_group in normalized else settings.OIDC_DEFAULT_ROLE


def username_from(claims: dict) -> str:
    return (
        claims.get("preferred_username")
        or claims.get("email")
        or claims.get("sub")
        or "sso-user"
    )
