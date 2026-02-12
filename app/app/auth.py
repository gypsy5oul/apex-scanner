"""
Authentication module for admin access
JWT + API key authentication with bcrypt password hashing and rate limiting
"""
import hashlib
import secrets
import sys
from datetime import datetime, timedelta
from typing import Optional

import bcrypt
import jwt
from fastapi import HTTPException, Security, Depends, Header, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

from app.config import settings, get_redis_client
from app.logging_config import get_logger

logger = get_logger(__name__)

# Constants
JWT_ALGORITHM = "HS256"
INSECURE_JWT_SECRETS = {"your-secret-key-change-in-production", ""}
INSECURE_PASSWORDS = {"scanner@admin", "admin", "password", "changeme", ""}
API_KEY_PREFIX = "apex_"
API_KEY_REDIS_PREFIX = "api_key:"
LOGIN_ATTEMPT_PREFIX = "login_attempts:"

# Security scheme
security = HTTPBearer(auto_error=False)


# --- Pydantic Models ---

class LoginRequest(BaseModel):
    """Login request model"""
    username: str
    password: str


class LoginResponse(BaseModel):
    """Login response model"""
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    username: str
    role: str


class TokenData(BaseModel):
    """Decoded token data"""
    username: str
    role: str = "admin"
    exp: datetime
    auth_method: str = "jwt"


class APIKeyCreate(BaseModel):
    """API key creation request"""
    name: str
    expires_days: Optional[int] = 365


class APIKeyResponse(BaseModel):
    """API key creation response (only time the raw key is shown)"""
    key: str
    key_id: str
    name: str
    created_at: str
    expires_at: Optional[str] = None


class APIKeyInfo(BaseModel):
    """API key info (without the raw key)"""
    key_id: str
    name: str
    created_at: str
    expires_at: Optional[str] = None
    last_used: Optional[str] = None


# --- Startup Validation ---

def validate_credentials_or_die():
    """
    Refuse to start if insecure default credentials are detected.
    Call this during application startup.
    """
    errors = []

    # Check JWT secret
    if settings.JWT_SECRET_KEY in INSECURE_JWT_SECRETS:
        errors.append(
            "JWT_SECRET_KEY is not set or uses an insecure default. "
            "Set a strong random secret: python -c \"import secrets; print(secrets.token_urlsafe(64))\""
        )

    # Check that a password hash is provided
    if not settings.ADMIN_PASSWORD_HASH:
        # Check if they're still using the legacy plaintext approach
        if settings.ADMIN_PASSWORD and settings.ADMIN_PASSWORD not in INSECURE_PASSWORDS:
            errors.append(
                "ADMIN_PASSWORD (plaintext) is no longer supported. "
                "Migrate to ADMIN_PASSWORD_HASH with bcrypt. Generate with:\n"
                f"  python -c \"import bcrypt; print(bcrypt.hashpw(b'<your-password>', bcrypt.gensalt()).decode())\""
            )
        else:
            errors.append(
                "ADMIN_PASSWORD_HASH is not set. Generate a bcrypt hash:\n"
                "  python -c \"import bcrypt; print(bcrypt.hashpw(b'yourpassword', bcrypt.gensalt()).decode())\""
            )

    # Check for legacy insecure plaintext password still being set
    if settings.ADMIN_PASSWORD in INSECURE_PASSWORDS and settings.ADMIN_PASSWORD != "":
        errors.append(
            f"ADMIN_PASSWORD is set to an insecure default value '{settings.ADMIN_PASSWORD}'. "
            "Remove ADMIN_PASSWORD and use ADMIN_PASSWORD_HASH instead."
        )

    if errors:
        logger.error("SECURITY: Startup blocked due to insecure credentials", errors=errors)
        print("\n" + "=" * 70, file=sys.stderr)
        print("SECURITY ERROR: Cannot start with insecure credentials!", file=sys.stderr)
        print("=" * 70, file=sys.stderr)
        for i, error in enumerate(errors, 1):
            print(f"\n  {i}. {error}", file=sys.stderr)
        print("\n" + "=" * 70 + "\n", file=sys.stderr)
        sys.exit(1)


# --- Password Authentication ---

def authenticate_user(username: str, password: str) -> Optional[str]:
    """
    Validate credentials using bcrypt.
    Returns role string ("admin" or "user") on success, None on failure.
    """
    # Check admin credentials
    if username == settings.ADMIN_USERNAME and settings.ADMIN_PASSWORD_HASH:
        try:
            if bcrypt.checkpw(
                password.encode("utf-8"),
                settings.ADMIN_PASSWORD_HASH.encode("utf-8"),
            ):
                return "admin"
        except (ValueError, TypeError) as e:
            logger.error("Admin password verification failed", error=str(e))

    # Check normal user credentials
    if (settings.USER_USERNAME
            and settings.USER_PASSWORD_HASH
            and username == settings.USER_USERNAME):
        try:
            if bcrypt.checkpw(
                password.encode("utf-8"),
                settings.USER_PASSWORD_HASH.encode("utf-8"),
            ):
                return "user"
        except (ValueError, TypeError) as e:
            logger.error("User password verification failed", error=str(e))

    return None


# --- Rate Limiting ---

def check_rate_limit(client_ip: str) -> None:
    """
    Check and enforce login rate limiting.
    Raises HTTP 429 if too many failed attempts.
    """
    r = get_redis_client()
    key = f"{LOGIN_ATTEMPT_PREFIX}{client_ip}"

    attempts = r.get(key)
    if attempts and int(attempts) >= settings.LOGIN_MAX_ATTEMPTS:
        ttl = r.ttl(key)
        logger.warning("Login rate limit exceeded", client_ip=client_ip, attempts=attempts)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed login attempts. Try again in {ttl} seconds.",
            headers={"Retry-After": str(ttl)},
        )


def record_failed_login(client_ip: str) -> None:
    """Record a failed login attempt for rate limiting."""
    r = get_redis_client()
    key = f"{LOGIN_ATTEMPT_PREFIX}{client_ip}"
    pipe = r.pipeline()
    pipe.incr(key)
    pipe.expire(key, settings.LOGIN_LOCKOUT_SECONDS)
    pipe.execute()


def clear_login_attempts(client_ip: str) -> None:
    """Clear failed login attempts after successful login."""
    r = get_redis_client()
    r.delete(f"{LOGIN_ATTEMPT_PREFIX}{client_ip}")


# --- JWT Token Management ---

def create_access_token(username: str, role: str = "admin") -> tuple[str, int]:
    """
    Create JWT access token with role claim.
    Returns: (token, expires_in_seconds)
    """
    expires_delta = timedelta(hours=settings.JWT_EXPIRATION_HOURS)
    expire = datetime.utcnow() + expires_delta

    payload = {
        "sub": username,
        "role": role,
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "access",
    }

    token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    expires_in = int(expires_delta.total_seconds())

    return token, expires_in


def verify_token(token: str) -> Optional[TokenData]:
    """Verify JWT token and return token data."""
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
        exp = datetime.fromtimestamp(payload.get("exp"))
        role = payload.get("role", "admin")  # Default "admin" for backward compat

        if username is None:
            return None

        return TokenData(username=username, role=role, exp=exp, auth_method="jwt")
    except jwt.ExpiredSignatureError:
        logger.warning("Token expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.warning("Invalid token", error=str(e))
        return None


# --- API Key Management ---

def _hash_api_key(raw_key: str) -> str:
    """Hash an API key for storage using SHA-256."""
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def create_api_key(name: str, expires_days: Optional[int] = 365) -> APIKeyResponse:
    """Create a new API key and store its hash in Redis."""
    raw_key = f"{API_KEY_PREFIX}{secrets.token_urlsafe(48)}"
    key_hash = _hash_api_key(raw_key)
    key_id = key_hash[:12]

    now = datetime.utcnow()
    key_data = {
        "key_id": key_id,
        "name": name,
        "key_hash": key_hash,
        "created_at": now.isoformat(),
        "created_by": settings.ADMIN_USERNAME,
    }

    expires_at = None
    ttl = None
    if expires_days:
        expires_at = (now + timedelta(days=expires_days)).isoformat()
        key_data["expires_at"] = expires_at
        ttl = expires_days * 86400

    r = get_redis_client()
    redis_key = f"{API_KEY_REDIS_PREFIX}{key_hash}"
    r.hset(redis_key, mapping=key_data)
    if ttl:
        r.expire(redis_key, ttl)

    # Also maintain an index of all key IDs for listing
    r.sadd("api_keys:index", key_hash)

    logger.info("API key created", key_id=key_id, name=name)

    return APIKeyResponse(
        key=raw_key,
        key_id=key_id,
        name=name,
        created_at=now.isoformat(),
        expires_at=expires_at,
    )


def validate_api_key(raw_key: str) -> Optional[TokenData]:
    """Validate an API key and return token data if valid."""
    if not raw_key.startswith(API_KEY_PREFIX):
        return None

    key_hash = _hash_api_key(raw_key)
    r = get_redis_client()
    key_data = r.hgetall(f"{API_KEY_REDIS_PREFIX}{key_hash}")

    if not key_data:
        return None

    # Check expiration
    expires_at = key_data.get("expires_at")
    if expires_at:
        if datetime.fromisoformat(expires_at) < datetime.utcnow():
            return None

    # Update last used timestamp
    r.hset(f"{API_KEY_REDIS_PREFIX}{key_hash}", "last_used", datetime.utcnow().isoformat())

    return TokenData(
        username=key_data.get("created_by", "api_key"),
        exp=datetime.fromisoformat(expires_at) if expires_at else datetime.max,
        auth_method="api_key",
    )


def list_api_keys() -> list[APIKeyInfo]:
    """List all active API keys (without the raw keys)."""
    r = get_redis_client()
    key_hashes = r.smembers("api_keys:index")
    keys = []

    for key_hash in key_hashes:
        key_data = r.hgetall(f"{API_KEY_REDIS_PREFIX}{key_hash}")
        if key_data:
            keys.append(APIKeyInfo(
                key_id=key_data.get("key_id", ""),
                name=key_data.get("name", ""),
                created_at=key_data.get("created_at", ""),
                expires_at=key_data.get("expires_at"),
                last_used=key_data.get("last_used"),
            ))
        else:
            # Key expired from Redis, clean up the index
            r.srem("api_keys:index", key_hash)

    return keys


def revoke_api_key(key_id: str) -> bool:
    """Revoke an API key by its key_id."""
    r = get_redis_client()
    key_hashes = r.smembers("api_keys:index")

    for key_hash in key_hashes:
        key_data = r.hgetall(f"{API_KEY_REDIS_PREFIX}{key_hash}")
        if key_data and key_data.get("key_id") == key_id:
            r.delete(f"{API_KEY_REDIS_PREFIX}{key_hash}")
            r.srem("api_keys:index", key_hash)
            logger.info("API key revoked", key_id=key_id)
            return True

    return False


# --- FastAPI Dependencies ---

async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security),
    x_api_key: Optional[str] = Header(None),
) -> TokenData:
    """
    Dependency to get current authenticated user.
    Supports both JWT Bearer tokens and X-API-Key header.
    Raises 401 if not authenticated.
    """
    # Try API key first
    if x_api_key and settings.API_KEY_ENABLED:
        token_data = validate_api_key(x_api_key)
        if token_data:
            return token_data

    # Try JWT Bearer token
    if credentials:
        token_data = verify_token(credentials.credentials)
        if token_data:
            return token_data

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Provide a Bearer token or X-API-Key header.",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_current_admin(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security),
    x_api_key: Optional[str] = Header(None),
) -> TokenData:
    """
    Dependency to get current admin user.
    Raises 401 if not authenticated, 403 if not admin role.
    """
    token_data = await get_current_user(credentials, x_api_key)

    if token_data.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required. This action is restricted to administrators.",
        )

    return token_data


async def get_optional_admin(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security),
    x_api_key: Optional[str] = Header(None),
) -> Optional[TokenData]:
    """
    Dependency to optionally get admin user.
    Returns None if not authenticated (doesn't raise error).
    """
    if x_api_key and settings.API_KEY_ENABLED:
        token_data = validate_api_key(x_api_key)
        if token_data:
            return token_data

    if credentials:
        return verify_token(credentials.credentials)

    return None


def login(username: str, password: str, request: Optional[Request] = None) -> LoginResponse:
    """
    Authenticate user and return access token.
    Enforces rate limiting when request is provided.
    """
    client_ip = "unknown"
    if request:
        client_ip = request.client.host if request.client else "unknown"
        check_rate_limit(client_ip)

    role = authenticate_user(username, password)
    if role is None:
        logger.warning("Failed login attempt", username=username, client_ip=client_ip)
        if request:
            record_failed_login(client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    # Clear rate limit on successful login
    if request:
        clear_login_attempts(client_ip)

    token, expires_in = create_access_token(username, role)

    logger.info("Login successful", username=username, role=role, client_ip=client_ip)

    return LoginResponse(
        access_token=token,
        token_type="bearer",
        expires_in=expires_in,
        username=username,
        role=role,
    )
