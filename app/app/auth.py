"""
Authentication module for admin access
Simple JWT-based authentication for protecting admin endpoints
"""
import os
from datetime import datetime, timedelta
from typing import Optional
from fastapi import HTTPException, Security, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from pydantic import BaseModel

from app.logging_config import get_logger

logger = get_logger(__name__)

# Configuration from environment
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "scanner@admin")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-change-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = int(os.getenv("JWT_EXPIRATION_HOURS", "24"))

# Security scheme
security = HTTPBearer(auto_error=False)


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


class TokenData(BaseModel):
    """Decoded token data"""
    username: str
    exp: datetime


def create_access_token(username: str) -> tuple[str, int]:
    """
    Create JWT access token
    Returns: (token, expires_in_seconds)
    """
    expires_delta = timedelta(hours=JWT_EXPIRATION_HOURS)
    expire = datetime.utcnow() + expires_delta

    payload = {
        "sub": username,
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "access"
    }

    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    expires_in = int(expires_delta.total_seconds())

    return token, expires_in


def verify_token(token: str) -> Optional[TokenData]:
    """Verify JWT token and return token data"""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
        exp = datetime.fromtimestamp(payload.get("exp"))

        if username is None:
            return None

        return TokenData(username=username, exp=exp)
    except jwt.ExpiredSignatureError:
        logger.warning("Token expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.warning("Invalid token", error=str(e))
        return None


def authenticate_user(username: str, password: str) -> bool:
    """Validate admin credentials"""
    return username == ADMIN_USERNAME and password == ADMIN_PASSWORD


async def get_current_admin(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security)
) -> TokenData:
    """
    Dependency to get current authenticated admin user
    Raises 401 if not authenticated or token invalid
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token_data = verify_token(credentials.credentials)

    if token_data is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return token_data


async def get_optional_admin(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security)
) -> Optional[TokenData]:
    """
    Dependency to optionally get admin user
    Returns None if not authenticated (doesn't raise error)
    Used for endpoints that work differently for admin vs public
    """
    if credentials is None:
        return None

    return verify_token(credentials.credentials)


def login(username: str, password: str) -> LoginResponse:
    """
    Authenticate user and return access token
    """
    if not authenticate_user(username, password):
        logger.warning("Failed login attempt", username=username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    token, expires_in = create_access_token(username)

    logger.info("Admin login successful", username=username)

    return LoginResponse(
        access_token=token,
        token_type="bearer",
        expires_in=expires_in,
        username=username
    )
