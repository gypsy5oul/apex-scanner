"""
Application configuration using Pydantic Settings
"""
import os
import ssl
from typing import List, Optional
from urllib.parse import urlparse, urlunparse
from pydantic_settings import BaseSettings
from pydantic import Field, computed_field
import redis


class Settings(BaseSettings):
    """Application settings with environment variable support"""

    # Redis configuration
    REDIS_URL: str = Field(
        default="redis://redis:6379/0",
        description="Redis connection URL"
    )
    REDIS_MAX_CONNECTIONS: int = Field(
        default=50,
        description="Maximum Redis connection pool size"
    )
    REDIS_PASSWORD: Optional[str] = Field(
        default=None,
        description="Redis authentication password"
    )
    REDIS_TLS_ENABLED: bool = Field(
        default=False,
        description="Enable TLS for Redis connections"
    )
    REDIS_TLS_CERT_PATH: Optional[str] = Field(
        default=None,
        description="Path to Redis TLS client certificate"
    )
    REDIS_TLS_KEY_PATH: Optional[str] = Field(
        default=None,
        description="Path to Redis TLS client key"
    )
    REDIS_TLS_CA_PATH: Optional[str] = Field(
        default=None,
        description="Path to Redis TLS CA certificate"
    )
    SCAN_RESULT_TTL: int = Field(
        default=2592000,  # 30 days in seconds
        description="TTL for scan results in Redis"
    )

    # Directory configuration
    REPORTS_DIR: str = Field(
        default="/var/www/html/reports",
        description="Directory for HTML reports"
    )
    SBOMS_DIR: str = Field(
        default="/var/www/html/sboms",
        description="Directory for SBOM files"
    )

    # Server configuration
    SERVER_HOST: str = Field(
        default="http://localhost:7070",
        description="Public server URL for report links"
    )
    SCAN_TIMEOUT: int = Field(
        default=900,
        description="Scan timeout in seconds (15 min for parallel scans)"
    )

    # CORS configuration
    CORS_ORIGINS: str = Field(
        default="",
        description="Comma-separated list of allowed CORS origins (empty = no CORS)"
    )

    # Scanner feature flags
    ENABLE_GRYPE: bool = Field(
        default=True,
        description="Enable Grype scanner"
    )
    ENABLE_TRIVY: bool = Field(
        default=True,
        description="Enable Trivy scanner"
    )
    ENABLE_SYFT: bool = Field(
        default=True,
        description="Enable Syft SBOM generator"
    )

    # Logging configuration
    LOG_LEVEL: str = Field(
        default="INFO",
        description="Logging level"
    )
    LOG_FORMAT: str = Field(
        default="json",
        description="Log format (json or console)"
    )

    # Batch scanning limits
    BATCH_MAX_IMAGES: int = Field(
        default=50,
        description="Maximum images per batch scan"
    )
    BATCH_CONCURRENT_SCANS: int = Field(
        default=5,
        description="Concurrent scans in batch mode"
    )

    # Metrics configuration
    ENABLE_METRICS: bool = Field(
        default=True,
        description="Enable Prometheus metrics"
    )
    METRICS_PATH: str = Field(
        default="/metrics",
        description="Path for Prometheus metrics endpoint"
    )

    # History configuration
    MAX_HISTORY_PER_IMAGE: int = Field(
        default=100,
        description="Maximum scan history entries per image"
    )

    # Cleanup configuration
    ARTIFACT_RETENTION_DAYS: int = Field(
        default=7,
        description="Days to retain SBOM/report files before cleanup"
    )

    # Authentication configuration
    ADMIN_USERNAME: str = Field(
        default="admin",
        description="Admin username"
    )
    ADMIN_PASSWORD_HASH: str = Field(
        default="",
        description="Bcrypt hash of admin password. Generate with: python -c \"import bcrypt; print(bcrypt.hashpw(b'yourpassword', bcrypt.gensalt()).decode())\""
    )
    # Legacy plaintext password (used only for hash migration)
    ADMIN_PASSWORD: str = Field(
        default="",
        description="[DEPRECATED] Plaintext admin password - will be rejected at startup. Use ADMIN_PASSWORD_HASH instead."
    )

    # Normal user authentication (optional - empty = disabled)
    USER_USERNAME: str = Field(
        default="",
        description="Normal user username (empty = user account disabled)"
    )
    USER_PASSWORD_HASH: str = Field(
        default="",
        description="Bcrypt hash of normal user password"
    )
    JWT_SECRET_KEY: str = Field(
        default="",
        description="Secret key for JWT token signing. MUST be changed from default."
    )
    JWT_EXPIRATION_HOURS: int = Field(
        default=24,
        description="JWT token expiration in hours"
    )

    # Rate limiting
    LOGIN_MAX_ATTEMPTS: int = Field(
        default=5,
        description="Maximum login attempts before lockout"
    )
    LOGIN_LOCKOUT_SECONDS: int = Field(
        default=900,
        description="Lockout duration in seconds after max failed attempts"
    )

    # API key configuration
    API_KEY_ENABLED: bool = Field(
        default=True,
        description="Enable API key authentication for CI/CD"
    )

    @property
    def effective_redis_url(self) -> str:
        """Build Redis URL with authentication and TLS scheme."""
        parsed = urlparse(self.REDIS_URL)

        # Inject password if configured
        netloc = parsed.hostname or "redis"
        port = parsed.port or 6379
        if self.REDIS_PASSWORD:
            netloc = f":{self.REDIS_PASSWORD}@{netloc}"
        netloc = f"{netloc}:{port}"

        # Switch to rediss:// scheme for TLS
        scheme = "rediss" if self.REDIS_TLS_ENABLED else parsed.scheme

        return urlunparse((scheme, netloc, parsed.path or "/0", "", "", ""))

    @property
    def cors_origins_list(self) -> List[str]:
        """Parse CORS_ORIGINS into a list."""
        if not self.CORS_ORIGINS:
            return []
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]

    @property
    def redis_ssl_context(self) -> Optional[ssl.SSLContext]:
        """Build SSL context for Redis TLS connections."""
        if not self.REDIS_TLS_ENABLED:
            return None

        ctx = ssl.create_default_context(cafile=self.REDIS_TLS_CA_PATH)
        if self.REDIS_TLS_CERT_PATH and self.REDIS_TLS_KEY_PATH:
            ctx.load_cert_chain(
                certfile=self.REDIS_TLS_CERT_PATH,
                keyfile=self.REDIS_TLS_KEY_PATH,
            )
        return ctx

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True
        extra = "ignore"


# Global settings instance
settings = Settings()

# Singleton Redis connection pool
_redis_pool: Optional[redis.ConnectionPool] = None


def get_redis_pool() -> redis.ConnectionPool:
    """Get or create the singleton Redis connection pool with auth/TLS support."""
    global _redis_pool
    if _redis_pool is None:
        pool_kwargs = {
            "max_connections": settings.REDIS_MAX_CONNECTIONS,
            "decode_responses": True,
        }

        if settings.REDIS_TLS_ENABLED:
            pool_kwargs["connection_class"] = redis.SSLConnection
            if settings.REDIS_TLS_CA_PATH:
                pool_kwargs["ssl_ca_certs"] = settings.REDIS_TLS_CA_PATH
            if settings.REDIS_TLS_CERT_PATH:
                pool_kwargs["ssl_certfile"] = settings.REDIS_TLS_CERT_PATH
            if settings.REDIS_TLS_KEY_PATH:
                pool_kwargs["ssl_keyfile"] = settings.REDIS_TLS_KEY_PATH

        _redis_pool = redis.ConnectionPool.from_url(
            settings.effective_redis_url,
            **pool_kwargs,
        )
    return _redis_pool


def get_redis_client() -> redis.Redis:
    """Get a Redis client backed by the singleton connection pool."""
    return redis.Redis(connection_pool=get_redis_pool())
