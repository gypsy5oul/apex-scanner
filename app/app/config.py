"""
Application configuration using Pydantic Settings
"""
import os
from typing import Optional
from pydantic_settings import BaseSettings
from pydantic import Field


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

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


# Global settings instance
settings = Settings()
