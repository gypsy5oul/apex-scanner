"""
Base scanner class for all vulnerability scanners
"""
import shutil
import subprocess
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


class BaseScanner(ABC):
    """Abstract base class for all vulnerability scanners"""

    def __init__(self, scanner_name: str):
        self.scanner_name = scanner_name
        self.logger = logging.getLogger(f"{__name__}.{scanner_name}")

    @abstractmethod
    def scan(self, image_name: str, output_path: str, timeout: int = 300) -> Dict[str, Any]:
        """
        Perform vulnerability scan on the given image

        Args:
            image_name: Docker image to scan
            output_path: Path to save scan output
            timeout: Scan timeout in seconds

        Returns:
            Dictionary containing scan results
        """
        pass

    @abstractmethod
    def parse_results(self, raw_output: str) -> Dict[str, Any]:
        """
        Parse raw scanner output into standardized format

        Args:
            raw_output: Raw output from scanner

        Returns:
            Standardized vulnerability data
        """
        pass

    def validate_image_name(self, image_name: str) -> bool:
        """
        Validate Docker image name format

        Args:
            image_name: Image name to validate

        Returns:
            True if valid, False otherwise
        """
        import re
        # Basic Docker image name validation
        pattern = r'^[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*(:[a-z0-9_.-]+)?(@sha256:[a-f0-9]{64})?$'
        return bool(re.match(pattern, image_name.lower()))

    def preflight(self) -> Tuple[bool, Optional[str]]:
        """
        Verify the scanner binary is installed and can execute.

        Subclasses should call super().preflight() first, then add
        scanner-specific checks (e.g. DB presence).

        Returns:
            (True, None) if healthy, (False, error_message) otherwise
        """
        binary_path = shutil.which(self.scanner_name)
        if not binary_path:
            return False, f"{self.scanner_name} binary not found in PATH"

        try:
            result = subprocess.run(
                [self.scanner_name, "version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return False, (
                    f"{self.scanner_name} version check failed "
                    f"(exit {result.returncode}): {result.stderr.strip()}"
                )
        except subprocess.TimeoutExpired:
            return False, f"{self.scanner_name} version check timed out"
        except OSError as exc:
            return False, f"{self.scanner_name} cannot execute: {exc}"

        return True, None

    def get_scanner_version(self) -> Optional[str]:
        """
        Get the version of the scanner binary

        Returns:
            Version string or None if unavailable
        """
        try:
            result = subprocess.run(
                [self.scanner_name, "version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.stdout.strip() if result.returncode == 0 else None
        except Exception as e:
            self.logger.warning(f"Could not get scanner version: {e}")
            return None
