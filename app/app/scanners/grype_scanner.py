"""
Grype vulnerability scanner implementation
"""
import json
import os
import subprocess
from typing import Dict, Any, Optional, Tuple
from .base import BaseScanner


class GrypeScanner(BaseScanner):
    """Grype vulnerability scanner"""

    def __init__(self):
        super().__init__("grype")

    def preflight(self) -> Tuple[bool, Optional[str]]:
        """Check grype binary exists AND vulnerability DB is loaded."""
        ok, err = super().preflight()
        if not ok:
            return ok, err

        # Verify vulnerability DB is present and not stale
        try:
            result = subprocess.run(
                ["grype", "db", "check"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode != 0:
                return False, (
                    f"Grype DB missing or stale: {result.stderr.strip()}. "
                    "Run: grype db update"
                )
        except subprocess.TimeoutExpired:
            return False, "Grype DB check timed out"
        except OSError as exc:
            return False, f"Grype DB check failed: {exc}"

        return True, None

    def scan(self, image_name: str, output_path: str, timeout: int = 300) -> Dict[str, Any]:
        """
        Perform Grype vulnerability scan

        Args:
            image_name: Docker image to scan
            output_path: Path to save JSON output
            timeout: Scan timeout in seconds

        Returns:
            Dictionary with scan status and results
        """
        try:
            self.logger.info(f"Starting Grype scan for: {image_name}")

            command = [
                "grype",
                image_name,
                "-o", "json",
                "--scope", "all-layers"
            ]

            # Disable auto DB update during scans to avoid failures on low disk.
            # DB updates are handled by the scheduled Celery task instead.
            env = os.environ.copy()
            env["GRYPE_DB_AUTO_UPDATE"] = "false"

            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env
            )

            if result.returncode != 0:
                error_msg = f"Grype scan failed: {result.stderr}"
                self.logger.error(error_msg)
                return {
                    "success": False,
                    "error": error_msg,
                    "scanner": self.scanner_name
                }

            # Save raw output
            with open(output_path, "w") as f:
                f.write(result.stdout)

            # Parse and return results
            parsed = self.parse_results(result.stdout)
            parsed["success"] = True
            parsed["scanner"] = self.scanner_name

            self.logger.info(f"Grype scan completed: {len(parsed.get('vulnerabilities', []))} vulnerabilities found")
            return parsed

        except subprocess.TimeoutExpired:
            error_msg = f"Grype scan timed out after {timeout} seconds"
            self.logger.error(error_msg)
            return {"success": False, "error": error_msg, "scanner": self.scanner_name}
        except Exception as e:
            error_msg = f"Grype scan error: {str(e)}"
            self.logger.error(error_msg)
            return {"success": False, "error": error_msg, "scanner": self.scanner_name}

    def parse_results(self, raw_output: str) -> Dict[str, Any]:
        """
        Parse Grype JSON output into standardized format

        Args:
            raw_output: Raw JSON output from Grype

        Returns:
            Standardized vulnerability data
        """
        try:
            data = json.loads(raw_output)
            vulnerabilities = []

            for match in data.get("matches", []):
                vuln_data = match.get("vulnerability", {})
                artifact_data = match.get("artifact", {})

                # Extract CVSS score
                cvss_data = vuln_data.get("cvss", [])
                cvss_score = "N/A"
                if cvss_data:
                    cvss_score = cvss_data[0].get("metrics", {}).get("baseScore", "N/A")

                vuln = {
                    "id": vuln_data.get("id", "N/A"),
                    "severity": vuln_data.get("severity", "Unknown"),
                    "package_name": artifact_data.get("name", "Unknown"),
                    "package_version": artifact_data.get("version", "N/A"),
                    "package_type": artifact_data.get("type", "N/A"),
                    "description": vuln_data.get("description", "No description available"),
                    "cvss_score": cvss_score,
                    "fix_available": bool(vuln_data.get("fix", {}).get("versions", [])),
                    "fix_versions": vuln_data.get("fix", {}).get("versions", []),
                    "urls": vuln_data.get("urls", []),
                    "source": "grype"
                }
                vulnerabilities.append(vuln)

            # Calculate severity counts
            severity_counts = {
                "Critical": sum(1 for v in vulnerabilities if v["severity"] == "Critical"),
                "High": sum(1 for v in vulnerabilities if v["severity"] == "High"),
                "Medium": sum(1 for v in vulnerabilities if v["severity"] == "Medium"),
                "Low": sum(1 for v in vulnerabilities if v["severity"] == "Low"),
                "Negligible": sum(1 for v in vulnerabilities if v["severity"] == "Negligible"),
                "Unknown": sum(1 for v in vulnerabilities if v["severity"] == "Unknown")
            }

            return {
                "vulnerabilities": vulnerabilities,
                "total_vulnerabilities": len(vulnerabilities),
                "severity_counts": severity_counts,
                "raw_data": data
            }

        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse Grype JSON: {e}")
            return {
                "vulnerabilities": [],
                "total_vulnerabilities": 0,
                "severity_counts": {},
                "error": f"JSON parse error: {str(e)}"
            }
