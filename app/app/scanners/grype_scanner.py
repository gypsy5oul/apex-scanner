"""
Grype vulnerability scanner implementation
"""
import glob
import json
import os
import shutil
import subprocess
from typing import Dict, Any, Optional, Tuple
from .base import BaseScanner
from .normalization import normalize_cvss


class GrypeScanner(BaseScanner):
    """Grype vulnerability scanner"""

    def __init__(self):
        super().__init__("grype")

    def preflight(self) -> Tuple[bool, Optional[str]]:
        """Check grype binary exists AND vulnerability DB is loaded.

        If the DB is stale or missing, attempt an automatic update
        (best-effort, capped at 120 s) so the scan can proceed.
        """
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
                self.logger.warning(
                    f"Grype DB stale/missing ({result.stderr.strip()}), "
                    "attempting automatic update..."
                )
                update = subprocess.run(
                    ["grype", "db", "update"],
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                if update.returncode != 0:
                    return False, (
                        f"Grype DB update failed: {update.stderr.strip()}"
                    )
                self.logger.info("Grype DB updated successfully during preflight")
                # `grype db update` leaves stale grype-db-download* dirs in the
                # cache, each ~1.5GB. Without this, a worker running for weeks
                # accumulates hundreds of them and fills the disk.
                self._cleanup_stale_db_downloads()
        except subprocess.TimeoutExpired:
            return False, "Grype DB check/update timed out"
        except OSError as exc:
            return False, f"Grype DB check failed: {exc}"

        return True, None

    def _cleanup_stale_db_downloads(self) -> None:
        """Remove leftover grype-db-download* dirs from previous updates.

        Grype writes each DB download into a fresh `grype-db-download<rand>`
        directory and only renames the active one into `db/<schema>/`. The
        stale dirs are ~1.5GB each and otherwise persist forever.
        """
        cache_dir = os.environ.get(
            "GRYPE_DB_CACHE_DIR", "/home/scanner/.cache/grype/db"
        )
        removed = 0
        for path in glob.glob(os.path.join(cache_dir, "grype-db-download*")):
            try:
                shutil.rmtree(path, ignore_errors=True)
                removed += 1
            except OSError:
                pass
        if removed:
            self.logger.info(
                f"Cleaned up {removed} stale grype-db-download dirs from {cache_dir}"
            )

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

            # Flags first, then `--`, then the image as a positional arg.
            # The `--` stops Grype's flag parser, so an image reference that
            # somehow starts with '-' can never be interpreted as a CLI flag
            # (defense-in-depth alongside the API-layer image validator).
            command = [
                "grype",
                "-o", "json",
                "--scope", "all-layers",
                "--",
                image_name,
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

                # Extract CVSS score (normalized to float | None — never "N/A")
                cvss_data = vuln_data.get("cvss", [])
                cvss_score = None
                if cvss_data:
                    cvss_score = normalize_cvss(
                        cvss_data[0].get("metrics", {}).get("baseScore")
                    )

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
