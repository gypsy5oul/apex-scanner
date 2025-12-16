"""
Trivy vulnerability scanner implementation
"""
import json
import subprocess
from typing import Dict, Any
from .base import BaseScanner


class TrivyScanner(BaseScanner):
    """Trivy all-in-one security scanner"""

    def __init__(self):
        super().__init__("trivy")

    def scan(self, image_name: str, output_path: str, timeout: int = 300) -> Dict[str, Any]:
        """
        Perform Trivy vulnerability scan

        Args:
            image_name: Docker image to scan
            output_path: Path to save JSON output
            timeout: Scan timeout in seconds

        Returns:
            Dictionary with scan status and results
        """
        try:
            self.logger.info(f"Starting Trivy scan for: {image_name}")

            command = [
                "trivy",
                "image",
                "--format", "json",
                "--scanners", "vuln,secret",  # Scan for vulnerabilities and secrets
                "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
                image_name
            ]

            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            if result.returncode != 0:
                error_msg = f"Trivy scan failed: {result.stderr}"
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

            self.logger.info(f"Trivy scan completed: {len(parsed.get('vulnerabilities', []))} vulnerabilities, {len(parsed.get('secrets', []))} secrets found")
            return parsed

        except subprocess.TimeoutExpired:
            error_msg = f"Trivy scan timed out after {timeout} seconds"
            self.logger.error(error_msg)
            return {"success": False, "error": error_msg, "scanner": self.scanner_name}
        except Exception as e:
            error_msg = f"Trivy scan error: {str(e)}"
            self.logger.error(error_msg)
            return {"success": False, "error": error_msg, "scanner": self.scanner_name}

    def parse_results(self, raw_output: str) -> Dict[str, Any]:
        """
        Parse Trivy JSON output into standardized format

        Args:
            raw_output: Raw JSON output from Trivy

        Returns:
            Standardized vulnerability and secret data
        """
        try:
            data = json.loads(raw_output)
            vulnerabilities = []
            secrets = []

            # Parse results from all targets (layers)
            for result in data.get("Results", []):
                # Parse vulnerabilities
                for vuln in result.get("Vulnerabilities", []):
                    vulnerability = {
                        "id": vuln.get("VulnerabilityID", "N/A"),
                        "severity": vuln.get("Severity", "Unknown"),
                        "package_name": vuln.get("PkgName", "Unknown"),
                        "package_version": vuln.get("InstalledVersion", "N/A"),
                        "package_type": result.get("Type", "N/A"),
                        "description": vuln.get("Description", "No description available"),
                        "cvss_score": self._extract_cvss(vuln),
                        "fix_available": bool(vuln.get("FixedVersion")),
                        "fix_versions": [vuln.get("FixedVersion")] if vuln.get("FixedVersion") else [],
                        "urls": vuln.get("References", []),
                        "source": "trivy"
                    }
                    vulnerabilities.append(vulnerability)

                # Parse secrets
                for secret in result.get("Secrets", []):
                    secret_data = {
                        "rule_id": secret.get("RuleID", "Unknown"),
                        "category": secret.get("Category", "Unknown"),
                        "severity": secret.get("Severity", "Unknown"),
                        "title": secret.get("Title", "Secret detected"),
                        "match": secret.get("Match", "***"),
                        "file": result.get("Target", "Unknown"),
                        "line": secret.get("StartLine", 0)
                    }
                    secrets.append(secret_data)

            # Calculate severity counts
            severity_counts = {
                "Critical": sum(1 for v in vulnerabilities if v["severity"] == "CRITICAL"),
                "High": sum(1 for v in vulnerabilities if v["severity"] == "HIGH"),
                "Medium": sum(1 for v in vulnerabilities if v["severity"] == "MEDIUM"),
                "Low": sum(1 for v in vulnerabilities if v["severity"] == "LOW"),
                "Negligible": sum(1 for v in vulnerabilities if v["severity"] == "NEGLIGIBLE"),
                "Unknown": sum(1 for v in vulnerabilities if v["severity"] == "UNKNOWN")
            }

            return {
                "vulnerabilities": vulnerabilities,
                "secrets": secrets,
                "total_vulnerabilities": len(vulnerabilities),
                "total_secrets": len(secrets),
                "severity_counts": severity_counts,
                "raw_data": data
            }

        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse Trivy JSON: {e}")
            return {
                "vulnerabilities": [],
                "secrets": [],
                "total_vulnerabilities": 0,
                "total_secrets": 0,
                "severity_counts": {},
                "error": f"JSON parse error: {str(e)}"
            }

    def _extract_cvss(self, vuln: Dict) -> str:
        """Extract CVSS score from vulnerability data"""
        # Try to get CVSS from various possible locations in Trivy output
        cvss = vuln.get("CVSS", {})

        if isinstance(cvss, dict):
            # Try NVD first
            if "nvd" in cvss:
                nvd_data = cvss["nvd"]
                if isinstance(nvd_data, dict) and "V3Score" in nvd_data:
                    return str(nvd_data["V3Score"])

            # Try other vendors
            for vendor_data in cvss.values():
                if isinstance(vendor_data, dict) and "V3Score" in vendor_data:
                    return str(vendor_data["V3Score"])

        return "N/A"
