"""
Scanner orchestrator for managing multiple security scanners
"""
import asyncio
import logging
from typing import Dict, Any, List
from concurrent.futures import ThreadPoolExecutor
from .grype_scanner import GrypeScanner
from .trivy_scanner import TrivyScanner
from .syft_scanner import SyftScanner

logger = logging.getLogger(__name__)


class ScannerOrchestrator:
    """Orchestrates multiple security scanners and merges results"""

    def __init__(self):
        self.grype = GrypeScanner()
        self.trivy = TrivyScanner()
        self.syft = SyftScanner()
        self.logger = logging.getLogger(__name__)

    def run_all_scans(
        self,
        image_name: str,
        scan_id: str,
        base_output_dir: str = "/tmp",
        sbom_output_dir: str = "/var/www/html/sboms",
        timeout: int = 300
    ) -> Dict[str, Any]:
        """
        Run all scanners in parallel and merge results

        Args:
            image_name: Docker image to scan
            scan_id: Unique scan identifier
            base_output_dir: Directory for temporary scan outputs
            sbom_output_dir: Directory for SBOM files
            timeout: Timeout for each scanner

        Returns:
            Merged scan results from all scanners
        """
        self.logger.info(f"Starting orchestrated scan for {image_name} (ID: {scan_id})")

        # Use ThreadPoolExecutor for parallel execution
        with ThreadPoolExecutor(max_workers=3) as executor:
            # Submit all scanner tasks
            grype_future = executor.submit(
                self.grype.scan,
                image_name,
                f"{base_output_dir}/{scan_id}_grype.json",
                timeout
            )

            trivy_future = executor.submit(
                self.trivy.scan,
                image_name,
                f"{base_output_dir}/{scan_id}_trivy.json",
                timeout
            )

            syft_future = executor.submit(
                self.syft.generate_sbom,
                image_name,
                ["spdx-json", "cyclonedx-json", "syft-json"],
                sbom_output_dir,
                scan_id,
                timeout
            )

            # Wait for all to complete
            grype_result = grype_future.result()
            trivy_result = trivy_future.result()
            syft_result = syft_future.result()

        self.logger.info("All scanners completed, merging results...")

        # Merge results
        merged = self.merge_results(grype_result, trivy_result, syft_result, scan_id)

        self.logger.info(
            f"Scan complete - Total unique CVEs: {merged['total_unique_vulnerabilities']}, "
            f"Secrets: {merged['total_secrets']}, "
            f"Packages: {merged.get('sbom', {}).get('statistics', {}).get('total_packages', 0)}"
        )

        return merged

    def merge_results(
        self,
        grype_result: Dict[str, Any],
        trivy_result: Dict[str, Any],
        syft_result: Dict[str, Any],
        scan_id: str
    ) -> Dict[str, Any]:
        """
        Merge and deduplicate results from all scanners

        Args:
            grype_result: Results from Grype scanner
            trivy_result: Results from Trivy scanner
            syft_result: Results from Syft SBOM generator
            scan_id: Unique scan identifier

        Returns:
            Merged and deduplicated results
        """
        # Initialize merged structure
        merged = {
            "scan_id": scan_id,
            "scanners_used": [],
            "vulnerabilities": {
                "all": [],
                "by_source": {
                    "grype_only": [],
                    "trivy_only": [],
                    "both_scanners": []
                }
            },
            "secrets": [],
            "sbom": {},
            "summary": {
                "grype": {"success": False, "count": 0},
                "trivy": {"success": False, "count": 0},
                "syft": {"success": False}
            }
        }

        # Process Grype results
        if grype_result.get("success"):
            merged["scanners_used"].append("grype")
            merged["summary"]["grype"]["success"] = True
            merged["summary"]["grype"]["count"] = grype_result.get("total_vulnerabilities", 0)
            grype_vulns = grype_result.get("vulnerabilities", [])
        else:
            grype_vulns = []
            merged["summary"]["grype"]["error"] = grype_result.get("error", "Unknown error")

        # Process Trivy results
        if trivy_result.get("success"):
            merged["scanners_used"].append("trivy")
            merged["summary"]["trivy"]["success"] = True
            merged["summary"]["trivy"]["count"] = trivy_result.get("total_vulnerabilities", 0)
            trivy_vulns = trivy_result.get("vulnerabilities", [])
            merged["secrets"] = trivy_result.get("secrets", [])
        else:
            trivy_vulns = []
            merged["summary"]["trivy"]["error"] = trivy_result.get("error", "Unknown error")

        # Process Syft results
        if syft_result.get("syft-json", {}).get("success") or syft_result.get("success"):
            merged["scanners_used"].append("syft")
            merged["summary"]["syft"]["success"] = True
            merged["sbom"] = {
                "formats": syft_result,
                "statistics": syft_result.get("statistics", {})
            }
        else:
            merged["summary"]["syft"]["error"] = syft_result.get("error", "Unknown error")

        # Deduplicate and categorize vulnerabilities
        merged_vulns = self._deduplicate_vulnerabilities(grype_vulns, trivy_vulns)

        merged["vulnerabilities"]["all"] = merged_vulns["all"]
        merged["vulnerabilities"]["by_source"] = merged_vulns["by_source"]

        # Calculate severity counts from deduplicated vulnerabilities
        severity_counts = self._calculate_severity_counts(merged_vulns["all"])
        merged["severity_counts"] = severity_counts

        # Calculate counts
        merged["total_unique_vulnerabilities"] = len(merged_vulns["all"])
        merged["total_secrets"] = len(merged["secrets"])
        merged["grype_unique_count"] = len(merged_vulns["by_source"]["grype_only"])
        merged["trivy_unique_count"] = len(merged_vulns["by_source"]["trivy_only"])
        merged["both_scanners_count"] = len(merged_vulns["by_source"]["both_scanners"])

        # Fixable vulnerability counts
        fixable_counts = self._calculate_fixable_counts(merged_vulns["all"])
        merged["fixable_counts"] = fixable_counts

        return merged

    def _deduplicate_vulnerabilities(
        self,
        grype_vulns: List[Dict],
        trivy_vulns: List[Dict]
    ) -> Dict[str, Any]:
        """
        Deduplicate vulnerabilities from multiple scanners

        Args:
            grype_vulns: Vulnerabilities from Grype
            trivy_vulns: Vulnerabilities from Trivy

        Returns:
            Dictionary with deduplicated and categorized vulnerabilities
        """
        # Create lookup maps by CVE ID + package name
        grype_map = {
            f"{v['id']}:{v['package_name']}": v
            for v in grype_vulns
        }

        trivy_map = {
            f"{v['id']}:{v['package_name']}": v
            for v in trivy_vulns
        }

        all_keys = set(grype_map.keys()) | set(trivy_map.keys())
        grype_keys = set(grype_map.keys())
        trivy_keys = set(trivy_map.keys())

        result = {
            "all": [],
            "by_source": {
                "grype_only": [],
                "trivy_only": [],
                "both_scanners": []
            }
        }

        for key in all_keys:
            in_grype = key in grype_keys
            in_trivy = key in trivy_keys

            if in_grype and in_trivy:
                # Found by both - merge data and mark as high confidence
                vuln = grype_map[key].copy()
                vuln["found_by"] = ["grype", "trivy"]
                vuln["confidence"] = "high"
                # Prefer Grype's data but add Trivy-specific fields
                if "secrets" in trivy_map[key]:
                    vuln["trivy_additional_data"] = trivy_map[key]
                result["all"].append(vuln)
                result["by_source"]["both_scanners"].append(vuln)

            elif in_grype:
                # Found only by Grype
                vuln = grype_map[key].copy()
                vuln["found_by"] = ["grype"]
                vuln["confidence"] = "medium"
                result["all"].append(vuln)
                result["by_source"]["grype_only"].append(vuln)

            elif in_trivy:
                # Found only by Trivy
                vuln = trivy_map[key].copy()
                vuln["found_by"] = ["trivy"]
                vuln["confidence"] = "medium"
                result["all"].append(vuln)
                result["by_source"]["trivy_only"].append(vuln)

        return result

    def _calculate_severity_counts(self, vulnerabilities: List[Dict]) -> Dict[str, int]:
        """Calculate severity counts from vulnerability list"""
        # Normalize severity levels (Trivy uses UPPERCASE, Grype uses Titlecase)
        severity_map = {
            "CRITICAL": "Critical",
            "Critical": "Critical",
            "HIGH": "High",
            "High": "High",
            "MEDIUM": "Medium",
            "Medium": "Medium",
            "LOW": "Low",
            "Low": "Low",
            "NEGLIGIBLE": "Negligible",
            "Negligible": "Negligible",
            "UNKNOWN": "Unknown",
            "Unknown": "Unknown"
        }

        counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Negligible": 0,
            "Unknown": 0
        }

        for vuln in vulnerabilities:
            severity = vuln.get("severity", "Unknown")
            normalized = severity_map.get(severity, "Unknown")
            counts[normalized] = counts.get(normalized, 0) + 1

        return counts

    def _calculate_fixable_counts(self, vulnerabilities: List[Dict]) -> Dict[str, int]:
        """Calculate counts of vulnerabilities with available fixes"""
        fixable = [v for v in vulnerabilities if v.get("fix_available", False)]

        counts = {
            "Critical": sum(1 for v in fixable if v.get("severity") in ["Critical", "CRITICAL"]),
            "High": sum(1 for v in fixable if v.get("severity") in ["High", "HIGH"]),
            "Medium": sum(1 for v in fixable if v.get("severity") in ["Medium", "MEDIUM"]),
            "Low": sum(1 for v in fixable if v.get("severity") in ["Low", "LOW"]),
            "Negligible": sum(1 for v in fixable if v.get("severity") in ["Negligible", "NEGLIGIBLE"]),
            "Unknown": sum(1 for v in fixable if v.get("severity") in ["Unknown", "UNKNOWN"])
        }

        counts["total"] = len(fixable)
        return counts
