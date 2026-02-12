"""
Scanner orchestrator for managing multiple security scanners.

Enterprise-grade: preflight checks, per-scanner retry, explicit
tracking of requested vs succeeded vs failed scanners.
"""
import time
import logging
from typing import Dict, Any, List, Optional, Callable
from concurrent.futures import ThreadPoolExecutor, Future
from .grype_scanner import GrypeScanner
from .trivy_scanner import TrivyScanner
from .syft_scanner import SyftScanner

logger = logging.getLogger(__name__)

_MAX_RETRIES = 2
_RETRY_DELAY_SECONDS = 5


class ScannerOrchestrator:
    """Orchestrates multiple security scanners and merges results"""

    def __init__(self):
        from app.config import settings
        self.settings = settings
        self.logger = logging.getLogger(__name__)

        # Only instantiate enabled scanners
        self.grype = GrypeScanner() if settings.ENABLE_GRYPE else None
        self.trivy = TrivyScanner() if settings.ENABLE_TRIVY else None
        self.syft = SyftScanner() if settings.ENABLE_SYFT else None

        # Run preflights — log warnings but don't block (DB update task may fix later)
        self._preflight_status: Dict[str, Dict[str, Any]] = {}
        for name, scanner in self._enabled_scanners():
            ok, err = scanner.preflight()
            self._preflight_status[name] = {"ok": ok, "error": err}
            if not ok:
                self.logger.warning(
                    f"Preflight FAILED for {name}: {err}  "
                    "(scanner will still be attempted — may recover)"
                )
            else:
                self.logger.info(f"Preflight OK for {name}")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _enabled_scanners(self):
        """Yield (name, instance) for each enabled scanner."""
        if self.grype:
            yield "grype", self.grype
        if self.trivy:
            yield "trivy", self.trivy
        if self.syft:
            yield "syft", self.syft

    @staticmethod
    def _run_with_retry(
        fn: Callable,
        args: tuple,
        scanner_name: str,
        max_retries: int = _MAX_RETRIES,
    ) -> Dict[str, Any]:
        """
        Execute *fn(*args)* up to *max_retries + 1* times.

        If the callable returns a dict with ``success == True`` on any
        attempt the result is returned immediately.  Otherwise the last
        failure dict is returned with an ``attempts`` count.
        """
        last_result: Dict[str, Any] = {}
        for attempt in range(1, max_retries + 2):  # 1-indexed, inclusive
            try:
                result = fn(*args)
            except Exception as exc:
                result = {
                    "success": False,
                    "error": f"{scanner_name} exception: {exc}",
                    "scanner": scanner_name,
                }

            # Check for success — format varies between scan() and generate_sbom()
            succeeded = (
                result.get("success") is True
                or result.get("syft-json", {}).get("success") is True
            )
            if succeeded:
                result["attempts"] = attempt
                return result

            last_result = result
            logger.warning(
                f"{scanner_name} attempt {attempt}/{max_retries + 1} failed: "
                f"{result.get('error', 'unknown')}"
            )
            if attempt <= max_retries:
                time.sleep(_RETRY_DELAY_SECONDS)

        last_result["attempts"] = max_retries + 1
        return last_result

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def run_all_scans(
        self,
        image_name: str,
        scan_id: str,
        base_output_dir: str = "/tmp",
        sbom_output_dir: str = "/var/www/html/sboms",
        timeout: int = 300,
    ) -> Dict[str, Any]:
        """
        Run enabled scanners in parallel with retry and merge results.

        Returns merged dict that always contains:
        - scanners_requested: list of scanners that were attempted
        - scanners_used: list of scanners that succeeded
        - scanners_failed: dict mapping failed scanner name → error string
        """
        scanners_requested = [name for name, _ in self._enabled_scanners()]

        self.logger.info(
            f"Starting orchestrated scan for {image_name} (ID: {scan_id}), "
            f"scanners_requested: {scanners_requested}"
        )

        futures: Dict[str, Future] = {}
        active_workers = max(len(scanners_requested), 1)

        with ThreadPoolExecutor(max_workers=active_workers) as executor:
            if self.grype:
                futures["grype"] = executor.submit(
                    self._run_with_retry,
                    self.grype.scan,
                    (image_name, f"{base_output_dir}/{scan_id}_grype.json", timeout),
                    "grype",
                )

            if self.trivy:
                futures["trivy"] = executor.submit(
                    self._run_with_retry,
                    self.trivy.scan,
                    (image_name, f"{base_output_dir}/{scan_id}_trivy.json", timeout),
                    "trivy",
                )

            if self.syft:
                futures["syft"] = executor.submit(
                    self._run_with_retry,
                    self.syft.generate_sbom,
                    (
                        image_name,
                        ["spdx-json", "cyclonedx-json", "syft-json"],
                        sbom_output_dir,
                        scan_id,
                        timeout,
                    ),
                    "syft",
                )

            # Collect — disabled scanners get a sentinel result
            grype_result = self._collect(futures.get("grype"), "grype")
            trivy_result = self._collect(futures.get("trivy"), "trivy")
            syft_result = self._collect(futures.get("syft"), "syft")

        self.logger.info("All scanners completed, merging results...")

        merged = self.merge_results(
            grype_result, trivy_result, syft_result, scan_id
        )

        # Attach requested / failed metadata
        merged["scanners_requested"] = scanners_requested
        scanners_failed = {}
        for name in scanners_requested:
            if name not in merged["scanners_used"]:
                scanners_failed[name] = merged["summary"].get(name, {}).get(
                    "error", "Unknown error"
                )
        merged["scanners_failed"] = scanners_failed

        self.logger.info(
            f"Scan complete — "
            f"requested={scanners_requested}, "
            f"used={merged['scanners_used']}, "
            f"failed={list(scanners_failed.keys())}, "
            f"unique CVEs={merged['total_unique_vulnerabilities']}, "
            f"secrets={merged['total_secrets']}, "
            f"packages={merged.get('sbom', {}).get('statistics', {}).get('total_packages', 0)}"
        )

        return merged

    # ------------------------------------------------------------------
    # Future collection
    # ------------------------------------------------------------------

    def _collect(self, future: Optional[Future], name: str) -> Dict[str, Any]:
        """Safely collect a scanner future result."""
        if future is None:
            self.logger.info(f"{name} scanner is disabled, skipping")
            return {"success": False, "error": "Scanner disabled via configuration"}
        try:
            return future.result()
        except Exception as exc:
            self.logger.error(f"{name} scanner raised an unhandled exception: {exc}")
            return {"success": False, "error": f"{name} exception: {exc}"}

    # ------------------------------------------------------------------
    # Result merging (unchanged logic, cleaner structure)
    # ------------------------------------------------------------------

    def merge_results(
        self,
        grype_result: Dict[str, Any],
        trivy_result: Dict[str, Any],
        syft_result: Dict[str, Any],
        scan_id: str,
    ) -> Dict[str, Any]:
        """Merge and deduplicate results from all scanners."""
        merged: Dict[str, Any] = {
            "scan_id": scan_id,
            "scanners_used": [],
            "vulnerabilities": {
                "all": [],
                "by_source": {
                    "grype_only": [],
                    "trivy_only": [],
                    "both_scanners": [],
                },
            },
            "secrets": [],
            "sbom": {},
            "summary": {
                "grype": {"success": False, "count": 0},
                "trivy": {"success": False, "count": 0},
                "syft": {"success": False},
            },
        }

        # --- Grype ---
        if grype_result.get("success"):
            merged["scanners_used"].append("grype")
            merged["summary"]["grype"]["success"] = True
            merged["summary"]["grype"]["count"] = grype_result.get("total_vulnerabilities", 0)
            grype_vulns = grype_result.get("vulnerabilities", [])
        else:
            grype_vulns = []
            merged["summary"]["grype"]["error"] = grype_result.get("error", "Unknown error")

        # --- Trivy ---
        if trivy_result.get("success"):
            merged["scanners_used"].append("trivy")
            merged["summary"]["trivy"]["success"] = True
            merged["summary"]["trivy"]["count"] = trivy_result.get("total_vulnerabilities", 0)
            trivy_vulns = trivy_result.get("vulnerabilities", [])
            merged["secrets"] = trivy_result.get("secrets", [])
        else:
            trivy_vulns = []
            merged["summary"]["trivy"]["error"] = trivy_result.get("error", "Unknown error")

        # --- Syft ---
        if syft_result.get("syft-json", {}).get("success") or syft_result.get("success"):
            merged["scanners_used"].append("syft")
            merged["summary"]["syft"]["success"] = True
            merged["sbom"] = {
                "formats": syft_result,
                "statistics": syft_result.get("statistics", {}),
            }
        else:
            merged["summary"]["syft"]["error"] = syft_result.get("error", "Unknown error")

        # --- Deduplicate & count ---
        merged_vulns = self._deduplicate_vulnerabilities(grype_vulns, trivy_vulns)
        merged["vulnerabilities"]["all"] = merged_vulns["all"]
        merged["vulnerabilities"]["by_source"] = merged_vulns["by_source"]
        merged["severity_counts"] = self._calculate_severity_counts(merged_vulns["all"])
        merged["total_unique_vulnerabilities"] = len(merged_vulns["all"])
        merged["total_secrets"] = len(merged["secrets"])
        merged["grype_unique_count"] = len(merged_vulns["by_source"]["grype_only"])
        merged["trivy_unique_count"] = len(merged_vulns["by_source"]["trivy_only"])
        merged["both_scanners_count"] = len(merged_vulns["by_source"]["both_scanners"])
        merged["fixable_counts"] = self._calculate_fixable_counts(merged_vulns["all"])

        return merged

    # ------------------------------------------------------------------
    # Vulnerability deduplication & counting helpers
    # ------------------------------------------------------------------

    def _deduplicate_vulnerabilities(
        self,
        grype_vulns: List[Dict],
        trivy_vulns: List[Dict],
    ) -> Dict[str, Any]:
        """Deduplicate vulnerabilities found by multiple scanners."""
        grype_map = {f"{v['id']}:{v['package_name']}": v for v in grype_vulns}
        trivy_map = {f"{v['id']}:{v['package_name']}": v for v in trivy_vulns}

        all_keys = set(grype_map) | set(trivy_map)
        result: Dict[str, Any] = {
            "all": [],
            "by_source": {"grype_only": [], "trivy_only": [], "both_scanners": []},
        }

        for key in all_keys:
            in_grype = key in grype_map
            in_trivy = key in trivy_map

            if in_grype and in_trivy:
                vuln = grype_map[key].copy()
                vuln["found_by"] = ["grype", "trivy"]
                vuln["confidence"] = "high"
                if "secrets" in trivy_map[key]:
                    vuln["trivy_additional_data"] = trivy_map[key]
                result["all"].append(vuln)
                result["by_source"]["both_scanners"].append(vuln)
            elif in_grype:
                vuln = grype_map[key].copy()
                vuln["found_by"] = ["grype"]
                vuln["confidence"] = "medium"
                result["all"].append(vuln)
                result["by_source"]["grype_only"].append(vuln)
            elif in_trivy:
                vuln = trivy_map[key].copy()
                vuln["found_by"] = ["trivy"]
                vuln["confidence"] = "medium"
                result["all"].append(vuln)
                result["by_source"]["trivy_only"].append(vuln)

        return result

    def _calculate_severity_counts(self, vulnerabilities: List[Dict]) -> Dict[str, int]:
        """Calculate severity counts from vulnerability list."""
        severity_map = {
            "CRITICAL": "Critical", "Critical": "Critical",
            "HIGH": "High", "High": "High",
            "MEDIUM": "Medium", "Medium": "Medium",
            "LOW": "Low", "Low": "Low",
            "NEGLIGIBLE": "Negligible", "Negligible": "Negligible",
            "UNKNOWN": "Unknown", "Unknown": "Unknown",
        }
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Negligible": 0, "Unknown": 0}
        for vuln in vulnerabilities:
            normalized = severity_map.get(vuln.get("severity", "Unknown"), "Unknown")
            counts[normalized] += 1
        return counts

    def _calculate_fixable_counts(self, vulnerabilities: List[Dict]) -> Dict[str, int]:
        """Calculate counts of vulnerabilities with available fixes."""
        fixable = [v for v in vulnerabilities if v.get("fix_available", False)]
        counts = {
            "Critical": sum(1 for v in fixable if v.get("severity") in ("Critical", "CRITICAL")),
            "High": sum(1 for v in fixable if v.get("severity") in ("High", "HIGH")),
            "Medium": sum(1 for v in fixable if v.get("severity") in ("Medium", "MEDIUM")),
            "Low": sum(1 for v in fixable if v.get("severity") in ("Low", "LOW")),
            "Negligible": sum(1 for v in fixable if v.get("severity") in ("Negligible", "NEGLIGIBLE")),
            "Unknown": sum(1 for v in fixable if v.get("severity") in ("Unknown", "UNKNOWN")),
        }
        counts["total"] = len(fixable)
        return counts
