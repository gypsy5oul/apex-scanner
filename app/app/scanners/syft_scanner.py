"""
Syft SBOM generator implementation
"""
import json
import subprocess
from typing import Dict, Any, List
from .base import BaseScanner


class SyftScanner(BaseScanner):
    """Syft Software Bill of Materials (SBOM) generator"""

    def __init__(self):
        super().__init__("syft")

    def generate_sbom(
        self,
        image_name: str,
        output_formats: List[str] = None,
        output_dir: str = "/var/www/html/sboms",
        scan_id: str = None,
        timeout: int = 300
    ) -> Dict[str, Any]:
        """
        Generate SBOM in multiple formats

        Args:
            image_name: Docker image to scan
            output_formats: List of formats (spdx-json, cyclonedx-json, syft-json)
            output_dir: Directory to save SBOM files
            scan_id: Scan ID for file naming
            timeout: Scan timeout in seconds

        Returns:
            Dictionary with SBOM generation status and file paths
        """
        if output_formats is None:
            output_formats = ["spdx-json", "cyclonedx-json", "syft-json"]

        try:
            self.logger.info(f"Generating SBOM for: {image_name}")

            results = {}
            for fmt in output_formats:
                output_path = f"{output_dir}/{scan_id}_{fmt.replace('-', '_')}.json"

                command = [
                    "syft",
                    image_name,
                    "-o", fmt,
                    "--file", output_path
                ]

                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )

                if result.returncode == 0:
                    results[fmt] = {
                        "success": True,
                        "file_path": output_path,
                        "format": fmt
                    }
                    self.logger.info(f"SBOM generated successfully: {fmt}")
                else:
                    results[fmt] = {
                        "success": False,
                        "error": result.stderr,
                        "format": fmt
                    }
                    self.logger.error(f"SBOM generation failed for {fmt}: {result.stderr}")

            # Parse the syft-json format for statistics
            if "syft-json" in results and results["syft-json"]["success"]:
                with open(results["syft-json"]["file_path"], "r") as f:
                    sbom_data = json.loads(f.read())
                    stats = self._extract_statistics(sbom_data)
                    results["statistics"] = stats

            results["scanner"] = self.scanner_name
            return results

        except subprocess.TimeoutExpired:
            error_msg = f"SBOM generation timed out after {timeout} seconds"
            self.logger.error(error_msg)
            return {"success": False, "error": error_msg, "scanner": self.scanner_name}
        except Exception as e:
            error_msg = f"SBOM generation error: {str(e)}"
            self.logger.error(error_msg)
            return {"success": False, "error": error_msg, "scanner": self.scanner_name}

    def scan(self, image_name: str, output_path: str, timeout: int = 300) -> Dict[str, Any]:
        """
        Generate SBOM (compatibility with BaseScanner interface)

        Args:
            image_name: Docker image to scan
            output_path: Path to save SBOM output
            timeout: Scan timeout in seconds

        Returns:
            Dictionary with SBOM data
        """
        try:
            command = [
                "syft",
                image_name,
                "-o", "syft-json"
            ]

            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            if result.returncode != 0:
                error_msg = f"Syft SBOM generation failed: {result.stderr}"
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

            self.logger.info(f"SBOM generated: {parsed.get('total_packages', 0)} packages found")
            return parsed

        except subprocess.TimeoutExpired:
            error_msg = f"Syft timed out after {timeout} seconds"
            self.logger.error(error_msg)
            return {"success": False, "error": error_msg, "scanner": self.scanner_name}
        except Exception as e:
            error_msg = f"Syft error: {str(e)}"
            self.logger.error(error_msg)
            return {"success": False, "error": error_msg, "scanner": self.scanner_name}

    def parse_results(self, raw_output: str) -> Dict[str, Any]:
        """
        Parse Syft JSON output

        Args:
            raw_output: Raw JSON output from Syft

        Returns:
            Parsed SBOM data with statistics
        """
        try:
            data = json.loads(raw_output)
            stats = self._extract_statistics(data)

            return {
                "sbom_data": data,
                "statistics": stats,
                "total_packages": stats.get("total_packages", 0)
            }

        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse Syft JSON: {e}")
            return {
                "sbom_data": {},
                "statistics": {},
                "total_packages": 0,
                "error": f"JSON parse error: {str(e)}"
            }

    def _extract_statistics(self, sbom_data: Dict) -> Dict[str, Any]:
        """Extract statistics from SBOM data including base image information"""
        artifacts = sbom_data.get("artifacts", [])

        # Count packages by type
        package_types = {}
        for artifact in artifacts:
            pkg_type = artifact.get("type", "unknown")
            package_types[pkg_type] = package_types.get(pkg_type, 0) + 1

        # Count packages by language
        languages = {}
        for artifact in artifacts:
            language = artifact.get("language", "unknown")
            if language and language != "unknown":
                languages[language] = languages.get(language, 0) + 1

        # Extract licenses
        licenses = set()
        for artifact in artifacts:
            artifact_licenses = artifact.get("licenses", [])
            for lic in artifact_licenses:
                if isinstance(lic, str):
                    licenses.add(lic)
                elif isinstance(lic, dict):
                    licenses.add(lic.get("value", "unknown"))

        # Extract base image/distro information
        base_image_info = {}
        distro = sbom_data.get("distro", {})
        if distro:
            base_image_info = {
                "os_name": distro.get("name", "Unknown"),
                "os_version": distro.get("version", "Unknown"),
                "os_pretty_name": distro.get("prettyName", "Unknown"),
                "os_id": distro.get("id", "Unknown"),
                "os_id_like": distro.get("idLike", []),
                "os_cpe": distro.get("cpeName", "Unknown")
            }

        # Extract image metadata
        source = sbom_data.get("source", {})
        image_metadata = {}
        if source and source.get("type") == "image":
            metadata = source.get("metadata", {})
            image_metadata = {
                "image_id": metadata.get("imageID", "Unknown"),
                "image_size": metadata.get("imageSize", 0),
                "manifest_digest": metadata.get("manifestDigest", "Unknown"),
                "layer_count": len(metadata.get("layers", []))
            }

        return {
            "total_packages": len(artifacts),
            "package_types": package_types,
            "languages": languages,
            "unique_licenses": list(licenses),
            "license_count": len(licenses),
            "base_image": base_image_info,
            "image_metadata": image_metadata
        }
