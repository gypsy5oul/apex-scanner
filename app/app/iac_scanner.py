"""
IaC (Infrastructure as Code) Scanner
Scans Dockerfiles, Kubernetes manifests, Terraform, etc. using Trivy
"""
import os
import json
import uuid
import shutil
import tempfile
import subprocess
from typing import Optional, List, Dict, Any
from datetime import datetime
from dataclasses import dataclass, asdict
from enum import Enum

from app.logging_config import get_logger

logger = get_logger(__name__)


class IacType(str, Enum):
    DOCKERFILE = "dockerfile"
    KUBERNETES = "kubernetes"
    TERRAFORM = "terraform"
    CLOUDFORMATION = "cloudformation"
    HELM = "helm"
    DOCKER_COMPOSE = "docker-compose"
    ALL = "all"


@dataclass
class IacFinding:
    """Single IaC misconfiguration finding"""
    id: str
    avd_id: str
    title: str
    description: str
    message: str
    severity: str
    resolution: str
    file: str
    start_line: int
    end_line: int
    code_snippet: Optional[str] = None
    primary_url: Optional[str] = None
    references: Optional[List[str]] = None


@dataclass
class IacScanResult:
    """IaC scan result"""
    scan_id: str
    status: str
    scanned_at: str
    scan_type: str
    source: str
    summary: Dict[str, int]
    findings: List[Dict[str, Any]]
    files_scanned: int
    policy_result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class IacScanner:
    """Infrastructure as Code Scanner using Trivy"""

    def __init__(self):
        self.temp_dir = "/tmp/iac_scans"
        os.makedirs(self.temp_dir, exist_ok=True)

    def scan_content(
        self,
        content: str,
        filename: str = "Dockerfile",
        scan_type: IacType = IacType.ALL
    ) -> IacScanResult:
        """Scan IaC content directly (for file upload)"""
        scan_id = str(uuid.uuid4())
        scan_dir = os.path.join(self.temp_dir, scan_id)

        try:
            os.makedirs(scan_dir, exist_ok=True)

            # Write content to file
            file_path = os.path.join(scan_dir, filename)
            with open(file_path, 'w') as f:
                f.write(content)

            # Run scan
            return self._run_trivy_scan(scan_id, scan_dir, f"file:{filename}")

        except Exception as e:
            logger.error(f"IaC scan failed: {e}")
            return IacScanResult(
                scan_id=scan_id,
                status="failed",
                scanned_at=datetime.utcnow().isoformat(),
                scan_type=scan_type.value,
                source=f"file:{filename}",
                summary={"critical": 0, "high": 0, "medium": 0, "low": 0},
                findings=[],
                files_scanned=0,
                error=str(e)
            )
        finally:
            # Cleanup
            if os.path.exists(scan_dir):
                shutil.rmtree(scan_dir, ignore_errors=True)

    def scan_multiple_files(
        self,
        files: Dict[str, str],  # filename -> content
        scan_type: IacType = IacType.ALL
    ) -> IacScanResult:
        """Scan multiple IaC files"""
        scan_id = str(uuid.uuid4())
        scan_dir = os.path.join(self.temp_dir, scan_id)

        try:
            os.makedirs(scan_dir, exist_ok=True)

            # Write all files
            for filename, content in files.items():
                # Handle nested paths
                file_path = os.path.join(scan_dir, filename)
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                with open(file_path, 'w') as f:
                    f.write(content)

            # Run scan
            return self._run_trivy_scan(
                scan_id,
                scan_dir,
                f"files:{len(files)} files"
            )

        except Exception as e:
            logger.error(f"IaC multi-file scan failed: {e}")
            return IacScanResult(
                scan_id=scan_id,
                status="failed",
                scanned_at=datetime.utcnow().isoformat(),
                scan_type=scan_type.value,
                source=f"files:{len(files)} files",
                summary={"critical": 0, "high": 0, "medium": 0, "low": 0},
                findings=[],
                files_scanned=0,
                error=str(e)
            )
        finally:
            if os.path.exists(scan_dir):
                shutil.rmtree(scan_dir, ignore_errors=True)

    def scan_git_repo(
        self,
        repo_url: str,
        branch: str = "main",
        token: Optional[str] = None,
        paths: Optional[List[str]] = None,
        scan_type: IacType = IacType.ALL
    ) -> IacScanResult:
        """Scan a Git repository for IaC misconfigurations"""
        scan_id = str(uuid.uuid4())
        scan_dir = os.path.join(self.temp_dir, scan_id)

        try:
            os.makedirs(scan_dir, exist_ok=True)

            # Prepare git URL with token if provided
            if token:
                # Insert token into URL
                if repo_url.startswith("https://"):
                    repo_url = repo_url.replace("https://", f"https://oauth2:{token}@")
                elif repo_url.startswith("http://"):
                    repo_url = repo_url.replace("http://", f"http://oauth2:{token}@")

            # Clone repository
            clone_cmd = [
                "git", "clone",
                "--depth", "1",
                "--branch", branch,
                repo_url,
                scan_dir
            ]

            result = subprocess.run(
                clone_cmd,
                capture_output=True,
                text=True,
                timeout=120
            )

            if result.returncode != 0:
                raise Exception(f"Git clone failed: {result.stderr}")

            # If specific paths provided, scan only those
            target_dir = scan_dir
            if paths:
                # Create temp dir with only specified paths
                filtered_dir = os.path.join(self.temp_dir, f"{scan_id}_filtered")
                os.makedirs(filtered_dir, exist_ok=True)

                for path in paths:
                    src = os.path.join(scan_dir, path)
                    if os.path.exists(src):
                        dst = os.path.join(filtered_dir, path)
                        os.makedirs(os.path.dirname(dst), exist_ok=True)
                        if os.path.isfile(src):
                            shutil.copy2(src, dst)
                        else:
                            shutil.copytree(src, dst)

                target_dir = filtered_dir

            # Run scan
            return self._run_trivy_scan(scan_id, target_dir, f"repo:{repo_url}")

        except subprocess.TimeoutExpired:
            logger.error(f"Git clone timeout for {repo_url}")
            return IacScanResult(
                scan_id=scan_id,
                status="failed",
                scanned_at=datetime.utcnow().isoformat(),
                scan_type=scan_type.value,
                source=f"repo:{repo_url}",
                summary={"critical": 0, "high": 0, "medium": 0, "low": 0},
                findings=[],
                files_scanned=0,
                error="Git clone timeout (120s)"
            )
        except Exception as e:
            logger.error(f"IaC repo scan failed: {e}")
            return IacScanResult(
                scan_id=scan_id,
                status="failed",
                scanned_at=datetime.utcnow().isoformat(),
                scan_type=scan_type.value,
                source=f"repo:{repo_url}",
                summary={"critical": 0, "high": 0, "medium": 0, "low": 0},
                findings=[],
                files_scanned=0,
                error=str(e)
            )
        finally:
            # Cleanup
            if os.path.exists(scan_dir):
                shutil.rmtree(scan_dir, ignore_errors=True)
            filtered_dir = os.path.join(self.temp_dir, f"{scan_id}_filtered")
            if os.path.exists(filtered_dir):
                shutil.rmtree(filtered_dir, ignore_errors=True)

    def _run_trivy_scan(
        self,
        scan_id: str,
        target_dir: str,
        source: str
    ) -> IacScanResult:
        """Run Trivy config scan on a directory"""
        try:
            cmd = [
                "trivy", "config",
                "--format", "json",
                "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
                target_dir
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            # Trivy returns exit code 0 even with findings
            output = result.stdout
            if not output:
                output = result.stderr

            # Parse JSON output
            try:
                scan_data = json.loads(output)
            except json.JSONDecodeError:
                # Try to find JSON in output
                if "{" in output:
                    json_start = output.index("{")
                    scan_data = json.loads(output[json_start:])
                else:
                    raise Exception(f"Invalid Trivy output: {output[:500]}")

            # Process results
            findings = []
            summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            files_scanned = 0

            results = scan_data.get("Results", [])

            for result_item in results:
                files_scanned += 1
                target_file = result_item.get("Target", "unknown")

                for misconfig in result_item.get("Misconfigurations", []):
                    severity = misconfig.get("Severity", "UNKNOWN").lower()
                    if severity in summary:
                        summary[severity] += 1

                    cause = misconfig.get("CauseMetadata", {})
                    code_lines = cause.get("Code", {}).get("Lines", [])
                    code_snippet = None
                    if code_lines:
                        code_snippet = "\n".join([
                            line.get("Content", "") for line in code_lines
                        ])

                    finding = {
                        "id": misconfig.get("ID", ""),
                        "avd_id": misconfig.get("AVDID", ""),
                        "title": misconfig.get("Title", ""),
                        "description": misconfig.get("Description", ""),
                        "message": misconfig.get("Message", ""),
                        "severity": misconfig.get("Severity", "UNKNOWN"),
                        "resolution": misconfig.get("Resolution", ""),
                        "file": target_file,
                        "start_line": cause.get("StartLine", 0),
                        "end_line": cause.get("EndLine", 0),
                        "code_snippet": code_snippet,
                        "primary_url": misconfig.get("PrimaryURL", ""),
                        "references": misconfig.get("References", [])
                    }
                    findings.append(finding)

            return IacScanResult(
                scan_id=scan_id,
                status="completed",
                scanned_at=datetime.utcnow().isoformat(),
                scan_type="iac",
                source=source,
                summary=summary,
                findings=findings,
                files_scanned=files_scanned
            )

        except subprocess.TimeoutExpired:
            raise Exception("Trivy scan timeout (300s)")
        except Exception as e:
            raise Exception(f"Trivy scan failed: {str(e)}")


# Global scanner instance
iac_scanner = IacScanner()
