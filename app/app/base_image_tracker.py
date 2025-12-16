"""
Base Image Detection and Tracking
Identifies and tracks vulnerabilities specific to base images
"""
import json
import redis
import re
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, asdict

from app.config import settings
from app.logging_config import get_logger

logger = get_logger(__name__)

# Redis connection
redis_pool = redis.ConnectionPool.from_url(
    settings.REDIS_URL,
    max_connections=10,
    decode_responses=True
)


def get_redis_client() -> redis.Redis:
    return redis.Redis(connection_pool=redis_pool)


@dataclass
class BaseImageInfo:
    """Base image information"""
    os_name: str
    os_version: str
    os_id: str
    os_pretty_name: str
    os_cpe: str
    detected_base: Optional[str] = None
    base_image_tag: Optional[str] = None
    is_official: bool = False
    last_updated: Optional[str] = None


# Common base image patterns
BASE_IMAGE_PATTERNS = {
    "alpine": {
        "pattern": r"alpine",
        "official_images": ["alpine", "alpine:*"],
        "os_id": "alpine"
    },
    "debian": {
        "pattern": r"debian|bullseye|buster|bookworm|stretch",
        "official_images": ["debian", "debian:*"],
        "os_id": "debian"
    },
    "ubuntu": {
        "pattern": r"ubuntu|focal|jammy|bionic|noble",
        "official_images": ["ubuntu", "ubuntu:*"],
        "os_id": "ubuntu"
    },
    "rhel": {
        "pattern": r"rhel|redhat|ubi|ubi8|ubi9",
        "official_images": ["redhat/ubi8", "redhat/ubi9", "registry.access.redhat.com/ubi*"],
        "os_id": "rhel"
    },
    "centos": {
        "pattern": r"centos",
        "official_images": ["centos", "centos:*"],
        "os_id": "centos"
    },
    "amazonlinux": {
        "pattern": r"amazon|amzn",
        "official_images": ["amazonlinux", "amazonlinux:*"],
        "os_id": "amzn"
    },
    "rockylinux": {
        "pattern": r"rocky",
        "official_images": ["rockylinux", "rockylinux:*"],
        "os_id": "rocky"
    },
    "oraclelinux": {
        "pattern": r"oracle",
        "official_images": ["oraclelinux", "oraclelinux:*"],
        "os_id": "ol"
    }
}


class BaseImageTracker:
    """Track and analyze base image vulnerabilities"""

    BASE_IMAGES_KEY = "base_images"
    BASE_IMAGE_VULNS_KEY = "base_image_vulns"

    def __init__(self):
        self.redis = get_redis_client()

    def detect_base_image(
        self,
        image_name: str,
        os_info: Dict[str, Any]
    ) -> BaseImageInfo:
        """
        Detect base image from image name and OS info

        Args:
            image_name: Full image name with tag
            os_info: OS information from SBOM

        Returns:
            BaseImageInfo with detected base image details
        """
        os_id = os_info.get("os_id", "").lower()
        os_name = os_info.get("os_name", "Unknown")
        os_version = os_info.get("os_version", "Unknown")
        os_pretty_name = os_info.get("os_pretty_name", f"{os_name} {os_version}")
        os_cpe = os_info.get("os_cpe", "Unknown")

        # Try to detect base image from OS ID
        detected_base = None
        is_official = False

        for base_name, config in BASE_IMAGE_PATTERNS.items():
            if os_id == config["os_id"] or re.search(config["pattern"], os_id, re.IGNORECASE):
                detected_base = base_name
                break

        # Check if image itself is an official base image
        image_lower = image_name.lower()
        for base_name, config in BASE_IMAGE_PATTERNS.items():
            for official in config["official_images"]:
                if official.endswith("*"):
                    if image_lower.startswith(official[:-1]):
                        is_official = True
                        detected_base = base_name
                        break
                elif image_lower.startswith(official):
                    is_official = True
                    detected_base = base_name
                    break

        # Try to extract base image tag from common patterns
        base_image_tag = None
        if detected_base:
            # Common versioning patterns
            version_match = re.search(r":(\d+\.?\d*\.?\d*)", image_name)
            if version_match:
                base_image_tag = f"{detected_base}:{version_match.group(1)}"
            elif os_version != "Unknown":
                base_image_tag = f"{detected_base}:{os_version.split()[0]}"

        return BaseImageInfo(
            os_name=os_name,
            os_version=os_version,
            os_id=os_id,
            os_pretty_name=os_pretty_name,
            os_cpe=os_cpe,
            detected_base=detected_base,
            base_image_tag=base_image_tag,
            is_official=is_official,
            last_updated=datetime.now().isoformat()
        )

    def categorize_vulnerabilities(
        self,
        vulnerabilities: List[Dict[str, Any]],
        base_image_info: BaseImageInfo
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Categorize vulnerabilities into base image vs application-specific

        Args:
            vulnerabilities: List of all vulnerabilities
            base_image_info: Base image information

        Returns:
            Dict with 'base_image' and 'application' vulnerability lists
        """
        base_image_vulns = []
        application_vulns = []

        # Packages typically from base images
        base_packages = {
            "alpine": ["musl", "busybox", "alpine-baselayout", "apk-tools", "scanelf", "ssl_client", "zlib", "libcrypto", "libssl"],
            "debian": ["libc6", "libssl", "openssl", "coreutils", "dpkg", "apt", "base-files", "bash", "glibc"],
            "ubuntu": ["libc6", "libssl", "openssl", "coreutils", "dpkg", "apt", "base-files", "bash", "glibc"],
            "rhel": ["glibc", "openssl", "openssl-libs", "rpm", "dnf", "systemd", "bash", "coreutils", "redhat-release"],
            "centos": ["glibc", "openssl", "openssl-libs", "rpm", "yum", "systemd", "bash", "coreutils"],
        }

        base_pkg_set = set()
        if base_image_info.detected_base:
            base_pkg_set = set(base_packages.get(base_image_info.detected_base, []))

        for vuln in vulnerabilities:
            pkg_name = vuln.get("package", "").lower()
            pkg_type = vuln.get("type", "").lower()

            # Heuristics for base image vulnerabilities
            is_base_vuln = False

            # Check if package is in known base packages
            for base_pkg in base_pkg_set:
                if base_pkg in pkg_name:
                    is_base_vuln = True
                    break

            # System-level package types are usually from base
            if pkg_type in ["rpm", "deb", "apk", "dpkg"]:
                # Unless it's clearly an app package
                if not any(app_indicator in pkg_name for app_indicator in
                          ["python", "node", "java", "ruby", "go", "rust", "npm", "pip"]):
                    is_base_vuln = True

            if is_base_vuln:
                vuln["source"] = "base_image"
                base_image_vulns.append(vuln)
            else:
                vuln["source"] = "application"
                application_vulns.append(vuln)

        return {
            "base_image": base_image_vulns,
            "application": application_vulns,
            "summary": {
                "base_image_count": len(base_image_vulns),
                "application_count": len(application_vulns),
                "base_critical": sum(1 for v in base_image_vulns if v.get("severity", "").upper() == "CRITICAL"),
                "base_high": sum(1 for v in base_image_vulns if v.get("severity", "").upper() == "HIGH"),
                "app_critical": sum(1 for v in application_vulns if v.get("severity", "").upper() == "CRITICAL"),
                "app_high": sum(1 for v in application_vulns if v.get("severity", "").upper() == "HIGH")
            }
        }

    def register_base_image(
        self,
        image_name: str,
        image_tag: str,
        description: str = ""
    ) -> Dict[str, Any]:
        """Register an image as a tracked base image"""
        base_id = f"base:{image_name}:{image_tag}"

        data = {
            "image_name": image_name,
            "image_tag": image_tag,
            "full_name": f"{image_name}:{image_tag}",
            "description": description or "",
            "registered_at": datetime.now().isoformat(),
            "last_scanned": "",
            "scan_count": "0",
            "current_vulns": json.dumps({
                "critical": 0, "high": 0, "medium": 0, "low": 0,
                "fixable_critical": 0, "fixable_high": 0, "fixable_medium": 0, "fixable_low": 0
            })
        }

        self.redis.hset(base_id, mapping=data)
        self.redis.sadd(self.BASE_IMAGES_KEY, base_id)

        logger.info(
            "Base image registered",
            image=f"{image_name}:{image_tag}"
        )

        return data

    def list_base_images(self) -> List[Dict[str, Any]]:
        """List all registered base images"""
        base_ids = self.redis.smembers(self.BASE_IMAGES_KEY)
        base_images = []

        for base_id in base_ids:
            data = self.redis.hgetall(base_id)
            if data:
                if "current_vulns" in data:
                    data["current_vulns"] = json.loads(data["current_vulns"])
                if "scan_count" in data:
                    data["scan_count"] = int(data["scan_count"])
                if data.get("last_scanned") == "":
                    data["last_scanned"] = None
                base_images.append(data)

        return base_images

    def update_base_image_vulns(
        self,
        image_name: str,
        image_tag: str,
        scan_id: str,
        vulnerabilities: Dict[str, int]
    ) -> None:
        """Update vulnerability counts for a base image"""
        base_id = f"base:{image_name}:{image_tag}"

        if self.redis.exists(base_id):
            self.redis.hset(base_id, mapping={
                "last_scanned": datetime.now().isoformat(),
                "last_scan_id": scan_id,
                "current_vulns": json.dumps(vulnerabilities)
            })
            self.redis.hincrby(base_id, "scan_count", 1)

            # Store historical data
            history_key = f"base_history:{image_name}:{image_tag}"
            history_entry = {
                "timestamp": datetime.now().isoformat(),
                "scan_id": scan_id,
                "vulns": vulnerabilities
            }
            self.redis.lpush(history_key, json.dumps(history_entry))
            self.redis.ltrim(history_key, 0, 99)

    def get_base_image_history(
        self,
        image_name: str,
        image_tag: str,
        limit: int = 30
    ) -> List[Dict[str, Any]]:
        """Get vulnerability history for a base image"""
        history_key = f"base_history:{image_name}:{image_tag}"
        entries = self.redis.lrange(history_key, 0, limit - 1)

        return [json.loads(entry) for entry in entries]

    def compare_base_images(
        self,
        image1: str,
        tag1: str,
        image2: str,
        tag2: str
    ) -> Dict[str, Any]:
        """Compare vulnerabilities between two base images"""
        base_id1 = f"base:{image1}:{tag1}"
        base_id2 = f"base:{image2}:{tag2}"

        data1 = self.redis.hgetall(base_id1)
        data2 = self.redis.hgetall(base_id2)

        if not data1 or not data2:
            return {"error": "One or both base images not found"}

        vulns1 = json.loads(data1.get("current_vulns", "{}"))
        vulns2 = json.loads(data2.get("current_vulns", "{}"))

        return {
            "image1": {
                "name": f"{image1}:{tag1}",
                "vulnerabilities": vulns1,
                "last_scanned": data1.get("last_scanned")
            },
            "image2": {
                "name": f"{image2}:{tag2}",
                "vulnerabilities": vulns2,
                "last_scanned": data2.get("last_scanned")
            },
            "comparison": {
                "critical_diff": vulns1.get("critical", 0) - vulns2.get("critical", 0),
                "high_diff": vulns1.get("high", 0) - vulns2.get("high", 0),
                "medium_diff": vulns1.get("medium", 0) - vulns2.get("medium", 0),
                "low_diff": vulns1.get("low", 0) - vulns2.get("low", 0),
                "recommendation": "image2" if (
                    vulns2.get("critical", 0) + vulns2.get("high", 0)
                ) < (
                    vulns1.get("critical", 0) + vulns1.get("high", 0)
                ) else "image1"
            }
        }
