"""
Auto-Update Service
Handles automatic updates for vulnerability databases and scanner tools

NOTE: Tool version checks and DB updates run on the WORKER container
where tools are installed. Results are stored in Redis and read by the API.
"""
import subprocess
import json
import redis
import httpx
import os
import re
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
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


# Redis keys for caching tool/db status
TOOL_STATUS_KEY = "system:tool_status"
DB_STATUS_KEY = "system:db_status"
TOOL_STATUS_TTL = 3600  # 1 hour cache


@dataclass
class ToolVersion:
    """Version information for a tool"""
    name: str
    current_version: str
    latest_version: str
    update_available: bool
    last_checked: str
    last_updated: str
    update_url: str


@dataclass
class DatabaseInfo:
    """Vulnerability database information"""
    name: str
    last_updated: str
    entry_count: int
    update_status: str


class UpdateService:
    """
    Manages updates for vulnerability databases and scanning tools
    """

    # GitHub API URLs for checking latest releases
    TOOL_REPOS = {
        "grype": "anchore/grype",
        "syft": "anchore/syft",
        "trivy": "aquasecurity/trivy"
    }

    def __init__(self):
        self.redis = get_redis_client()

    def get_cached_tool_status(self) -> Dict[str, Any]:
        """
        Get cached tool status from Redis (for API to read)
        This is populated by the worker via check_tool_updates()
        """
        cached = self.redis.get(TOOL_STATUS_KEY)
        if cached:
            return json.loads(cached)

        # Return empty status if not cached yet
        return {
            "checked_at": None,
            "tools": {
                "grype": {"name": "grype", "current_version": "checking...", "latest_version": "checking...", "update_available": False},
                "syft": {"name": "syft", "current_version": "checking...", "latest_version": "checking...", "update_available": False},
                "trivy": {"name": "trivy", "current_version": "checking...", "latest_version": "checking...", "update_available": False},
            },
            "updates_available": False,
            "note": "Status will be updated after first scheduled check or manual trigger"
        }

    def get_cached_db_status(self) -> Dict[str, Any]:
        """
        Get cached DB status from Redis (for API to read)
        This is populated by the worker via update_grype_db()
        """
        cached = self.redis.get(DB_STATUS_KEY)
        if cached:
            return json.loads(cached)

        # Return status from last_updates if available
        last_updates = self.get_last_updates()
        last_grype = last_updates.get("grype")

        # Try to get db_info from update history when cache is missing
        grype_db_info = {}
        try:
            history = self.get_update_history(20)
            for entry in history:
                if entry.get("tool") == "grype" and entry.get("db_info"):
                    grype_db_info = entry.get("db_info", {})
                    break
        except Exception:
            pass

        status = {
            "grype": grype_db_info,
            "last_updates": last_updates
        }

        if last_grype:
            try:
                last_dt = datetime.fromisoformat(last_grype)
                hours_since = (datetime.now() - last_dt).total_seconds() / 3600
                status["grype_hours_since_update"] = round(hours_since, 1)
                status["grype_update_due"] = hours_since > 24
            except Exception:
                status["grype_update_due"] = True
        else:
            status["grype_update_due"] = True
            status["note"] = "Database status will be updated after first scan or manual update"

        return status

    def check_tool_updates(self) -> Dict[str, Any]:
        """
        Check for updates to all scanning tools
        NOTE: This should be called from the WORKER container where tools are installed

        Returns:
            Dictionary with update status for each tool
        """
        results = {}

        for tool_name, repo in self.TOOL_REPOS.items():
            try:
                current = self._get_current_version(tool_name)
                latest = self._get_latest_version(repo)

                update_available = self._compare_versions(current, latest)

                results[tool_name] = {
                    "name": tool_name,
                    "current_version": current,
                    "latest_version": latest,
                    "update_available": update_available,
                    "last_checked": datetime.now().isoformat(),
                    "repository": f"https://github.com/{repo}"
                }

                # Cache the result
                self.redis.hset(
                    "tool_versions",
                    tool_name,
                    json.dumps(results[tool_name])
                )

            except Exception as e:
                logger.error(f"Failed to check updates for {tool_name}: {e}")
                results[tool_name] = {
                    "name": tool_name,
                    "error": str(e),
                    "last_checked": datetime.now().isoformat()
                }

        result = {
            "checked_at": datetime.now().isoformat(),
            "tools": results,
            "updates_available": any(
                r.get("update_available", False)
                for r in results.values()
            )
        }

        # Cache the full status for API to read
        self.redis.setex(TOOL_STATUS_KEY, TOOL_STATUS_TTL, json.dumps(result))

        return result

    def _get_current_version(self, tool_name: str) -> str:
        """Get the currently installed version of a tool"""
        try:
            if tool_name == "grype":
                result = subprocess.run(
                    ["grype", "version", "-o", "json"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    data = json.loads(result.stdout)
                    return data.get("version", "unknown")

            elif tool_name == "syft":
                result = subprocess.run(
                    ["syft", "version", "-o", "json"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    data = json.loads(result.stdout)
                    return data.get("version", "unknown")

            elif tool_name == "trivy":
                result = subprocess.run(
                    ["trivy", "version", "-f", "json"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    data = json.loads(result.stdout)
                    return data.get("Version", "unknown")

        except FileNotFoundError:
            return "not installed"
        except subprocess.TimeoutExpired:
            return "timeout"
        except Exception as e:
            logger.error(f"Error getting version for {tool_name}: {e}")

        return "unknown"

    def _get_latest_version(self, repo: str) -> str:
        """Get the latest version from GitHub releases"""
        try:
            url = f"https://api.github.com/repos/{repo}/releases/latest"
            headers = {"Accept": "application/vnd.github.v3+json"}

            # Add token if available
            github_token = os.environ.get("GITHUB_TOKEN")
            if github_token:
                headers["Authorization"] = f"token {github_token}"

            with httpx.Client(timeout=10) as client:
                response = client.get(url, headers=headers)
                if response.status_code == 200:
                    data = response.json()
                    tag = data.get("tag_name", "unknown")
                    # Remove 'v' prefix if present
                    return tag.lstrip("v")

        except Exception as e:
            logger.error(f"Error fetching latest version for {repo}: {e}")

        return "unknown"

    def _compare_versions(self, current: str, latest: str) -> bool:
        """Compare two version strings"""
        if current in ["unknown", "not installed", "timeout"]:
            return True
        if latest == "unknown":
            return False

        try:
            def parse_version(v: str) -> Tuple:
                parts = re.split(r'[.\-+]', v.lstrip("v"))
                result = []
                for p in parts:
                    try:
                        result.append(int(re.sub(r'[^\d]', '', p) or 0))
                    except ValueError:
                        result.append(0)
                return tuple(result)

            return parse_version(latest) > parse_version(current)
        except Exception:
            return current != latest

    def update_grype_db(self) -> Dict[str, Any]:
        """
        Update Grype vulnerability database
        NOTE: This should be called from the WORKER container where grype is installed

        Returns:
            Update status
        """
        logger.info("Starting Grype database update")

        try:
            result = subprocess.run(
                ["grype", "db", "update"],
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

            success = result.returncode == 0

            # Get DB info after update
            db_info = self._get_grype_db_info()

            update_record = {
                "tool": "grype",
                "action": "db_update",
                "success": success,
                "timestamp": datetime.now().isoformat(),
                "output": result.stdout[:1000] if result.stdout else "",
                "error": result.stderr[:500] if result.stderr and not success else "",
                "db_info": db_info
            }

            # Store update history
            self._record_update(update_record)

            # Cache DB status for API to read
            if success:
                db_status = {
                    "grype": db_info,
                    "last_updates": self.get_last_updates(),
                    "grype_hours_since_update": 0,
                    "grype_update_due": False
                }
                self.redis.setex(DB_STATUS_KEY, TOOL_STATUS_TTL, json.dumps(db_status))

            logger.info(
                "Grype DB update completed",
                success=success,
                db_info=db_info
            )

            return update_record

        except subprocess.TimeoutExpired:
            return {
                "tool": "grype",
                "action": "db_update",
                "success": False,
                "error": "Update timed out",
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Grype DB update failed: {e}")
            return {
                "tool": "grype",
                "action": "db_update",
                "success": False,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }

    def update_trivy_db(self) -> Dict[str, Any]:
        """
        Update Trivy vulnerability database

        Returns:
            Update status
        """
        logger.info("Starting Trivy database update")

        try:
            # Trivy updates DB on first scan, but we can force it
            result = subprocess.run(
                ["trivy", "image", "--download-db-only"],
                capture_output=True,
                text=True,
                timeout=300
            )

            success = result.returncode == 0

            update_record = {
                "tool": "trivy",
                "action": "db_update",
                "success": success,
                "timestamp": datetime.now().isoformat(),
                "output": result.stdout[:1000] if result.stdout else "",
                "error": result.stderr[:500] if result.stderr and not success else ""
            }

            self._record_update(update_record)

            logger.info("Trivy DB update completed", success=success)

            return update_record

        except subprocess.TimeoutExpired:
            return {
                "tool": "trivy",
                "action": "db_update",
                "success": False,
                "error": "Update timed out",
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Trivy DB update failed: {e}")
            return {
                "tool": "trivy",
                "action": "db_update",
                "success": False,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }

    def _get_grype_db_info(self) -> Dict[str, Any]:
        """Get Grype database information"""
        try:
            result = subprocess.run(
                ["grype", "db", "status", "-o", "json"],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                data = json.loads(result.stdout)
                return {
                    "built": data.get("built", "unknown"),
                    "schema_version": data.get("schemaVersion", "unknown"),
                    "location": data.get("location", "unknown"),
                    "checksum": data.get("checksum", "unknown")
                }
        except Exception as e:
            logger.error(f"Error getting Grype DB info: {e}")

        return {}

    def _record_update(self, record: Dict[str, Any]) -> None:
        """Record update in Redis history"""
        history_key = "update_history"

        # Add to list
        self.redis.lpush(history_key, json.dumps(record))

        # Keep last 100 records
        self.redis.ltrim(history_key, 0, 99)

        # Update last update timestamp
        if record.get("success"):
            self.redis.hset(
                "last_updates",
                record["tool"],
                record["timestamp"]
            )

    def get_update_history(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get update history"""
        history_key = "update_history"
        entries = self.redis.lrange(history_key, 0, limit - 1)
        return [json.loads(e) for e in entries]

    def get_last_updates(self) -> Dict[str, str]:
        """Get last update times for each tool"""
        return self.redis.hgetall("last_updates") or {}

    def get_db_status(self) -> Dict[str, Any]:
        """Get status of all vulnerability databases"""
        status = {
            "grype": self._get_grype_db_info(),
            "last_updates": self.get_last_updates()
        }

        # Check if updates are due
        last_grype = status["last_updates"].get("grype")
        if last_grype:
            try:
                last_dt = datetime.fromisoformat(last_grype)
                hours_since = (datetime.now() - last_dt).total_seconds() / 3600
                status["grype_hours_since_update"] = round(hours_since, 1)
                status["grype_update_due"] = hours_since > 24
            except Exception:
                status["grype_update_due"] = True
        else:
            status["grype_update_due"] = True

        return status

    def run_scheduled_updates(self) -> Dict[str, Any]:
        """
        Run all scheduled updates (called by Celery beat)

        Returns:
            Combined update results
        """
        logger.info("Running scheduled vulnerability database updates")

        results = {
            "started_at": datetime.now().isoformat(),
            "updates": []
        }

        # Update Grype DB
        grype_result = self.update_grype_db()
        results["updates"].append(grype_result)

        # Update Trivy DB
        trivy_result = self.update_trivy_db()
        results["updates"].append(trivy_result)

        # Check for tool updates (informational only)
        tool_updates = self.check_tool_updates()
        results["tool_updates"] = tool_updates

        results["completed_at"] = datetime.now().isoformat()
        results["all_successful"] = all(
            u.get("success", False) for u in results["updates"]
        )

        # Send notification if updates available
        if tool_updates.get("updates_available"):
            self._notify_updates_available(tool_updates)

        return results

    def _notify_updates_available(self, tool_updates: Dict[str, Any]) -> None:
        """Send notification about available tool updates"""
        # Store notification for dashboard
        notification = {
            "type": "tool_updates_available",
            "timestamp": datetime.now().isoformat(),
            "tools": [
                name for name, info in tool_updates.get("tools", {}).items()
                if info.get("update_available")
            ]
        }

        self.redis.lpush("notifications", json.dumps(notification))
        self.redis.ltrim("notifications", 0, 49)  # Keep last 50

        logger.info(
            "Tool updates available",
            tools=notification["tools"]
        )


# Celery task for scheduled updates
def create_update_task(celery_app):
    """Create Celery task for scheduled updates"""

    @celery_app.task(bind=True, name='update_vulnerability_databases')
    def update_vulnerability_databases(self) -> Dict[str, Any]:
        """Celery task to update vulnerability databases"""
        updater = UpdateService()
        return updater.run_scheduled_updates()

    return update_vulnerability_databases
