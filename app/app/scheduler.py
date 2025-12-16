"""
Scheduled scans with Google Chat notifications
Supports cron-based scheduling for base images
"""
import json
import redis
import httpx
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from celery import Celery
from celery.schedules import crontab
import asyncio

from app.config import settings
from app.logging_config import get_logger

logger = get_logger(__name__)

# Redis client for schedule storage
redis_pool = redis.ConnectionPool.from_url(
    settings.REDIS_URL,
    max_connections=10,
    decode_responses=True
)


def get_redis_client() -> redis.Redis:
    return redis.Redis(connection_pool=redis_pool)


class GoogleChatNotifier:
    """Send notifications to Google Chat webhooks"""

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    async def send_scan_report(
        self,
        scan_result: Dict[str, Any],
        image_name: str,
        scan_id: str
    ) -> bool:
        """Send formatted scan report to Google Chat"""
        try:
            # Determine status color and icon
            critical = scan_result.get("critical", 0)
            high = scan_result.get("high", 0)

            if critical > 0:
                status_icon = "🔴"
                status_text = "CRITICAL"
                header_color = "#DC3545"
            elif high > 0:
                status_icon = "🟠"
                status_text = "HIGH RISK"
                header_color = "#FD7E14"
            else:
                status_icon = "🟢"
                status_text = "PASSED"
                header_color = "#28A745"

            # Build Google Chat card message
            card = {
                "cardsV2": [{
                    "cardId": f"scan-{scan_id}",
                    "card": {
                        "header": {
                            "title": f"{status_icon} Security Scan Report",
                            "subtitle": image_name[:50] + "..." if len(image_name) > 50 else image_name,
                            "imageUrl": "https://cdn-icons-png.flaticon.com/512/6213/6213731.png",
                            "imageType": "CIRCLE"
                        },
                        "sections": [
                            {
                                "header": "Vulnerability Summary",
                                "widgets": [
                                    {
                                        "decoratedText": {
                                            "topLabel": "Status",
                                            "text": f"<b>{status_text}</b>",
                                            "startIcon": {"knownIcon": "BOOKMARK"}
                                        }
                                    },
                                    {
                                        "decoratedText": {
                                            "topLabel": "Critical",
                                            "text": f"<font color=\"#DC3545\"><b>{critical}</b></font>",
                                            "startIcon": {"knownIcon": "TICKET"}
                                        }
                                    },
                                    {
                                        "decoratedText": {
                                            "topLabel": "High",
                                            "text": f"<font color=\"#FD7E14\"><b>{high}</b></font>",
                                            "startIcon": {"knownIcon": "TICKET"}
                                        }
                                    },
                                    {
                                        "decoratedText": {
                                            "topLabel": "Medium",
                                            "text": f"<font color=\"#FFC107\"><b>{scan_result.get('medium', 0)}</b></font>",
                                            "startIcon": {"knownIcon": "TICKET"}
                                        }
                                    },
                                    {
                                        "decoratedText": {
                                            "topLabel": "Low",
                                            "text": f"<font color=\"#28A745\"><b>{scan_result.get('low', 0)}</b></font>",
                                            "startIcon": {"knownIcon": "TICKET"}
                                        }
                                    }
                                ]
                            },
                            {
                                "header": "Details",
                                "widgets": [
                                    {
                                        "decoratedText": {
                                            "topLabel": "Total Packages",
                                            "text": str(scan_result.get("total_packages", 0)),
                                            "startIcon": {"knownIcon": "DESCRIPTION"}
                                        }
                                    },
                                    {
                                        "decoratedText": {
                                            "topLabel": "Base Image",
                                            "text": scan_result.get("base_image_os", "Unknown"),
                                            "startIcon": {"knownIcon": "MULTIPLE_PEOPLE"}
                                        }
                                    },
                                    {
                                        "decoratedText": {
                                            "topLabel": "Scan ID",
                                            "text": scan_id[:8] + "...",
                                            "startIcon": {"knownIcon": "CONFIRMATION_NUMBER_ICON"}
                                        }
                                    },
                                    {
                                        "decoratedText": {
                                            "topLabel": "Scanned At",
                                            "text": datetime.now().strftime("%Y-%m-%d %H:%M UTC"),
                                            "startIcon": {"knownIcon": "CLOCK"}
                                        }
                                    }
                                ]
                            },
                            {
                                "widgets": [
                                    {
                                        "buttonList": {
                                            "buttons": [
                                                {
                                                    "text": "View Full Report",
                                                    "onClick": {
                                                        "openLink": {
                                                            "url": scan_result.get("report_url", "#")
                                                        }
                                                    }
                                                },
                                                {
                                                    "text": "View SBOM",
                                                    "onClick": {
                                                        "openLink": {
                                                            "url": scan_result.get("sbom_report_url", "#")
                                                        }
                                                    }
                                                }
                                            ]
                                        }
                                    }
                                ]
                            }
                        ]
                    }
                }]
            }

            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.webhook_url,
                    json=card,
                    timeout=30.0
                )
                response.raise_for_status()

            logger.info(
                "Google Chat notification sent",
                scan_id=scan_id,
                image=image_name
            )
            return True

        except Exception as e:
            logger.error(
                "Failed to send Google Chat notification",
                error=str(e),
                scan_id=scan_id
            )
            return False

    async def send_summary_report(
        self,
        schedule_name: str,
        results: List[Dict[str, Any]],
        total_images: int
    ) -> bool:
        """Send summary report for scheduled batch scan"""
        try:
            completed = sum(1 for r in results if r.get("status") == "completed")
            failed = total_images - completed

            total_critical = sum(r.get("critical", 0) for r in results)
            total_high = sum(r.get("high", 0) for r in results)
            total_medium = sum(r.get("medium", 0) for r in results)

            if total_critical > 0:
                status_icon = "🔴"
                status_text = "ACTION REQUIRED"
            elif total_high > 0:
                status_icon = "🟠"
                status_text = "REVIEW RECOMMENDED"
            else:
                status_icon = "🟢"
                status_text = "ALL PASSED"

            card = {
                "cardsV2": [{
                    "cardId": f"schedule-{schedule_name}",
                    "card": {
                        "header": {
                            "title": f"{status_icon} Scheduled Scan Summary",
                            "subtitle": schedule_name,
                            "imageUrl": "https://cdn-icons-png.flaticon.com/512/2972/2972351.png",
                            "imageType": "CIRCLE"
                        },
                        "sections": [
                            {
                                "header": "Scan Overview",
                                "widgets": [
                                    {
                                        "decoratedText": {
                                            "topLabel": "Overall Status",
                                            "text": f"<b>{status_text}</b>"
                                        }
                                    },
                                    {
                                        "decoratedText": {
                                            "topLabel": "Images Scanned",
                                            "text": f"{completed}/{total_images} completed"
                                        }
                                    },
                                    {
                                        "decoratedText": {
                                            "topLabel": "Failed Scans",
                                            "text": str(failed)
                                        }
                                    }
                                ]
                            },
                            {
                                "header": "Total Vulnerabilities",
                                "widgets": [
                                    {
                                        "columns": {
                                            "columnItems": [
                                                {
                                                    "horizontalSizeStyle": "FILL_AVAILABLE_SPACE",
                                                    "horizontalAlignment": "CENTER",
                                                    "verticalAlignment": "CENTER",
                                                    "widgets": [
                                                        {"decoratedText": {"topLabel": "Critical", "text": f"<font color=\"#DC3545\"><b>{total_critical}</b></font>"}}
                                                    ]
                                                },
                                                {
                                                    "horizontalSizeStyle": "FILL_AVAILABLE_SPACE",
                                                    "horizontalAlignment": "CENTER",
                                                    "verticalAlignment": "CENTER",
                                                    "widgets": [
                                                        {"decoratedText": {"topLabel": "High", "text": f"<font color=\"#FD7E14\"><b>{total_high}</b></font>"}}
                                                    ]
                                                },
                                                {
                                                    "horizontalSizeStyle": "FILL_AVAILABLE_SPACE",
                                                    "horizontalAlignment": "CENTER",
                                                    "verticalAlignment": "CENTER",
                                                    "widgets": [
                                                        {"decoratedText": {"topLabel": "Medium", "text": f"<font color=\"#FFC107\"><b>{total_medium}</b></font>"}}
                                                    ]
                                                }
                                            ]
                                        }
                                    }
                                ]
                            },
                            {
                                "widgets": [
                                    {
                                        "decoratedText": {
                                            "topLabel": "Completed At",
                                            "text": datetime.now().strftime("%Y-%m-%d %H:%M UTC")
                                        }
                                    }
                                ]
                            }
                        ]
                    }
                }]
            }

            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.webhook_url,
                    json=card,
                    timeout=30.0
                )
                response.raise_for_status()

            return True

        except Exception as e:
            logger.error(
                "Failed to send summary notification",
                error=str(e),
                schedule=schedule_name
            )
            return False


class ScheduleManager:
    """Manage scheduled scans"""

    SCHEDULES_KEY = "scheduled_scans"

    def __init__(self):
        self.redis = get_redis_client()

    def create_schedule(
        self,
        name: str,
        images: List[str],
        cron_expression: str,
        google_chat_webhook: Optional[str] = None,
        enabled: bool = True,
        description: str = ""
    ) -> Dict[str, Any]:
        """Create a new scheduled scan"""
        schedule_id = f"schedule:{name}"

        schedule = {
            "id": schedule_id,
            "name": name,
            "images": images,
            "cron_expression": cron_expression,
            "google_chat_webhook": google_chat_webhook or "",
            "enabled": enabled,
            "description": description,
            "created_at": datetime.now().isoformat(),
            "last_run": None,
            "next_run": None,
            "run_count": 0
        }

        self.redis.hset(schedule_id, mapping={
            k: json.dumps(v) if isinstance(v, (list, dict, bool)) else str(v) if v is not None else ""
            for k, v in schedule.items()
        })
        self.redis.sadd(self.SCHEDULES_KEY, schedule_id)

        logger.info(
            "Schedule created",
            name=name,
            image_count=len(images),
            cron=cron_expression
        )

        return schedule

    def get_schedule(self, name: str) -> Optional[Dict[str, Any]]:
        """Get a schedule by name"""
        schedule_id = f"schedule:{name}"
        data = self.redis.hgetall(schedule_id)

        if not data:
            return None

        # Parse stored data
        schedule = {}
        for key, value in data.items():
            if key in ["images", "enabled"]:
                schedule[key] = json.loads(value)
            else:
                schedule[key] = value

        return schedule

    def list_schedules(self) -> List[Dict[str, Any]]:
        """List all schedules"""
        schedule_ids = self.redis.smembers(self.SCHEDULES_KEY)
        schedules = []

        for schedule_id in schedule_ids:
            data = self.redis.hgetall(schedule_id)
            if data:
                schedule = {}
                for key, value in data.items():
                    if key in ["images", "enabled"]:
                        try:
                            schedule[key] = json.loads(value)
                        except:
                            schedule[key] = value
                    else:
                        schedule[key] = value
                schedules.append(schedule)

        return schedules

    def update_schedule(
        self,
        name: str,
        updates: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Update a schedule"""
        schedule_id = f"schedule:{name}"

        if not self.redis.exists(schedule_id):
            return None

        for key, value in updates.items():
            if isinstance(value, (list, dict, bool)):
                self.redis.hset(schedule_id, key, json.dumps(value))
            else:
                self.redis.hset(schedule_id, key, str(value) if value is not None else "")

        return self.get_schedule(name)

    def delete_schedule(self, name: str) -> bool:
        """Delete a schedule"""
        schedule_id = f"schedule:{name}"

        if self.redis.exists(schedule_id):
            self.redis.delete(schedule_id)
            self.redis.srem(self.SCHEDULES_KEY, schedule_id)
            logger.info("Schedule deleted", name=name)
            return True

        return False

    def record_run(
        self,
        name: str,
        results: List[Dict[str, Any]]
    ) -> None:
        """Record a schedule run"""
        schedule_id = f"schedule:{name}"
        now = datetime.now().isoformat()

        self.redis.hset(schedule_id, "last_run", now)
        self.redis.hincrby(schedule_id, "run_count", 1)

        # Store run history
        run_key = f"schedule_runs:{name}"
        run_data = {
            "timestamp": now,
            "results_count": len(results),
            "completed": sum(1 for r in results if r.get("status") == "completed"),
            "total_critical": sum(r.get("critical", 0) for r in results),
            "total_high": sum(r.get("high", 0) for r in results)
        }

        self.redis.lpush(run_key, json.dumps(run_data))
        self.redis.ltrim(run_key, 0, 99)  # Keep last 100 runs


# Celery beat schedule will be configured dynamically
def get_celery_beat_schedule() -> Dict[str, Any]:
    """Generate Celery beat schedule from stored schedules"""
    manager = ScheduleManager()
    schedules = manager.list_schedules()

    beat_schedule = {}

    for schedule in schedules:
        if schedule.get("enabled") == True or schedule.get("enabled") == "true":
            cron_parts = schedule.get("cron_expression", "0 0 * * *").split()

            if len(cron_parts) == 5:
                beat_schedule[f"scheduled-scan-{schedule['name']}"] = {
                    "task": "run_scheduled_scan",
                    "schedule": crontab(
                        minute=cron_parts[0],
                        hour=cron_parts[1],
                        day_of_month=cron_parts[2],
                        month_of_year=cron_parts[3],
                        day_of_week=cron_parts[4]
                    ),
                    "args": [schedule["name"]]
                }

    return beat_schedule
