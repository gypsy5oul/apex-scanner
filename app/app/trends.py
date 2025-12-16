"""
Vulnerability Trends Analysis
Track and analyze vulnerability trends over time
"""
import json
import redis
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from collections import defaultdict

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


def scan_redis_keys(redis_client: redis.Redis, pattern: str, count: int = 100) -> list:
    """Use SCAN instead of KEYS for better performance on large datasets."""
    keys = []
    cursor = 0
    while True:
        cursor, batch = redis_client.scan(cursor, match=pattern, count=count)
        keys.extend(batch)
        if cursor == 0:
            break
    return keys


class TrendAnalyzer:
    """Analyze vulnerability trends across scans"""

    TREND_KEY_PREFIX = "trend"
    IMAGE_TREND_KEY_PREFIX = "image_trend"

    def __init__(self):
        self.redis = get_redis_client()

    def record_scan_metrics(
        self,
        scan_id: str,
        image_name: str,
        metrics: Dict[str, Any]
    ) -> None:
        """Record scan metrics for trend analysis"""
        timestamp = datetime.now().isoformat()
        date_key = datetime.now().strftime("%Y-%m-%d")

        # Normalize image name for key
        normalized_image = self._normalize_image_name(image_name)

        # Record image-specific trend
        image_trend_key = f"{self.IMAGE_TREND_KEY_PREFIX}:{normalized_image}"
        trend_entry = {
            "timestamp": timestamp,
            "date": date_key,
            "scan_id": scan_id,
            "critical": metrics.get("critical", 0),
            "high": metrics.get("high", 0),
            "medium": metrics.get("medium", 0),
            "low": metrics.get("low", 0),
            "total": metrics.get("total", 0),
            "packages": metrics.get("packages", 0),
            "fixable": metrics.get("fixable", 0)
        }

        self.redis.lpush(image_trend_key, json.dumps(trend_entry))
        self.redis.ltrim(image_trend_key, 0, 499)  # Keep last 500 entries
        self.redis.expire(image_trend_key, 86400 * 90)  # 90 days retention

        # Record global daily metrics
        global_key = f"{self.TREND_KEY_PREFIX}:daily:{date_key}"
        self.redis.hincrby(global_key, "total_scans", 1)
        self.redis.hincrby(global_key, "total_critical", metrics.get("critical", 0))
        self.redis.hincrby(global_key, "total_high", metrics.get("high", 0))
        self.redis.hincrby(global_key, "total_medium", metrics.get("medium", 0))
        self.redis.hincrby(global_key, "total_low", metrics.get("low", 0))
        self.redis.hincrby(global_key, "total_packages", metrics.get("packages", 0))
        self.redis.expire(global_key, 86400 * 365)  # 1 year retention

        # Track unique images scanned
        images_key = f"{self.TREND_KEY_PREFIX}:images:{date_key}"
        self.redis.sadd(images_key, normalized_image)
        self.redis.expire(images_key, 86400 * 365)

    def _normalize_image_name(self, image_name: str) -> str:
        """Normalize image name for consistent keys"""
        # Remove registry prefix for local registry images
        # Replace special characters
        normalized = image_name.replace("/", "_").replace(":", "_")
        # Limit length
        if len(normalized) > 100:
            normalized = normalized[:100]
        return normalized

    def get_image_trends(
        self,
        image_name: str,
        days: int = 30,
        limit: int = 100
    ) -> Dict[str, Any]:
        """Get vulnerability trends for a specific image"""
        normalized_image = self._normalize_image_name(image_name)
        image_trend_key = f"{self.IMAGE_TREND_KEY_PREFIX}:{normalized_image}"

        entries = self.redis.lrange(image_trend_key, 0, limit - 1)
        trends = [json.loads(entry) for entry in entries]

        if not trends:
            return {
                "image_name": image_name,
                "data_points": 0,
                "trends": [],
                "summary": {}
            }

        # Filter by date range
        cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
        filtered_trends = [t for t in trends if t["timestamp"] >= cutoff_date]

        # Calculate trend direction
        if len(filtered_trends) >= 2:
            latest = filtered_trends[0]
            oldest = filtered_trends[-1]

            trend_direction = {
                "critical": self._calculate_trend(oldest.get("critical", 0), latest.get("critical", 0)),
                "high": self._calculate_trend(oldest.get("high", 0), latest.get("high", 0)),
                "medium": self._calculate_trend(oldest.get("medium", 0), latest.get("medium", 0)),
                "low": self._calculate_trend(oldest.get("low", 0), latest.get("low", 0)),
                "total": self._calculate_trend(oldest.get("total", 0), latest.get("total", 0))
            }
        else:
            trend_direction = {}

        # Aggregate by date
        daily_aggregates = defaultdict(lambda: {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "scans": 0
        })

        for entry in filtered_trends:
            date = entry.get("date")
            if date:
                daily_aggregates[date]["critical"] = max(
                    daily_aggregates[date]["critical"],
                    entry.get("critical", 0)
                )
                daily_aggregates[date]["high"] = max(
                    daily_aggregates[date]["high"],
                    entry.get("high", 0)
                )
                daily_aggregates[date]["medium"] = max(
                    daily_aggregates[date]["medium"],
                    entry.get("medium", 0)
                )
                daily_aggregates[date]["low"] = max(
                    daily_aggregates[date]["low"],
                    entry.get("low", 0)
                )
                daily_aggregates[date]["scans"] += 1

        # Sort by date
        sorted_dates = sorted(daily_aggregates.keys())
        chart_data = [
            {
                "date": date,
                **daily_aggregates[date]
            }
            for date in sorted_dates
        ]

        return {
            "image_name": image_name,
            "data_points": len(filtered_trends),
            "date_range": {
                "start": sorted_dates[0] if sorted_dates else None,
                "end": sorted_dates[-1] if sorted_dates else None
            },
            "trends": chart_data,
            "trend_direction": trend_direction,
            "latest": filtered_trends[0] if filtered_trends else None,
            "summary": {
                "total_scans": len(filtered_trends),
                "avg_critical": round(sum(t.get("critical", 0) for t in filtered_trends) / len(filtered_trends), 1) if filtered_trends else 0,
                "avg_high": round(sum(t.get("high", 0) for t in filtered_trends) / len(filtered_trends), 1) if filtered_trends else 0,
                "max_critical": max(t.get("critical", 0) for t in filtered_trends) if filtered_trends else 0,
                "max_high": max(t.get("high", 0) for t in filtered_trends) if filtered_trends else 0
            }
        }

    def _calculate_trend(self, old_value: int, new_value: int) -> Dict[str, Any]:
        """Calculate trend between two values"""
        if old_value == 0 and new_value == 0:
            return {"direction": "stable", "change": 0, "percentage": 0}

        change = new_value - old_value

        if old_value == 0:
            percentage = 100 if new_value > 0 else 0
        else:
            percentage = round((change / old_value) * 100, 1)

        if change > 0:
            direction = "increasing"
        elif change < 0:
            direction = "decreasing"
        else:
            direction = "stable"

        return {
            "direction": direction,
            "change": change,
            "percentage": percentage
        }

    def get_global_trends(
        self,
        days: int = 30
    ) -> Dict[str, Any]:
        """Get global vulnerability trends across all scans"""
        daily_data = []

        for i in range(days):
            date = (datetime.now() - timedelta(days=i)).strftime("%Y-%m-%d")
            global_key = f"{self.TREND_KEY_PREFIX}:daily:{date}"
            images_key = f"{self.TREND_KEY_PREFIX}:images:{date}"

            data = self.redis.hgetall(global_key)
            unique_images = self.redis.scard(images_key)

            if data:
                daily_data.append({
                    "date": date,
                    "total_scans": int(data.get("total_scans", 0)),
                    "total_critical": int(data.get("total_critical", 0)),
                    "total_high": int(data.get("total_high", 0)),
                    "total_medium": int(data.get("total_medium", 0)),
                    "total_low": int(data.get("total_low", 0)),
                    "unique_images": unique_images
                })

        # Sort by date ascending
        daily_data.sort(key=lambda x: x["date"])

        # Calculate totals
        totals = {
            "total_scans": sum(d["total_scans"] for d in daily_data),
            "total_critical": sum(d["total_critical"] for d in daily_data),
            "total_high": sum(d["total_high"] for d in daily_data),
            "total_medium": sum(d["total_medium"] for d in daily_data),
            "total_low": sum(d["total_low"] for d in daily_data),
            "unique_images_scanned": len(set(
                self.redis.smembers(f"{self.TREND_KEY_PREFIX}:images:{d['date']}")
                for d in daily_data
            ))
        }

        # Calculate week-over-week change
        if len(daily_data) >= 14:
            this_week = daily_data[-7:]
            last_week = daily_data[-14:-7]

            this_week_critical = sum(d["total_critical"] for d in this_week)
            last_week_critical = sum(d["total_critical"] for d in last_week)

            wow_change = self._calculate_trend(last_week_critical, this_week_critical)
        else:
            wow_change = None

        return {
            "period_days": days,
            "daily_data": daily_data,
            "totals": totals,
            "week_over_week": wow_change,
            "averages": {
                "daily_scans": round(totals["total_scans"] / max(len(daily_data), 1), 1),
                "daily_critical": round(totals["total_critical"] / max(len(daily_data), 1), 1),
                "daily_high": round(totals["total_high"] / max(len(daily_data), 1), 1)
            }
        }

    def get_top_vulnerable_images(
        self,
        days: int = 7,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Get top vulnerable images"""
        # Scan all image trend keys (using SCAN for performance)
        image_keys = scan_redis_keys(self.redis, f"{self.IMAGE_TREND_KEY_PREFIX}:*", count=200)

        if not image_keys:
            return []

        # Pipeline: Get latest entry from all keys in batch
        pipe = self.redis.pipeline()
        for key in image_keys:
            pipe.lrange(key, 0, 0)  # Get latest entry
        key_results = pipe.execute()

        image_stats = []
        for key, entries in zip(image_keys, key_results):
            image_name = key.replace(f"{self.IMAGE_TREND_KEY_PREFIX}:", "")

            if entries:
                latest = json.loads(entries[0])
                image_stats.append({
                    "image_name": image_name,
                    "critical": latest.get("critical", 0),
                    "high": latest.get("high", 0),
                    "medium": latest.get("medium", 0),
                    "low": latest.get("low", 0),
                    "total": latest.get("total", 0),
                    "last_scanned": latest.get("timestamp"),
                    "risk_score": (
                        latest.get("critical", 0) * 10 +
                        latest.get("high", 0) * 5 +
                        latest.get("medium", 0) * 2 +
                        latest.get("low", 0)
                    )
                })

        # Sort by risk score
        image_stats.sort(key=lambda x: x["risk_score"], reverse=True)

        return image_stats[:limit]

    def get_vulnerability_distribution(
        self,
        days: int = 30
    ) -> Dict[str, Any]:
        """Get vulnerability distribution statistics"""
        all_entries = []

        # Get all image trends (using SCAN for performance)
        image_keys = scan_redis_keys(self.redis, f"{self.IMAGE_TREND_KEY_PREFIX}:*", count=200)

        if not image_keys:
            return {"total_scans": 0}

        cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()

        # Pipeline: Get entries from all keys in batch
        pipe = self.redis.pipeline()
        for key in image_keys:
            pipe.lrange(key, 0, 100)
        key_results = pipe.execute()

        for entries in key_results:
            for entry in entries:
                data = json.loads(entry)
                if data.get("timestamp", "") >= cutoff_date:
                    all_entries.append(data)

        if not all_entries:
            return {"total_scans": 0}

        # Calculate distribution
        severity_totals = {
            "critical": sum(e.get("critical", 0) for e in all_entries),
            "high": sum(e.get("high", 0) for e in all_entries),
            "medium": sum(e.get("medium", 0) for e in all_entries),
            "low": sum(e.get("low", 0) for e in all_entries)
        }

        total_vulns = sum(severity_totals.values())

        distribution = {
            severity: {
                "count": count,
                "percentage": round(count / total_vulns * 100, 1) if total_vulns > 0 else 0
            }
            for severity, count in severity_totals.items()
        }

        return {
            "total_scans": len(all_entries),
            "total_vulnerabilities": total_vulns,
            "distribution": distribution,
            "period_days": days
        }
