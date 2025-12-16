"""
WebSocket Manager for Real-time Scan Progress
Provides live updates during vulnerability scans
"""
import json
import asyncio
import redis.asyncio as aioredis
from datetime import datetime
from typing import Dict, Any, List, Set, Optional
from fastapi import WebSocket, WebSocketDisconnect
from dataclasses import dataclass, asdict
import logging

from app.config import settings

logger = logging.getLogger(__name__)


@dataclass
class ScanProgress:
    """Scan progress update"""
    scan_id: str
    status: str
    progress: int  # 0-100
    current_step: str
    steps_completed: List[str]
    steps_remaining: List[str]
    message: str
    timestamp: str
    details: Optional[Dict[str, Any]] = None


class ConnectionManager:
    """Manage WebSocket connections for real-time updates"""

    def __init__(self):
        # Map of scan_id -> set of WebSocket connections
        self.active_connections: Dict[str, Set[WebSocket]] = {}
        # Map of WebSocket -> scan_id
        self.connection_scans: Dict[WebSocket, str] = {}
        # Global subscribers (for dashboard)
        self.global_subscribers: Set[WebSocket] = set()
        # Redis pub/sub for distributed updates
        self.redis_url = settings.REDIS_URL

    async def connect(self, websocket: WebSocket, scan_id: Optional[str] = None):
        """Accept a new WebSocket connection"""
        await websocket.accept()

        if scan_id:
            if scan_id not in self.active_connections:
                self.active_connections[scan_id] = set()
            self.active_connections[scan_id].add(websocket)
            self.connection_scans[websocket] = scan_id
            logger.info(f"WebSocket connected for scan: {scan_id}")
        else:
            self.global_subscribers.add(websocket)
            logger.info("Global WebSocket subscriber connected")

    def disconnect(self, websocket: WebSocket):
        """Handle WebSocket disconnection"""
        # Remove from scan-specific connections
        if websocket in self.connection_scans:
            scan_id = self.connection_scans[websocket]
            if scan_id in self.active_connections:
                self.active_connections[scan_id].discard(websocket)
                if not self.active_connections[scan_id]:
                    del self.active_connections[scan_id]
            del self.connection_scans[websocket]

        # Remove from global subscribers
        self.global_subscribers.discard(websocket)

    async def send_progress(self, scan_id: str, progress: ScanProgress):
        """Send progress update to connected clients"""
        message = json.dumps(asdict(progress))

        # Send to scan-specific subscribers
        if scan_id in self.active_connections:
            disconnected = set()
            for websocket in self.active_connections[scan_id]:
                try:
                    await websocket.send_text(message)
                except Exception:
                    disconnected.add(websocket)

            # Clean up disconnected clients
            for ws in disconnected:
                self.disconnect(ws)

        # Send to global subscribers
        disconnected = set()
        for websocket in self.global_subscribers:
            try:
                await websocket.send_text(message)
            except Exception:
                disconnected.add(websocket)

        for ws in disconnected:
            self.disconnect(ws)

    async def broadcast(self, message: Dict[str, Any]):
        """Broadcast message to all connected clients"""
        message_str = json.dumps(message)

        # All scan-specific connections
        all_connections = set()
        for connections in self.active_connections.values():
            all_connections.update(connections)

        # Global subscribers
        all_connections.update(self.global_subscribers)

        disconnected = set()
        for websocket in all_connections:
            try:
                await websocket.send_text(message_str)
            except Exception:
                disconnected.add(websocket)

        for ws in disconnected:
            self.disconnect(ws)


# Global connection manager instance
manager = ConnectionManager()


class ScanProgressTracker:
    """Track and broadcast scan progress"""

    SCAN_STEPS = [
        "Initializing scan",
        "Pulling image metadata",
        "Running Grype scanner",
        "Running Trivy scanner",
        "Generating SBOM with Syft",
        "Merging scanner results",
        "Generating HTML report",
        "Storing results",
        "Scan complete"
    ]

    def __init__(self, scan_id: str, image_name: str):
        self.scan_id = scan_id
        self.image_name = image_name
        self.current_step_index = 0
        self.start_time = datetime.now()

    def _calculate_progress(self) -> int:
        """Calculate progress percentage"""
        return int((self.current_step_index / len(self.SCAN_STEPS)) * 100)

    def _create_progress(
        self,
        status: str,
        message: str,
        details: Optional[Dict[str, Any]] = None
    ) -> ScanProgress:
        """Create a progress update object"""
        return ScanProgress(
            scan_id=self.scan_id,
            status=status,
            progress=self._calculate_progress(),
            current_step=self.SCAN_STEPS[min(self.current_step_index, len(self.SCAN_STEPS) - 1)],
            steps_completed=self.SCAN_STEPS[:self.current_step_index],
            steps_remaining=self.SCAN_STEPS[self.current_step_index + 1:],
            message=message,
            timestamp=datetime.now().isoformat(),
            details=details
        )

    async def update_progress(
        self,
        step_name: str,
        message: str,
        details: Optional[Dict[str, Any]] = None
    ):
        """Update and broadcast scan progress"""
        # Find step index
        try:
            self.current_step_index = self.SCAN_STEPS.index(step_name)
        except ValueError:
            # Custom step, increment from current
            self.current_step_index = min(
                self.current_step_index + 1,
                len(self.SCAN_STEPS) - 1
            )

        progress = self._create_progress("in_progress", message, details)
        await manager.send_progress(self.scan_id, progress)

    async def complete(
        self,
        success: bool,
        summary: Dict[str, Any]
    ):
        """Mark scan as complete"""
        self.current_step_index = len(self.SCAN_STEPS) - 1

        status = "completed" if success else "failed"
        message = "Scan completed successfully" if success else "Scan failed"

        duration = (datetime.now() - self.start_time).total_seconds()
        summary["duration_seconds"] = round(duration, 2)

        progress = self._create_progress(status, message, summary)
        progress.progress = 100 if success else self._calculate_progress()

        await manager.send_progress(self.scan_id, progress)

    async def error(self, error_message: str):
        """Report scan error"""
        progress = self._create_progress(
            "error",
            error_message,
            {"error": error_message}
        )
        await manager.send_progress(self.scan_id, progress)


# Redis pub/sub for distributed progress updates
class RedisPubSubManager:
    """Manage Redis pub/sub for distributed WebSocket updates"""

    CHANNEL = "scan_progress"

    def __init__(self):
        self.redis_url = settings.REDIS_URL
        self._pubsub = None
        self._redis = None

    async def connect(self):
        """Connect to Redis"""
        self._redis = await aioredis.from_url(self.redis_url)
        self._pubsub = self._redis.pubsub()
        await self._pubsub.subscribe(self.CHANNEL)

    async def disconnect(self):
        """Disconnect from Redis"""
        if self._pubsub:
            await self._pubsub.unsubscribe(self.CHANNEL)
        if self._redis:
            await self._redis.close()

    async def publish(self, message: Dict[str, Any]):
        """Publish progress update"""
        if self._redis:
            await self._redis.publish(self.CHANNEL, json.dumps(message))

    async def listen(self):
        """Listen for progress updates"""
        if self._pubsub:
            async for message in self._pubsub.listen():
                if message["type"] == "message":
                    try:
                        data = json.loads(message["data"])
                        yield data
                    except json.JSONDecodeError:
                        continue


# Synchronous helper for Celery tasks
def publish_progress_sync(
    scan_id: str,
    step: str,
    message: str,
    progress: int,
    details: Optional[Dict[str, Any]] = None
):
    """Synchronous progress publisher for Celery tasks"""
    import redis

    try:
        r = redis.Redis.from_url(settings.REDIS_URL)
        update = {
            "scan_id": scan_id,
            "step": step,
            "message": message,
            "progress": progress,
            "timestamp": datetime.now().isoformat(),
            "details": details or {}
        }
        r.publish("scan_progress", json.dumps(update))

        # Also store in Redis for late subscribers
        r.setex(
            f"progress:{scan_id}",
            300,  # 5 minute TTL
            json.dumps(update)
        )
    except Exception as e:
        logger.warning(f"Failed to publish progress: {e}")
