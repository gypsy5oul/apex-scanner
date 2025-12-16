"""
Worker monitoring module for Celery workers
Provides endpoints and utilities for monitoring worker health, queue stats, and scaling
"""
import json
import redis
from datetime import datetime
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict

from app.config import settings
from app.tasks import celery


def get_redis_client() -> redis.Redis:
    """Get Redis client"""
    return redis.from_url(settings.REDIS_URL, decode_responses=True)


@dataclass
class QueueInfo:
    """Queue information"""
    name: str
    length: int
    consumers: int = 0


@dataclass
class WorkerStats:
    """Worker statistics"""
    hostname: str
    status: str
    active: int
    processed: int
    failed: int
    queues: List[str]
    concurrency: int
    load_average: List[float]
    uptime: str


@dataclass
class ClusterStats:
    """Overall cluster statistics"""
    total_workers: int
    active_workers: int
    total_queued: int
    total_active_tasks: int
    total_processed: int
    total_failed: int
    queues: List[QueueInfo]
    workers: List[WorkerStats]


class WorkerMonitor:
    """
    Monitor Celery workers and queues
    """

    QUEUE_NAMES = ['high_priority', 'default', 'batch', 'low_priority', 'system']

    def __init__(self):
        self.redis = get_redis_client()
        self.inspect = celery.control.inspect()

    def get_queue_lengths(self) -> Dict[str, int]:
        """Get length of all queues"""
        lengths = {}
        for queue in self.QUEUE_NAMES:
            try:
                lengths[queue] = self.redis.llen(queue)
            except Exception:
                lengths[queue] = 0
        return lengths

    def get_queue_info(self) -> List[QueueInfo]:
        """Get detailed queue information"""
        queues = []
        lengths = self.get_queue_lengths()

        # Try to get consumer counts from Celery inspect
        try:
            active_queues = self.inspect.active_queues() or {}
            queue_consumers = {}
            for worker, worker_queues in active_queues.items():
                for q in worker_queues:
                    queue_name = q.get('name', '')
                    queue_consumers[queue_name] = queue_consumers.get(queue_name, 0) + 1
        except Exception:
            queue_consumers = {}

        for queue in self.QUEUE_NAMES:
            queues.append(QueueInfo(
                name=queue,
                length=lengths.get(queue, 0),
                consumers=queue_consumers.get(queue, 0)
            ))

        return queues

    def get_worker_stats(self) -> List[WorkerStats]:
        """Get statistics for all workers"""
        workers = []

        try:
            # Get worker stats from Celery inspect
            stats = self.inspect.stats() or {}
            active = self.inspect.active() or {}
            reserved = self.inspect.reserved() or {}

            for hostname, worker_stats in stats.items():
                worker_active = len(active.get(hostname, []))

                # Get queue names this worker is listening to
                queues = []
                try:
                    active_queues = self.inspect.active_queues() or {}
                    if hostname in active_queues:
                        queues = [q.get('name', '') for q in active_queues[hostname]]
                except Exception:
                    pass

                workers.append(WorkerStats(
                    hostname=hostname,
                    status='online',
                    active=worker_active,
                    processed=worker_stats.get('total', {}).get('tasks.scan_image', 0) +
                              worker_stats.get('total', {}).get('tasks.batch_scan_images', 0),
                    failed=0,  # Would need additional tracking
                    queues=queues,
                    concurrency=worker_stats.get('pool', {}).get('max-concurrency', 0),
                    load_average=worker_stats.get('rusage', {}).get('stime', [0, 0, 0]),
                    uptime=str(worker_stats.get('clock', 'unknown'))
                ))

        except Exception as e:
            print(f"Error getting worker stats: {e}")

        return workers

    def get_cluster_stats(self) -> ClusterStats:
        """Get overall cluster statistics"""
        queues = self.get_queue_info()
        workers = self.get_worker_stats()

        total_queued = sum(q.length for q in queues)
        total_active = sum(w.active for w in workers)
        total_processed = sum(w.processed for w in workers)
        total_failed = sum(w.failed for w in workers)
        active_workers = len([w for w in workers if w.status == 'online'])

        return ClusterStats(
            total_workers=len(workers),
            active_workers=active_workers,
            total_queued=total_queued,
            total_active_tasks=total_active,
            total_processed=total_processed,
            total_failed=total_failed,
            queues=queues,
            workers=workers
        )

    def get_autoscaler_status(self) -> Dict[str, Any]:
        """Get auto-scaler status from Redis"""
        try:
            status = self.redis.get('autoscaler:status')
            if status:
                return json.loads(status)
        except Exception:
            pass

        return {
            'running': False,
            'last_check': None,
            'queue_depth': 0,
            'worker_count': 0
        }

    def get_autoscaler_metrics(self) -> Dict[str, Any]:
        """Get auto-scaler metrics from Redis"""
        try:
            metrics = self.redis.get('autoscaler:metrics')
            if metrics:
                return json.loads(metrics)
        except Exception:
            pass

        return {}

    def get_scaling_history(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get recent scaling decisions"""
        try:
            history = self.redis.lrange('autoscaler:history', 0, limit - 1)
            return [json.loads(h) for h in history]
        except Exception:
            return []

    def get_task_stats(self) -> Dict[str, Any]:
        """Get task execution statistics"""
        stats = {
            'total_scans': 0,
            'completed_scans': 0,
            'failed_scans': 0,
            'in_progress': 0,
            'avg_duration': 0,
            'by_status': {}
        }

        try:
            # Count scans by status from Redis
            # Scan keys matching scan patterns
            cursor = 0
            scan_count = 0
            status_counts = {'completed': 0, 'failed': 0, 'in_progress': 0}

            while True:
                cursor, keys = self.redis.scan(cursor, match='????????-????-????-????-????????????', count=1000)
                for key in keys:
                    if self.redis.type(key) == 'hash':
                        status = self.redis.hget(key, 'status')
                        if status:
                            scan_count += 1
                            status_counts[status] = status_counts.get(status, 0) + 1

                if cursor == 0:
                    break

            stats['total_scans'] = scan_count
            stats['completed_scans'] = status_counts.get('completed', 0)
            stats['failed_scans'] = status_counts.get('failed', 0)
            stats['in_progress'] = status_counts.get('in_progress', 0)
            stats['by_status'] = status_counts

        except Exception as e:
            print(f"Error getting task stats: {e}")

        return stats

    def ping_workers(self) -> Dict[str, bool]:
        """Ping all workers to check responsiveness"""
        try:
            pong = celery.control.ping(timeout=5)
            results = {}
            for response in pong:
                for hostname, status in response.items():
                    results[hostname] = status.get('ok') == 'pong'
            return results
        except Exception:
            return {}

    def purge_queue(self, queue_name: str) -> int:
        """Purge all tasks from a queue"""
        if queue_name not in self.QUEUE_NAMES:
            raise ValueError(f"Invalid queue name: {queue_name}")

        try:
            length = self.redis.llen(queue_name)
            self.redis.delete(queue_name)
            return length
        except Exception as e:
            raise Exception(f"Failed to purge queue: {e}")

    def get_comprehensive_status(self) -> Dict[str, Any]:
        """Get comprehensive monitoring status"""
        cluster = self.get_cluster_stats()
        autoscaler = self.get_autoscaler_status()
        autoscaler_metrics = self.get_autoscaler_metrics()
        task_stats = self.get_task_stats()
        worker_pings = self.ping_workers()

        return {
            'timestamp': datetime.now().isoformat(),
            'cluster': {
                'total_workers': cluster.total_workers,
                'active_workers': cluster.active_workers,
                'total_queued': cluster.total_queued,
                'total_active_tasks': cluster.total_active_tasks,
                'total_processed': cluster.total_processed,
                'total_failed': cluster.total_failed,
            },
            'queues': [asdict(q) for q in cluster.queues],
            'workers': [
                {
                    **asdict(w),
                    'responsive': worker_pings.get(w.hostname, False)
                }
                for w in cluster.workers
            ],
            'autoscaler': autoscaler,
            'autoscaler_config': autoscaler_metrics.get('config', {}),
            'tasks': task_stats,
            'health': {
                'redis': self._check_redis_health(),
                'celery': len(cluster.workers) > 0,
                'autoscaler': autoscaler.get('running', False)
            }
        }

    def _check_redis_health(self) -> bool:
        """Check Redis health"""
        try:
            return self.redis.ping()
        except Exception:
            return False


# Singleton instance
_monitor = None


def get_monitor() -> WorkerMonitor:
    """Get singleton monitor instance"""
    global _monitor
    if _monitor is None:
        _monitor = WorkerMonitor()
    return _monitor
