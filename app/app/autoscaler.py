"""
Auto-scaler service for Celery workers
Monitors queue depth and scales workers up/down based on demand
"""
import os
import time
import json
import redis
import docker
from datetime import datetime
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict

# Configuration from environment
REDIS_URL = os.getenv('REDIS_URL', 'redis://redis:6379/0')
MIN_WORKERS = int(os.getenv('MIN_WORKERS', '2'))
MAX_WORKERS = int(os.getenv('MAX_WORKERS', '10'))
SCALE_UP_THRESHOLD = int(os.getenv('SCALE_UP_THRESHOLD', '10'))  # Tasks in queue to trigger scale up
SCALE_DOWN_THRESHOLD = int(os.getenv('SCALE_DOWN_THRESHOLD', '2'))  # Tasks in queue to trigger scale down
CHECK_INTERVAL = int(os.getenv('CHECK_INTERVAL', '30'))  # Seconds between checks
COOLDOWN_PERIOD = int(os.getenv('COOLDOWN_PERIOD', '60'))  # Seconds between scaling actions
SCALE_UP_STEP = int(os.getenv('SCALE_UP_STEP', '2'))  # Workers to add per scale up
SCALE_DOWN_STEP = int(os.getenv('SCALE_DOWN_STEP', '1'))  # Workers to remove per scale down


@dataclass
class QueueStats:
    """Statistics for a single queue"""
    name: str
    length: int
    active_tasks: int
    reserved_tasks: int
    scheduled_tasks: int


@dataclass
class WorkerInfo:
    """Information about a single worker"""
    hostname: str
    status: str
    active_tasks: int
    processed: int
    queues: List[str]
    concurrency: int
    pool: str


@dataclass
class ScalingDecision:
    """Record of a scaling decision"""
    timestamp: str
    action: str  # 'scale_up', 'scale_down', 'no_action'
    reason: str
    current_workers: int
    target_workers: int
    queue_depth: int


class AutoScaler:
    """
    Auto-scaler for Celery workers based on queue depth
    """

    def __init__(self):
        self.redis = redis.from_url(REDIS_URL, decode_responses=True)
        self.docker_client = None
        self.last_scale_time = 0
        self.scaling_history: List[ScalingDecision] = []

        # Queue names to monitor
        self.queues = ['high_priority', 'default', 'batch', 'low_priority', 'system']

        # Try to connect to Docker
        try:
            self.docker_client = docker.from_env()
            print("Connected to Docker daemon")
        except Exception as e:
            print(f"Warning: Could not connect to Docker: {e}")
            print("Auto-scaling will run in monitoring-only mode")

    def get_queue_lengths(self) -> Dict[str, int]:
        """Get current length of all queues"""
        queue_lengths = {}
        for queue in self.queues:
            try:
                length = self.redis.llen(queue)
                queue_lengths[queue] = length
            except Exception as e:
                print(f"Error getting length for queue {queue}: {e}")
                queue_lengths[queue] = 0
        return queue_lengths

    def get_queue_stats(self) -> List[QueueStats]:
        """Get detailed statistics for all queues"""
        stats = []
        for queue in self.queues:
            try:
                length = self.redis.llen(queue)
                # Get active tasks from Celery inspect
                active = self.redis.hlen(f"unacked:{queue}") if self.redis.exists(f"unacked:{queue}") else 0
                reserved = self.redis.llen(f"reserved:{queue}") if self.redis.exists(f"reserved:{queue}") else 0

                stats.append(QueueStats(
                    name=queue,
                    length=length,
                    active_tasks=active,
                    reserved_tasks=reserved,
                    scheduled_tasks=0
                ))
            except Exception as e:
                print(f"Error getting stats for queue {queue}: {e}")
                stats.append(QueueStats(name=queue, length=0, active_tasks=0, reserved_tasks=0, scheduled_tasks=0))

        return stats

    def get_total_queue_depth(self) -> int:
        """Get total number of pending tasks across all queues"""
        queue_lengths = self.get_queue_lengths()
        return sum(queue_lengths.values())

    def get_worker_count(self) -> int:
        """Get current number of batch workers"""
        if not self.docker_client:
            return MIN_WORKERS

        try:
            containers = self.docker_client.containers.list(
                filters={
                    'label': 'com.docker.compose.service=worker-batch',
                    'status': 'running'
                }
            )
            return len(containers) if containers else MIN_WORKERS
        except Exception as e:
            print(f"Error getting worker count: {e}")
            return MIN_WORKERS

    def get_all_workers(self) -> List[WorkerInfo]:
        """Get information about all running workers"""
        workers = []

        if not self.docker_client:
            return workers

        try:
            # Get worker containers
            containers = self.docker_client.containers.list(
                filters={
                    'name': 'worker',
                    'status': 'running'
                }
            )

            for container in containers:
                # Extract worker info from container
                name = container.name
                labels = container.labels

                workers.append(WorkerInfo(
                    hostname=name,
                    status='running',
                    active_tasks=0,  # Would need Celery inspect for accurate count
                    processed=0,
                    queues=labels.get('queues', 'default').split(','),
                    concurrency=int(labels.get('concurrency', '4')),
                    pool='prefork'
                ))
        except Exception as e:
            print(f"Error getting workers: {e}")

        return workers

    def scale_workers(self, target_count: int) -> bool:
        """Scale batch workers to target count using docker-compose"""
        if not self.docker_client:
            print("Docker client not available, cannot scale")
            return False

        current_count = self.get_worker_count()

        if target_count == current_count:
            return True

        try:
            # Use docker-compose scale command
            import subprocess
            result = subprocess.run(
                ['docker-compose', 'up', '-d', '--scale', f'worker-batch={target_count}', '--no-recreate'],
                cwd='/opt/new-grype-scanner-v1/app',
                capture_output=True,
                text=True
            )

            if result.returncode == 0:
                print(f"Scaled workers from {current_count} to {target_count}")
                return True
            else:
                print(f"Failed to scale workers: {result.stderr}")
                return False

        except Exception as e:
            print(f"Error scaling workers: {e}")
            return False

    def make_scaling_decision(self) -> ScalingDecision:
        """Determine if scaling is needed based on queue depth"""
        current_time = time.time()
        queue_depth = self.get_total_queue_depth()
        current_workers = self.get_worker_count()

        # Check cooldown period
        if current_time - self.last_scale_time < COOLDOWN_PERIOD:
            return ScalingDecision(
                timestamp=datetime.now().isoformat(),
                action='no_action',
                reason='In cooldown period',
                current_workers=current_workers,
                target_workers=current_workers,
                queue_depth=queue_depth
            )

        # Scale up decision
        if queue_depth > SCALE_UP_THRESHOLD and current_workers < MAX_WORKERS:
            target = min(current_workers + SCALE_UP_STEP, MAX_WORKERS)
            return ScalingDecision(
                timestamp=datetime.now().isoformat(),
                action='scale_up',
                reason=f'Queue depth ({queue_depth}) > threshold ({SCALE_UP_THRESHOLD})',
                current_workers=current_workers,
                target_workers=target,
                queue_depth=queue_depth
            )

        # Scale down decision
        if queue_depth < SCALE_DOWN_THRESHOLD and current_workers > MIN_WORKERS:
            target = max(current_workers - SCALE_DOWN_STEP, MIN_WORKERS)
            return ScalingDecision(
                timestamp=datetime.now().isoformat(),
                action='scale_down',
                reason=f'Queue depth ({queue_depth}) < threshold ({SCALE_DOWN_THRESHOLD})',
                current_workers=current_workers,
                target_workers=target,
                queue_depth=queue_depth
            )

        # No action needed
        return ScalingDecision(
            timestamp=datetime.now().isoformat(),
            action='no_action',
            reason='Queue depth within normal range',
            current_workers=current_workers,
            target_workers=current_workers,
            queue_depth=queue_depth
        )

    def execute_scaling(self, decision: ScalingDecision) -> bool:
        """Execute a scaling decision"""
        if decision.action == 'no_action':
            return True

        success = self.scale_workers(decision.target_workers)

        if success:
            self.last_scale_time = time.time()
            self.scaling_history.append(decision)

            # Keep only last 100 scaling decisions
            if len(self.scaling_history) > 100:
                self.scaling_history = self.scaling_history[-100:]

            # Store in Redis for monitoring
            self.redis.lpush('autoscaler:history', json.dumps(asdict(decision)))
            self.redis.ltrim('autoscaler:history', 0, 99)

        return success

    def update_metrics(self):
        """Update metrics in Redis for monitoring dashboard"""
        queue_stats = self.get_queue_stats()
        workers = self.get_all_workers()
        queue_depth = self.get_total_queue_depth()

        metrics = {
            'timestamp': datetime.now().isoformat(),
            'queue_depth': queue_depth,
            'worker_count': len(workers),
            'queues': [asdict(q) for q in queue_stats],
            'workers': [asdict(w) for w in workers],
            'config': {
                'min_workers': MIN_WORKERS,
                'max_workers': MAX_WORKERS,
                'scale_up_threshold': SCALE_UP_THRESHOLD,
                'scale_down_threshold': SCALE_DOWN_THRESHOLD,
                'cooldown_period': COOLDOWN_PERIOD
            }
        }

        self.redis.set('autoscaler:metrics', json.dumps(metrics))
        self.redis.expire('autoscaler:metrics', 120)  # Expire after 2 minutes if not updated

    def run(self):
        """Main loop for auto-scaler"""
        print(f"Starting Auto-Scaler")
        print(f"  Min Workers: {MIN_WORKERS}")
        print(f"  Max Workers: {MAX_WORKERS}")
        print(f"  Scale Up Threshold: {SCALE_UP_THRESHOLD} tasks")
        print(f"  Scale Down Threshold: {SCALE_DOWN_THRESHOLD} tasks")
        print(f"  Check Interval: {CHECK_INTERVAL} seconds")
        print(f"  Cooldown Period: {COOLDOWN_PERIOD} seconds")

        while True:
            try:
                # Update metrics
                self.update_metrics()

                # Make scaling decision
                decision = self.make_scaling_decision()

                # Log decision
                if decision.action != 'no_action':
                    print(f"[{decision.timestamp}] {decision.action.upper()}: {decision.reason}")
                    print(f"  Workers: {decision.current_workers} -> {decision.target_workers}")
                    print(f"  Queue Depth: {decision.queue_depth}")

                # Execute scaling
                self.execute_scaling(decision)

                # Store current status
                status = {
                    'running': True,
                    'last_check': datetime.now().isoformat(),
                    'last_decision': asdict(decision),
                    'queue_depth': decision.queue_depth,
                    'worker_count': decision.current_workers
                }
                self.redis.set('autoscaler:status', json.dumps(status))

            except Exception as e:
                print(f"Error in auto-scaler loop: {e}")
                import traceback
                traceback.print_exc()

            time.sleep(CHECK_INTERVAL)


def main():
    """Entry point for auto-scaler"""
    scaler = AutoScaler()
    scaler.run()


if __name__ == '__main__':
    main()
