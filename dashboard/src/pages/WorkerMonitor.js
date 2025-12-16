import React, { useState, useEffect, useCallback } from 'react';
import {
  Box,
  Paper,
  Typography,
  Grid,
  Card,
  CardContent,
  Chip,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  LinearProgress,
  Alert,
  CircularProgress,
  Tooltip,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Divider,
} from '@mui/material';
import RefreshIcon from '@mui/icons-material/Refresh';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import DeleteIcon from '@mui/icons-material/Delete';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import WarningIcon from '@mui/icons-material/Warning';
import SpeedIcon from '@mui/icons-material/Speed';
import QueueIcon from '@mui/icons-material/Queue';
import GroupWorkIcon from '@mui/icons-material/GroupWork';
import TrendingUpIcon from '@mui/icons-material/TrendingUp';
import TrendingDownIcon from '@mui/icons-material/TrendingDown';
import MemoryIcon from '@mui/icons-material/Memory';
import TimelineIcon from '@mui/icons-material/Timeline';
import {
  getWorkersStatus,
  getQueueStats,
  getAutoscalerStatus,
  getScalingHistory,
  pingWorkers,
  purgeQueue,
  getWorkersHealth,
} from '../api';

// Auto-refresh interval in ms
const REFRESH_INTERVAL = 10000;

function WorkerMonitor() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [status, setStatus] = useState(null);
  const [queueStats, setQueueStats] = useState(null);
  const [autoscaler, setAutoscaler] = useState(null);
  const [scalingHistory, setScalingHistory] = useState([]);
  const [health, setHealth] = useState(null);
  const [refreshing, setRefreshing] = useState(false);
  const [purgeDialogOpen, setPurgeDialogOpen] = useState(false);
  const [selectedQueue, setSelectedQueue] = useState(null);
  const [autoRefresh, setAutoRefresh] = useState(true);

  const fetchData = useCallback(async () => {
    try {
      const [statusRes, queueRes, autoscalerRes, historyRes, healthRes] = await Promise.all([
        getWorkersStatus(),
        getQueueStats(),
        getAutoscalerStatus(),
        getScalingHistory(10),
        getWorkersHealth(),
      ]);

      setStatus(statusRes.data);
      setQueueStats(queueRes.data);
      setAutoscaler(autoscalerRes.data);
      setScalingHistory(historyRes.data?.history || []);
      setHealth(healthRes.data);
      setError(null);
    } catch (err) {
      setError('Failed to fetch worker status');
      console.error(err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Auto-refresh
  useEffect(() => {
    if (!autoRefresh) return;

    const interval = setInterval(fetchData, REFRESH_INTERVAL);
    return () => clearInterval(interval);
  }, [autoRefresh, fetchData]);

  const handleRefresh = async () => {
    setRefreshing(true);
    await fetchData();
    setRefreshing(false);
  };

  const handlePingWorkers = async () => {
    try {
      const res = await pingWorkers();
      alert(`Pinged ${res.data.total} workers. ${res.data.responsive} responded.`);
      fetchData();
    } catch (err) {
      alert('Failed to ping workers');
    }
  };

  const handlePurgeQueue = async () => {
    if (!selectedQueue) return;

    try {
      await purgeQueue(selectedQueue);
      setPurgeDialogOpen(false);
      setSelectedQueue(null);
      fetchData();
    } catch (err) {
      alert('Failed to purge queue');
    }
  };

  const openPurgeDialog = (queueName) => {
    setSelectedQueue(queueName);
    setPurgeDialogOpen(true);
  };

  const getHealthColor = (healthStatus) => {
    switch (healthStatus) {
      case 'healthy':
        return 'success';
      case 'degraded':
        return 'warning';
      case 'unhealthy':
        return 'error';
      default:
        return 'default';
    }
  };

  const getHealthIcon = (healthStatus) => {
    switch (healthStatus) {
      case 'healthy':
        return <CheckCircleIcon color="success" />;
      case 'degraded':
        return <WarningIcon color="warning" />;
      case 'unhealthy':
        return <ErrorIcon color="error" />;
      default:
        return <WarningIcon />;
    }
  };

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', mt: 4 }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box>
          <Typography variant="h4">Worker Monitor</Typography>
          <Typography variant="body2" color="text.secondary">
            Real-time monitoring of Celery workers and task queues
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
          <Chip
            label={autoRefresh ? 'Auto-refresh ON' : 'Auto-refresh OFF'}
            color={autoRefresh ? 'success' : 'default'}
            onClick={() => setAutoRefresh(!autoRefresh)}
            size="small"
          />
          <Button
            variant="outlined"
            startIcon={refreshing ? <CircularProgress size={20} /> : <RefreshIcon />}
            onClick={handleRefresh}
            disabled={refreshing}
          >
            Refresh
          </Button>
          <Button
            variant="outlined"
            startIcon={<PlayArrowIcon />}
            onClick={handlePingWorkers}
          >
            Ping Workers
          </Button>
        </Box>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {/* Health Overview */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                {health && getHealthIcon(health.status)}
                <Typography variant="h6">System Health</Typography>
              </Box>
              <Chip
                label={health?.status?.toUpperCase() || 'UNKNOWN'}
                color={getHealthColor(health?.status)}
                sx={{ mb: 1 }}
              />
              <Typography variant="body2" color="text.secondary">
                Redis: {health?.redis || 'unknown'}
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                <GroupWorkIcon color="primary" />
                <Typography variant="h6">Workers</Typography>
              </Box>
              <Typography variant="h3" color="primary">
                {status?.cluster?.active_workers || 0}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                of {status?.cluster?.total_workers || 0} total
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                <QueueIcon color="primary" />
                <Typography variant="h6">Queued Tasks</Typography>
              </Box>
              <Typography variant="h3" color={status?.cluster?.total_queued > 10 ? 'error.main' : 'primary'}>
                {status?.cluster?.total_queued || 0}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {status?.cluster?.total_active_tasks || 0} active
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                <SpeedIcon color="primary" />
                <Typography variant="h6">Processed</Typography>
              </Box>
              <Typography variant="h3" color="success.main">
                {status?.cluster?.total_processed || 0}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {status?.cluster?.total_failed || 0} failed
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <Grid container spacing={3}>
        {/* Queue Statistics */}
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              <QueueIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
              Queue Statistics
            </Typography>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Queue</TableCell>
                    <TableCell align="right">Pending</TableCell>
                    <TableCell align="right">Consumers</TableCell>
                    <TableCell align="center">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {queueStats?.queues?.map((queue) => (
                    <TableRow key={queue.name}>
                      <TableCell>
                        <Chip
                          label={queue.name}
                          size="small"
                          variant="outlined"
                          color={
                            queue.name === 'high_priority'
                              ? 'error'
                              : queue.name === 'batch'
                              ? 'warning'
                              : queue.name === 'system'
                              ? 'info'
                              : 'default'
                          }
                        />
                      </TableCell>
                      <TableCell align="right">
                        <Typography
                          color={queue.length > 5 ? 'error' : queue.length > 0 ? 'warning.main' : 'text.primary'}
                          fontWeight={queue.length > 0 ? 'bold' : 'normal'}
                        >
                          {queue.length}
                        </Typography>
                      </TableCell>
                      <TableCell align="right">{queue.consumers}</TableCell>
                      <TableCell align="center">
                        <Tooltip title="Purge Queue">
                          <IconButton
                            size="small"
                            color="error"
                            onClick={() => openPurgeDialog(queue.name)}
                            disabled={queue.length === 0}
                          >
                            <DeleteIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>
        </Grid>

        {/* Workers List */}
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              <MemoryIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
              Active Workers
            </Typography>
            {status?.workers?.length > 0 ? (
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Worker</TableCell>
                      <TableCell align="center">Status</TableCell>
                      <TableCell align="right">Active</TableCell>
                      <TableCell align="right">Concurrency</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {status.workers.map((worker) => (
                      <TableRow key={worker.hostname}>
                        <TableCell>
                          <Typography variant="body2" fontFamily="monospace">
                            {worker.hostname.split('@')[0]}
                          </Typography>
                        </TableCell>
                        <TableCell align="center">
                          <Chip
                            size="small"
                            label={worker.responsive ? 'Online' : 'Offline'}
                            color={worker.responsive ? 'success' : 'error'}
                          />
                        </TableCell>
                        <TableCell align="right">{worker.active}</TableCell>
                        <TableCell align="right">{worker.concurrency}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            ) : (
              <Alert severity="warning">No workers detected</Alert>
            )}
          </Paper>
        </Grid>

        {/* Autoscaler Status */}
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              <TrendingUpIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
              Autoscaler Status
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={6}>
                <Typography variant="body2" color="text.secondary">Status</Typography>
                <Chip
                  label={autoscaler?.status?.running ? 'Running' : 'Stopped'}
                  color={autoscaler?.status?.running ? 'success' : 'error'}
                  size="small"
                />
              </Grid>
              <Grid item xs={6}>
                <Typography variant="body2" color="text.secondary">Last Check</Typography>
                <Typography variant="body1">
                  {autoscaler?.status?.last_check
                    ? new Date(autoscaler.status.last_check).toLocaleTimeString()
                    : 'N/A'}
                </Typography>
              </Grid>
              <Grid item xs={6}>
                <Typography variant="body2" color="text.secondary">Current Workers</Typography>
                <Typography variant="h6">{autoscaler?.status?.worker_count || 0}</Typography>
              </Grid>
              <Grid item xs={6}>
                <Typography variant="body2" color="text.secondary">Queue Depth</Typography>
                <Typography variant="h6">{autoscaler?.status?.queue_depth || 0}</Typography>
              </Grid>
            </Grid>

            <Divider sx={{ my: 2 }} />

            <Typography variant="subtitle2" gutterBottom>Configuration</Typography>
            <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
              <Chip
                label={`Min: ${autoscaler?.config?.min_workers || 2}`}
                size="small"
                variant="outlined"
              />
              <Chip
                label={`Max: ${autoscaler?.config?.max_workers || 10}`}
                size="small"
                variant="outlined"
              />
              <Chip
                label={`Scale Up: ${autoscaler?.config?.scale_up_threshold || 10} tasks`}
                size="small"
                variant="outlined"
              />
              <Chip
                label={`Scale Down: ${autoscaler?.config?.scale_down_threshold || 2} tasks`}
                size="small"
                variant="outlined"
              />
            </Box>
          </Paper>
        </Grid>

        {/* Scaling History */}
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              <TimelineIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
              Recent Scaling Events
            </Typography>
            {scalingHistory.length > 0 ? (
              <List dense>
                {scalingHistory.slice(0, 5).map((event, idx) => (
                  <ListItem key={idx}>
                    <ListItemIcon>
                      {event.action === 'scale_up' ? (
                        <TrendingUpIcon color="success" />
                      ) : event.action === 'scale_down' ? (
                        <TrendingDownIcon color="warning" />
                      ) : (
                        <CheckCircleIcon color="action" />
                      )}
                    </ListItemIcon>
                    <ListItemText
                      primary={
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <Chip
                            label={event.action?.replace('_', ' ').toUpperCase()}
                            size="small"
                            color={
                              event.action === 'scale_up'
                                ? 'success'
                                : event.action === 'scale_down'
                                ? 'warning'
                                : 'default'
                            }
                          />
                          <Typography variant="body2">
                            {event.current_workers} → {event.target_workers} workers
                          </Typography>
                        </Box>
                      }
                      secondary={
                        <>
                          <Typography variant="caption" display="block">
                            {event.reason}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            {new Date(event.timestamp).toLocaleString()}
                          </Typography>
                        </>
                      }
                    />
                  </ListItem>
                ))}
              </List>
            ) : (
              <Typography variant="body2" color="text.secondary">
                No recent scaling events
              </Typography>
            )}
          </Paper>
        </Grid>

        {/* Task Statistics */}
        <Grid item xs={12}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Task Statistics
            </Typography>
            <Grid container spacing={3}>
              <Grid item xs={6} md={2}>
                <Typography variant="body2" color="text.secondary">Total Scans</Typography>
                <Typography variant="h5">{status?.tasks?.total_scans || 0}</Typography>
              </Grid>
              <Grid item xs={6} md={2}>
                <Typography variant="body2" color="text.secondary">Completed</Typography>
                <Typography variant="h5" color="success.main">
                  {status?.tasks?.completed_scans || 0}
                </Typography>
              </Grid>
              <Grid item xs={6} md={2}>
                <Typography variant="body2" color="text.secondary">In Progress</Typography>
                <Typography variant="h5" color="info.main">
                  {status?.tasks?.in_progress || 0}
                </Typography>
              </Grid>
              <Grid item xs={6} md={2}>
                <Typography variant="body2" color="text.secondary">Failed</Typography>
                <Typography variant="h5" color="error.main">
                  {status?.tasks?.failed_scans || 0}
                </Typography>
              </Grid>
              <Grid item xs={12} md={4}>
                <Typography variant="body2" color="text.secondary" gutterBottom>
                  Success Rate
                </Typography>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                  <LinearProgress
                    variant="determinate"
                    value={
                      status?.tasks?.total_scans > 0
                        ? (status.tasks.completed_scans / status.tasks.total_scans) * 100
                        : 0
                    }
                    sx={{ flexGrow: 1, height: 10, borderRadius: 5 }}
                    color={
                      status?.tasks?.total_scans > 0 &&
                      status.tasks.completed_scans / status.tasks.total_scans > 0.9
                        ? 'success'
                        : 'warning'
                    }
                  />
                  <Typography variant="body2">
                    {status?.tasks?.total_scans > 0
                      ? ((status.tasks.completed_scans / status.tasks.total_scans) * 100).toFixed(1)
                      : 0}
                    %
                  </Typography>
                </Box>
              </Grid>
            </Grid>
          </Paper>
        </Grid>
      </Grid>

      {/* Purge Confirmation Dialog */}
      <Dialog open={purgeDialogOpen} onClose={() => setPurgeDialogOpen(false)}>
        <DialogTitle>Purge Queue?</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to purge all tasks from the <strong>{selectedQueue}</strong> queue?
            This action cannot be undone.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setPurgeDialogOpen(false)}>Cancel</Button>
          <Button onClick={handlePurgeQueue} color="error" variant="contained">
            Purge
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

export default WorkerMonitor;
