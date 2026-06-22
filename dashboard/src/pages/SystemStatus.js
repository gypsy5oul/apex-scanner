import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Button,
  Grid,
  Chip,
  Alert,
  CircularProgress,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  LinearProgress,
  Divider,
  IconButton,
  Tooltip,
} from '@mui/material';
import PageHeader from '../components/PageHeader';
import {
  Refresh,
  Sync,
  Update,
  CheckCircle,
  Warning,
  Error as ErrorIcon,
  Storage,
  Speed,
  Schedule,
  Notifications,
} from '@mui/icons-material';
import {
  getToolVersions,
  getDbStatus,
  triggerDbUpdate,
  refreshSystemStatus,
  getUpdateHistory,
  getSystemNotifications,
} from '../api';
import { PageHeaderSkeleton, StatCardsSkeleton, CardGridSkeleton } from '../components/LoadingSkeletons';
import { useToast } from '../components/Feedback';

function SystemStatus() {
  const toast = useToast();
  const [loading, setLoading] = useState(true);
  const [updating, setUpdating] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);
  const [toolVersions, setToolVersions] = useState(null);
  const [dbStatus, setDbStatus] = useState(null);
  const [updateHistory, setUpdateHistory] = useState([]);
  const [notifications, setNotifications] = useState([]);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [toolsRes, dbRes, historyRes, notifRes] = await Promise.all([
        getToolVersions(),
        getDbStatus(),
        getUpdateHistory(10),
        getSystemNotifications(10),
      ]);

      setToolVersions(toolsRes.data);
      setDbStatus(dbRes.data);
      setUpdateHistory(historyRes.data.history || []);
      setNotifications(notifRes.data.notifications || []);
    } catch (err) {
      setError('Failed to fetch system status');
      toast('Failed to fetch system status: ' + (err.response?.data?.detail || err.message), 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  // Re-fetch all panels without unmounting the page into a spinner.
  // Returns the latest db "last fetched" markers so callers can detect a
  // genuine update instead of claiming success on a timer.
  const reloadData = async () => {
    try {
      const [toolsRes, dbRes, historyRes, notifRes] = await Promise.all([
        getToolVersions(),
        getDbStatus(),
        getUpdateHistory(10),
        getSystemNotifications(10),
      ]);
      setToolVersions(toolsRes.data);
      setDbStatus(dbRes.data);
      setUpdateHistory(historyRes.data.history || []);
      setNotifications(notifRes.data.notifications || []);
      return dbRes.data?.last_updates || null;
    } catch (err) {
      // silent reload, don't overwrite existing data
      return null;
    }
  };

  // Poll reloadData until the db "last fetched" markers change vs the snapshot
  // taken when the action was triggered, or until we run out of attempts.
  const pollUntilUpdated = async (before, { attempts = 6, intervalMs = 3000 } = {}) => {
    const baseline = JSON.stringify(before || {});
    for (let i = 0; i < attempts; i += 1) {
      // eslint-disable-next-line no-await-in-loop
      await new Promise((resolve) => setTimeout(resolve, intervalMs));
      // eslint-disable-next-line no-await-in-loop
      const after = await reloadData();
      if (after && JSON.stringify(after) !== baseline) return true;
    }
    return false;
  };

  const handleUpdateDb = async () => {
    setUpdating(true);
    setError(null);
    setSuccess(null);
    try {
      const before = dbStatus?.last_updates || null;
      await triggerDbUpdate();
      setSuccess('Vulnerability database update triggered. This may take a few minutes.');
      toast('Database update triggered', 'info');
      const completed = await pollUntilUpdated(before);
      if (completed) {
        setSuccess('Vulnerability database updated.');
        toast('Vulnerability database updated', 'success');
      } else {
        setSuccess('Update triggered. It is still running — refresh later to confirm.');
      }
    } catch (err) {
      setError('Failed to trigger database update');
      toast('Failed to trigger database update: ' + (err.response?.data?.detail || err.message), 'error');
    } finally {
      setUpdating(false);
    }
  };

  const handleRefreshStatus = async () => {
    setRefreshing(true);
    setError(null);
    setSuccess(null);
    try {
      const before = dbStatus?.last_updates || null;
      await refreshSystemStatus();
      setSuccess('Status refresh triggered.');
      toast('Status refresh triggered', 'info');
      // Only claim success once the data actually reflects the refresh.
      const updated = await pollUntilUpdated(before);
      if (updated) {
        setSuccess('Status refreshed.');
        toast('Status refreshed', 'success');
        setTimeout(() => setSuccess(null), 3000);
      } else {
        setSuccess('Refresh triggered — data has not changed yet. Try again shortly.');
      }
    } catch (err) {
      setError('Failed to refresh system status');
      toast('Failed to refresh system status: ' + (err.response?.data?.detail || err.message), 'error');
    } finally {
      setRefreshing(false);
    }
  };

  if (loading) {
    return (
      <Box>
        <PageHeaderSkeleton />
        <StatCardsSkeleton count={3} />
        <Box sx={{ mt: 3 }}>
          <CardGridSkeleton count={2} height={220} cols={{ xs: 12, md: 6 }} />
        </Box>
      </Box>
    );
  }

  return (
    <Box>
      <PageHeader
        title="System Status"
        description="Monitor scanning tools and vulnerability databases"
        actions={
          <>
            <Button
              variant="outlined"
              startIcon={<Refresh />}
              onClick={reloadData}
            >
              Refresh View
            </Button>
            <Tooltip title="Trigger worker to refresh tool versions and DB status">
              <Button
                variant="outlined"
                color="secondary"
                startIcon={refreshing ? <CircularProgress size={20} /> : <Sync />}
                onClick={handleRefreshStatus}
                disabled={refreshing}
              >
                Refresh Status
              </Button>
            </Tooltip>
            <Button
              variant="contained"
              startIcon={updating ? <CircularProgress size={20} /> : <Update />}
              onClick={handleUpdateDb}
              disabled={updating}
            >
              Update Databases
            </Button>
          </>
        }
      />

      {error && (
        <Alert severity="error" onClose={() => setError(null)} sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}
      {success && (
        <Alert severity="success" onClose={() => setSuccess(null)} sx={{ mb: 2 }}>
          {success}
        </Alert>
      )}

      {/* Tool Versions */}
      <Grid container spacing={3} mb={3}>
        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" gap={1} mb={2}>
                <Speed color="primary" />
                <Typography variant="h6">Scanning Tools</Typography>
                {toolVersions?.updates_available && (
                  <Chip label="Updates Available" color="warning" size="small" />
                )}
              </Box>
              <Grid container spacing={2}>
                {toolVersions?.tools && Object.entries(toolVersions.tools).map(([name, info]) => (
                  <Grid item xs={12} md={4} key={name}>
                    <Card variant="outlined">
                      <CardContent>
                        <Box display="flex" justifyContent="space-between" alignItems="center">
                          <Typography variant="h6" textTransform="capitalize">
                            {name}
                          </Typography>
                          {info.update_available ? (
                            <Chip
                              icon={<Warning />}
                              label="Update Available"
                              color="warning"
                              size="small"
                            />
                          ) : (
                            <Chip
                              icon={<CheckCircle />}
                              label="Up to Date"
                              color="success"
                              size="small"
                            />
                          )}
                        </Box>
                        <Box mt={2}>
                          <Typography variant="body2" color="text.secondary">
                            Current Version
                          </Typography>
                          <Typography variant="h6" fontFamily="monospace">
                            {info.current_version || 'Unknown'}
                          </Typography>
                        </Box>
                        {info.update_available && (
                          <Box mt={1}>
                            <Typography variant="body2" color="text.secondary">
                              Latest Version
                            </Typography>
                            <Typography variant="body1" fontFamily="monospace" color="warning.main">
                              {info.latest_version}
                            </Typography>
                          </Box>
                        )}
                        <Typography variant="caption" color="text.secondary" display="block" mt={1}>
                          Last checked: {info.last_checked ? new Date(info.last_checked).toLocaleString() : 'Never'}
                        </Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Database Status */}
      <Grid container spacing={3} mb={3}>
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" gap={1} mb={2}>
                <Storage color="primary" />
                <Typography variant="h6">Grype Database</Typography>
              </Box>
              {dbStatus?.grype ? (
                <Box>
                  <Grid container spacing={2}>
                    <Grid item xs={6}>
                      <Typography variant="body2" color="text.secondary">
                        DB Build Date (vendor)
                      </Typography>
                      <Typography variant="body1">
                        {dbStatus.grype.built
                          ? new Date(dbStatus.grype.built).toLocaleString()
                          : 'Unknown'}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        When Anchore published this DB, not when we fetched it
                      </Typography>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="body2" color="text.secondary">
                        Last Fetched
                      </Typography>
                      <Typography variant="body1">
                        {dbStatus.last_updates?.grype
                          ? new Date(dbStatus.last_updates.grype).toLocaleString()
                          : 'Never'}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        Schema {dbStatus.grype.schema_version || '—'}
                      </Typography>
                    </Grid>
                  </Grid>
                  <Divider sx={{ my: 2 }} />
                  <Box display="flex" justifyContent="space-between" alignItems="center">
                    <Box>
                      <Typography variant="body2" color="text.secondary">
                        Hours Since Update
                      </Typography>
                      <Typography variant="h6">
                        {dbStatus.grype_hours_since_update?.toFixed(1) || 'Unknown'}
                      </Typography>
                    </Box>
                    {dbStatus.grype_update_due ? (
                      <Chip
                        icon={<Warning />}
                        label="Update Recommended"
                        color="warning"
                      />
                    ) : (
                      <Chip
                        icon={<CheckCircle />}
                        label="Up to Date"
                        color="success"
                      />
                    )}
                  </Box>
                </Box>
              ) : (
                <Typography color="text.secondary">No database information available</Typography>
              )}
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" gap={1} mb={2}>
                <Schedule color="primary" />
                <Typography variant="h6">Last Updates</Typography>
              </Box>
              {dbStatus?.last_updates ? (
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell>Tool</TableCell>
                        <TableCell>Last Updated</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {Object.entries(dbStatus.last_updates).map(([tool, timestamp]) => (
                        <TableRow key={tool}>
                          <TableCell>
                            <Typography textTransform="capitalize">{tool}</Typography>
                          </TableCell>
                          <TableCell>
                            {timestamp ? new Date(timestamp).toLocaleString() : 'Never'}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              ) : (
                <Typography color="text.secondary">No update history available</Typography>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Update History */}
      <Grid container spacing={3}>
        <Grid item xs={12} md={8}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Update History
              </Typography>
              {updateHistory.length > 0 ? (
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell>Tool</TableCell>
                        <TableCell>Action</TableCell>
                        <TableCell>Status</TableCell>
                        <TableCell>Timestamp</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {updateHistory.map((entry, index) => (
                        <TableRow key={index}>
                          <TableCell>
                            <Typography textTransform="capitalize">{entry.tool}</Typography>
                          </TableCell>
                          <TableCell>{entry.action}</TableCell>
                          <TableCell>
                            {entry.success ? (
                              <Chip icon={<CheckCircle />} label="Success" color="success" size="small" />
                            ) : (
                              <Chip icon={<ErrorIcon />} label="Failed" color="error" size="small" />
                            )}
                          </TableCell>
                          <TableCell>
                            {entry.timestamp ? new Date(entry.timestamp).toLocaleString() : '-'}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              ) : (
                <Typography color="text.secondary" textAlign="center" py={3}>
                  No update history available
                </Typography>
              )}
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" gap={1} mb={2}>
                <Notifications color="primary" />
                <Typography variant="h6">Notifications</Typography>
              </Box>
              {notifications.length > 0 ? (
                <Box>
                  {notifications.map((notif, index) => (
                    <Alert
                      key={index}
                      severity={notif.type === 'tool_updates_available' ? 'warning' : 'info'}
                      sx={{ mb: 1 }}
                    >
                      <Typography variant="body2">
                        {notif.type === 'tool_updates_available'
                          ? `Updates available for: ${notif.tools?.join(', ')}`
                          : notif.type}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {notif.timestamp ? new Date(notif.timestamp).toLocaleString() : ''}
                      </Typography>
                    </Alert>
                  ))}
                </Box>
              ) : (
                <Typography color="text.secondary" textAlign="center" py={3}>
                  No notifications
                </Typography>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Auto-Update Info */}
      <Card sx={{ mt: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Automatic Updates
          </Typography>
          <Alert severity="info">
            Vulnerability databases are automatically updated every 12 hours via scheduled task.
            Base images are scanned daily. You can trigger manual updates using the button above.
          </Alert>
        </CardContent>
      </Card>
    </Box>
  );
}

export default SystemStatus;
