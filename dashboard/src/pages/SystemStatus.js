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
import {
  Refresh,
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

function SystemStatus() {
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
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleUpdateDb = async () => {
    setUpdating(true);
    try {
      await triggerDbUpdate();
      setSuccess('Vulnerability database update started. This may take a few minutes.');
      // Refresh after a short delay
      setTimeout(fetchData, 5000);
    } catch (err) {
      setError('Failed to trigger database update');
    } finally {
      setUpdating(false);
    }
  };

  const handleRefreshStatus = async () => {
    setRefreshing(true);
    try {
      await refreshSystemStatus();
      setSuccess('Status refresh triggered. Please wait a moment...');
      // Refresh data after a short delay to allow worker to update cache
      setTimeout(fetchData, 3000);
    } catch (err) {
      setError('Failed to refresh system status');
    } finally {
      setRefreshing(false);
    }
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Box>
          <Typography variant="h4" fontWeight="bold">
            System Status
          </Typography>
          <Typography color="textSecondary">
            Monitor scanning tools and vulnerability databases
          </Typography>
        </Box>
        <Box display="flex" gap={2}>
          <Button
            variant="outlined"
            startIcon={<Refresh />}
            onClick={fetchData}
          >
            Refresh View
          </Button>
          <Tooltip title="Trigger worker to refresh tool versions and DB status">
            <Button
              variant="outlined"
              color="secondary"
              startIcon={refreshing ? <CircularProgress size={20} /> : <Refresh />}
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
        </Box>
      </Box>

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
                          <Typography variant="body2" color="textSecondary">
                            Current Version
                          </Typography>
                          <Typography variant="h6" fontFamily="monospace">
                            {info.current_version || 'Unknown'}
                          </Typography>
                        </Box>
                        {info.update_available && (
                          <Box mt={1}>
                            <Typography variant="body2" color="textSecondary">
                              Latest Version
                            </Typography>
                            <Typography variant="body1" fontFamily="monospace" color="warning.main">
                              {info.latest_version}
                            </Typography>
                          </Box>
                        )}
                        <Typography variant="caption" color="textSecondary" display="block" mt={1}>
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
                      <Typography variant="body2" color="textSecondary">Built</Typography>
                      <Typography variant="body1">
                        {dbStatus.grype.built || 'Unknown'}
                      </Typography>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="body2" color="textSecondary">Schema Version</Typography>
                      <Typography variant="body1">
                        {dbStatus.grype.schema_version || 'Unknown'}
                      </Typography>
                    </Grid>
                  </Grid>
                  <Divider sx={{ my: 2 }} />
                  <Box display="flex" justifyContent="space-between" alignItems="center">
                    <Box>
                      <Typography variant="body2" color="textSecondary">
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
                <Typography color="textSecondary">No database information available</Typography>
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
                <Typography color="textSecondary">No update history available</Typography>
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
                <Typography color="textSecondary" textAlign="center" py={3}>
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
                      <Typography variant="caption" color="textSecondary">
                        {notif.timestamp ? new Date(notif.timestamp).toLocaleString() : ''}
                      </Typography>
                    </Alert>
                  ))}
                </Box>
              ) : (
                <Typography color="textSecondary" textAlign="center" py={3}>
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
