import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Switch,
  FormControlLabel,
  Alert,
  CircularProgress,
  Tooltip,
  Grid,
} from '@mui/material';
import {
  Add,
  Delete,
  Edit,
  PlayArrow,
  Schedule,
  Notifications,
  Refresh,
} from '@mui/icons-material';
import {
  getSchedules,
  createSchedule,
  deleteSchedule,
  runScheduleNow,
  testNotification,
} from '../api';

function Schedules() {
  const [schedules, setSchedules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [testDialogOpen, setTestDialogOpen] = useState(false);
  const [newSchedule, setNewSchedule] = useState({
    name: '',
    images: '',
    cron_expression: '0 6 * * *',
    google_chat_webhook: '',
    description: '',
    enabled: true,
  });
  const [webhookTest, setWebhookTest] = useState('');

  const fetchSchedules = async () => {
    setLoading(true);
    try {
      const res = await getSchedules();
      setSchedules(res.data.schedules || []);
    } catch (err) {
      setError('Failed to fetch schedules');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSchedules();
  }, []);

  const handleCreate = async () => {
    try {
      const images = newSchedule.images.split('\n').filter((i) => i.trim());
      await createSchedule({
        ...newSchedule,
        images,
      });
      setSuccess('Schedule created successfully');
      setDialogOpen(false);
      setNewSchedule({
        name: '',
        images: '',
        cron_expression: '0 6 * * *',
        google_chat_webhook: '',
        description: '',
        enabled: true,
      });
      fetchSchedules();
    } catch (err) {
      setError('Failed to create schedule');
    }
  };

  const handleDelete = async (name) => {
    if (!window.confirm(`Delete schedule "${name}"?`)) return;
    try {
      await deleteSchedule(name);
      setSuccess('Schedule deleted');
      fetchSchedules();
    } catch (err) {
      setError('Failed to delete schedule');
    }
  };

  const handleRunNow = async (name) => {
    try {
      await runScheduleNow(name);
      setSuccess(`Triggered scan for "${name}"`);
    } catch (err) {
      setError('Failed to run schedule');
    }
  };

  const handleTestWebhook = async () => {
    try {
      await testNotification(webhookTest);
      setSuccess('Test notification sent successfully');
      setTestDialogOpen(false);
    } catch (err) {
      setError('Failed to send test notification');
    }
  };

  const cronToHuman = (cron) => {
    const parts = cron.split(' ');
    if (parts.length !== 5) return cron;
    const [minute, hour, day, month, weekday] = parts;

    if (day === '*' && month === '*' && weekday === '*') {
      return `Daily at ${hour.padStart(2, '0')}:${minute.padStart(2, '0')}`;
    }
    if (day === '*' && month === '*' && weekday !== '*') {
      const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
      return `${days[parseInt(weekday)]} at ${hour}:${minute}`;
    }
    return cron;
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
            Scheduled Scans
          </Typography>
          <Typography color="textSecondary">
            Configure automated security scans with notifications
          </Typography>
        </Box>
        <Box display="flex" gap={2}>
          <Button
            variant="outlined"
            startIcon={<Notifications />}
            onClick={() => setTestDialogOpen(true)}
          >
            Test Webhook
          </Button>
          <Button
            variant="contained"
            startIcon={<Add />}
            onClick={() => setDialogOpen(true)}
          >
            Create Schedule
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

      {schedules.length === 0 ? (
        <Card>
          <CardContent>
            <Box textAlign="center" py={4}>
              <Schedule sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
              <Typography variant="h6" gutterBottom>
                No Scheduled Scans
              </Typography>
              <Typography color="textSecondary" mb={3}>
                Create your first scheduled scan to automate security checks
              </Typography>
              <Button
                variant="contained"
                startIcon={<Add />}
                onClick={() => setDialogOpen(true)}
              >
                Create Schedule
              </Button>
            </Box>
          </CardContent>
        </Card>
      ) : (
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Name</TableCell>
                <TableCell>Images</TableCell>
                <TableCell>Schedule</TableCell>
                <TableCell>Notifications</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Last Run</TableCell>
                <TableCell align="right">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {schedules.map((schedule) => (
                <TableRow key={schedule.name}>
                  <TableCell>
                    <Typography fontWeight="medium">{schedule.name}</Typography>
                    {schedule.description && (
                      <Typography variant="body2" color="textSecondary">
                        {schedule.description}
                      </Typography>
                    )}
                  </TableCell>
                  <TableCell>
                    {Array.isArray(schedule.images) ? (
                      <Chip
                        label={`${schedule.images.length} images`}
                        size="small"
                        variant="outlined"
                      />
                    ) : (
                      <Chip label="1 image" size="small" variant="outlined" />
                    )}
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2">
                      {cronToHuman(schedule.cron_expression)}
                    </Typography>
                    <Typography variant="caption" color="textSecondary">
                      {schedule.cron_expression}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    {schedule.google_chat_webhook ? (
                      <Chip
                        icon={<Notifications />}
                        label="Google Chat"
                        size="small"
                        color="primary"
                        variant="outlined"
                      />
                    ) : (
                      <Typography variant="body2" color="textSecondary">
                        None
                      </Typography>
                    )}
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={schedule.enabled === true || schedule.enabled === 'true' ? 'Active' : 'Disabled'}
                      size="small"
                      color={schedule.enabled === true || schedule.enabled === 'true' ? 'success' : 'default'}
                    />
                  </TableCell>
                  <TableCell>
                    {schedule.last_run ? (
                      <Typography variant="body2">
                        {new Date(schedule.last_run).toLocaleString()}
                      </Typography>
                    ) : (
                      <Typography variant="body2" color="textSecondary">
                        Never
                      </Typography>
                    )}
                  </TableCell>
                  <TableCell align="right">
                    <Tooltip title="Run Now">
                      <IconButton
                        color="primary"
                        onClick={() => handleRunNow(schedule.name)}
                      >
                        <PlayArrow />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Delete">
                      <IconButton
                        color="error"
                        onClick={() => handleDelete(schedule.name)}
                      >
                        <Delete />
                      </IconButton>
                    </Tooltip>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      {/* Create Schedule Dialog */}
      <Dialog open={dialogOpen} onClose={() => setDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>Create Scheduled Scan</DialogTitle>
        <DialogContent>
          <Grid container spacing={2} sx={{ mt: 1 }}>
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label="Schedule Name"
                value={newSchedule.name}
                onChange={(e) => setNewSchedule({ ...newSchedule, name: e.target.value })}
                placeholder="daily-base-images"
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label="Cron Expression"
                value={newSchedule.cron_expression}
                onChange={(e) =>
                  setNewSchedule({ ...newSchedule, cron_expression: e.target.value })
                }
                helperText="Format: minute hour day month weekday (e.g., 0 6 * * * for daily at 6 AM)"
              />
            </Grid>
            <Grid item xs={12}>
              <TextField
                fullWidth
                multiline
                rows={4}
                label="Images (one per line)"
                value={newSchedule.images}
                onChange={(e) => setNewSchedule({ ...newSchedule, images: e.target.value })}
                placeholder="nginx:latest&#10;alpine:3.19&#10;ubuntu:22.04"
              />
            </Grid>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Google Chat Webhook URL (optional)"
                value={newSchedule.google_chat_webhook}
                onChange={(e) =>
                  setNewSchedule({ ...newSchedule, google_chat_webhook: e.target.value })
                }
                placeholder="https://chat.googleapis.com/v1/spaces/..."
              />
            </Grid>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Description"
                value={newSchedule.description}
                onChange={(e) =>
                  setNewSchedule({ ...newSchedule, description: e.target.value })
                }
              />
            </Grid>
            <Grid item xs={12}>
              <FormControlLabel
                control={
                  <Switch
                    checked={newSchedule.enabled}
                    onChange={(e) =>
                      setNewSchedule({ ...newSchedule, enabled: e.target.checked })
                    }
                  />
                }
                label="Enable schedule immediately"
              />
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDialogOpen(false)}>Cancel</Button>
          <Button variant="contained" onClick={handleCreate}>
            Create
          </Button>
        </DialogActions>
      </Dialog>

      {/* Test Webhook Dialog */}
      <Dialog open={testDialogOpen} onClose={() => setTestDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Test Google Chat Webhook</DialogTitle>
        <DialogContent>
          <TextField
            fullWidth
            label="Webhook URL"
            value={webhookTest}
            onChange={(e) => setWebhookTest(e.target.value)}
            placeholder="https://chat.googleapis.com/v1/spaces/..."
            sx={{ mt: 2 }}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setTestDialogOpen(false)}>Cancel</Button>
          <Button variant="contained" onClick={handleTestWebhook}>
            Send Test
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

export default Schedules;
