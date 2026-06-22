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
  CircularProgress,
  Tooltip,
  Grid,
} from '@mui/material';
import PageHeader from '../components/PageHeader';
import { TableSkeleton } from '../components/LoadingSkeletons';
import { useToast, useConfirm } from '../components/Feedback';
import {
  Add,
  Delete,
  PlayArrow,
  Schedule,
  Notifications,
} from '@mui/icons-material';
import {
  getSchedules,
  createSchedule,
  deleteSchedule,
  runScheduleNow,
  testNotification,
} from '../api';

// Basic 5-field cron validation: minute hour day month weekday.
const isValidCron = (cron) => {
  if (!cron || !cron.trim()) return false;
  return cron.trim().split(/\s+/).length === 5;
};

function Schedules() {
  const toast = useToast();
  const confirm = useConfirm();
  const [schedules, setSchedules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [testDialogOpen, setTestDialogOpen] = useState(false);
  const [creating, setCreating] = useState(false);
  const [testing, setTesting] = useState(false);
  const [runningName, setRunningName] = useState(null);
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
      toast('Failed to fetch schedules: ' + (err.response?.data?.detail || err.message), 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSchedules();
  }, []);

  const handleCreate = async () => {
    setCreating(true);
    try {
      const images = newSchedule.images.split('\n').filter((i) => i.trim());
      await createSchedule({
        ...newSchedule,
        images,
      });
      toast('Schedule created successfully', 'success');
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
      toast('Create schedule failed: ' + (err.response?.data?.detail || err.message), 'error');
    } finally {
      setCreating(false);
    }
  };

  const handleDelete = async (name) => {
    if (
      !(await confirm({
        title: 'Delete schedule?',
        message: `Delete scheduled scan "${name}"? This cannot be undone.`,
        confirmLabel: 'Delete',
        destructive: true,
      }))
    )
      return;
    try {
      await deleteSchedule(name);
      toast('Schedule deleted', 'success');
      fetchSchedules();
    } catch (err) {
      toast('Delete schedule failed: ' + (err.response?.data?.detail || err.message), 'error');
    }
  };

  const handleRunNow = async (name) => {
    if (
      !(await confirm({
        title: 'Run scan now?',
        message: `This starts a real scan for "${name}" immediately.`,
        confirmLabel: 'Run Now',
      }))
    )
      return;
    setRunningName(name);
    try {
      await runScheduleNow(name);
      toast(`Triggered scan for "${name}"`, 'success');
    } catch (err) {
      toast('Run schedule failed: ' + (err.response?.data?.detail || err.message), 'error');
    } finally {
      setRunningName(null);
    }
  };

  const handleTestWebhook = async () => {
    setTesting(true);
    try {
      await testNotification(webhookTest);
      toast('Test notification sent successfully', 'success');
      setTestDialogOpen(false);
    } catch (err) {
      toast('Test notification failed: ' + (err.response?.data?.detail || err.message), 'error');
    } finally {
      setTesting(false);
    }
  };

  const nameInvalid = !newSchedule.name.trim();
  const cronInvalid = !isValidCron(newSchedule.cron_expression);

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

  return (
    <Box>
      <PageHeader
        title="Scheduled Scans"
        description="Configure automated security scans with notifications"
        actions={
          <>
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
          </>
        }
      />

      {loading ? (
        <Paper>
          <TableSkeleton rows={5} cols={7} />
        </Paper>
      ) : schedules.length === 0 ? (
        <Card>
          <CardContent>
            <Box textAlign="center" py={4}>
              <Schedule sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
              <Typography variant="h6" gutterBottom>
                No Scheduled Scans
              </Typography>
              <Typography color="text.secondary" mb={3}>
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
                      <Typography variant="body2" color="text.secondary">
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
                    <Typography variant="caption" color="text.secondary">
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
                      <Typography variant="body2" color="text.secondary">
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
                      <Typography variant="body2" color="text.secondary">
                        Never
                      </Typography>
                    )}
                  </TableCell>
                  <TableCell align="right">
                    <Tooltip title="Run Now">
                      <span>
                        <IconButton
                          color="primary"
                          aria-label={`Run scan "${schedule.name}" now`}
                          disabled={runningName === schedule.name}
                          onClick={() => handleRunNow(schedule.name)}
                        >
                          {runningName === schedule.name ? (
                            <CircularProgress size={20} />
                          ) : (
                            <PlayArrow />
                          )}
                        </IconButton>
                      </span>
                    </Tooltip>
                    <Tooltip title="Delete">
                      <IconButton
                        color="error"
                        aria-label={`Delete schedule "${schedule.name}"`}
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
                required
                label="Schedule Name"
                value={newSchedule.name}
                onChange={(e) => setNewSchedule({ ...newSchedule, name: e.target.value })}
                placeholder="daily-base-images"
                error={nameInvalid}
                helperText={nameInvalid ? 'Name is required' : ' '}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                required
                label="Cron Expression"
                value={newSchedule.cron_expression}
                onChange={(e) =>
                  setNewSchedule({ ...newSchedule, cron_expression: e.target.value })
                }
                error={cronInvalid}
                helperText={
                  cronInvalid
                    ? 'Enter a valid 5-field cron (minute hour day month weekday)'
                    : 'Format: minute hour day month weekday (e.g., 0 6 * * * for daily at 6 AM)'
                }
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
          <Button onClick={() => setDialogOpen(false)} disabled={creating}>
            Cancel
          </Button>
          <Button
            variant="contained"
            onClick={handleCreate}
            disabled={creating || nameInvalid || cronInvalid}
            startIcon={creating ? <CircularProgress size={20} /> : null}
          >
            {creating ? 'Creating…' : 'Create'}
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
          <Button onClick={() => setTestDialogOpen(false)} disabled={testing}>
            Cancel
          </Button>
          <Button
            variant="contained"
            onClick={handleTestWebhook}
            disabled={testing || !webhookTest.trim()}
            startIcon={testing ? <CircularProgress size={20} /> : null}
          >
            {testing ? 'Sending…' : 'Send Test'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

export default Schedules;
