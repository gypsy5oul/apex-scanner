import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Grid,
  Paper,
  Typography,
  Box,
  Card,
  CardContent,
  Alert,
  Button,
  Chip,
  LinearProgress,
  IconButton,
  Divider,
  alpha,
} from '@mui/material';
import { useTheme } from '@mui/material/styles';
import SecurityIcon from '@mui/icons-material/Security';
import BugReportIcon from '@mui/icons-material/BugReport';
import InventoryIcon from '@mui/icons-material/Inventory';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import TrendingUpIcon from '@mui/icons-material/TrendingUp';
import ScheduleIcon from '@mui/icons-material/Schedule';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import RefreshIcon from '@mui/icons-material/Refresh';
import WarningIcon from '@mui/icons-material/Warning';
import ErrorIcon from '@mui/icons-material/Error';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import { getStats, healthCheck, getRecentScans } from '../api';
import { PageHeaderSkeleton, StatCardsSkeleton, CardGridSkeleton } from '../components/LoadingSkeletons';
import { Reveal, CountUp } from '../components/Motion';

function StatCard({ title, value, subtitle, icon, color }) {
  return (
    <Card
      sx={{
        height: '100%',
        transition: 'border-color 0.15s ease, box-shadow 0.15s ease',
        '&:hover': {
          borderColor: alpha(color, 0.5),
        },
      }}
    >
      <CardContent sx={{ p: 2.5 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
          {/* Flat tonal tile — no gradient/glow (enterprise data-dense look) */}
          <Box
            sx={{
              width: 40,
              height: 40,
              borderRadius: 1.5,
              flexShrink: 0,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              bgcolor: alpha(color, 0.12),
            }}
          >
            {React.cloneElement(icon, { sx: { color, fontSize: 22 } })}
          </Box>
          <Typography
            variant="overline"
            color="text.secondary"
            sx={{ lineHeight: 1.2 }}
          >
            {title}
          </Typography>
        </Box>
        <Typography variant="h3" fontWeight={700} sx={{ mb: 0.25, fontVariantNumeric: 'tabular-nums' }}>
          {typeof value === 'number' ? <CountUp value={value} /> : value}
        </Typography>
        {subtitle && (
          <Typography variant="caption" color="text.disabled">
            {subtitle}
          </Typography>
        )}
      </CardContent>
    </Card>
  );
}

function SeverityBar({ critical, high, medium, low }) {
  const theme = useTheme();
  const sev = theme.palette.severity; // mode-aware accents from tokens
  const total = critical + high + medium + low || 1;
  const segments = [
    { value: critical, color: sev.critical, label: 'Critical' },
    { value: high, color: sev.high, label: 'High' },
    { value: medium, color: sev.medium, label: 'Medium' },
    { value: low, color: sev.low, label: 'Low' },
  ];

  return (
    <Box>
      <Box
        sx={{
          display: 'flex',
          height: 8,
          borderRadius: 1,
          overflow: 'hidden',
          mb: 1,
          bgcolor: 'action.hover',
        }}
        role="img"
        aria-label={`Critical ${critical}, High ${high}, Medium ${medium}, Low ${low}`}
      >
        {segments.map((seg, idx) => (
          <Box
            key={idx}
            sx={{
              width: `${(seg.value / total) * 100}%`,
              bgcolor: seg.color,
              transition: 'width 0.3s ease',
            }}
          />
        ))}
      </Box>
      <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
        {segments.map((seg, idx) => (
          <Box key={idx} sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
            <Box sx={{ width: 8, height: 8, borderRadius: '50%', bgcolor: seg.color }} />
            <Typography variant="caption" color="text.secondary">
              {seg.label}: <strong style={{ fontVariantNumeric: 'tabular-nums' }}>{seg.value}</strong>
            </Typography>
          </Box>
        ))}
      </Box>
    </Box>
  );
}

function Dashboard() {
  const navigate = useNavigate();
  const [stats, setStats] = useState(null);
  const [health, setHealth] = useState(null);
  const [recentScans, setRecentScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchData = async () => {
    try {
      const [statsRes, healthRes, scansRes] = await Promise.all([
        getStats(),
        healthCheck(),
        getRecentScans(5),
      ]);
      setStats(statsRes.data);
      setHealth(healthRes.data);
      setRecentScans(scansRes.data?.scans || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <Box>
        <PageHeaderSkeleton />
        <StatCardsSkeleton count={4} />
        <CardGridSkeleton count={2} height={320} cols={{ xs: 12, lg: 6 }} />
      </Box>
    );
  }

  const totalVulns = recentScans.reduce((acc, scan) => {
    if (scan.summary) {
      return acc + (scan.summary.critical || 0) + (scan.summary.high || 0);
    }
    return acc;
  }, 0);

  return (
    <Box>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 4 }}>
        <Box>
          <Typography variant="h4" fontWeight={700} gutterBottom>
            Security Dashboard
          </Typography>
          <Typography variant="body1" color="text.secondary">
            Monitor vulnerabilities and track security posture across your container images
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <IconButton onClick={fetchData} sx={{ bgcolor: 'action.hover' }}>
            <RefreshIcon />
          </IconButton>
          <Button
            variant="contained"
            startIcon={<PlayArrowIcon />}
            onClick={() => navigate('/scan')}
          >
            New Scan
          </Button>
        </Box>
      </Box>

      {/* Health Status */}
      {health && (
        <Alert
          severity={health.status === 'healthy' ? 'success' : 'warning'}
          sx={{ mb: 3, borderRadius: 2 }}
          icon={health.status === 'healthy' ? <CheckCircleIcon /> : <WarningIcon />}
        >
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <Typography fontWeight={600}>System Status: {health.status}</Typography>
            {health.components?.redis && (
              <Chip
                label={`Redis: ${health.components.redis.status}`}
                size="small"
                color={health.components.redis.status === 'connected' ? 'success' : 'error'}
                variant="outlined"
              />
            )}
            {health.components?.celery && (
              <Chip
                label={`Celery: ${health.components.celery.status}`}
                size="small"
                color={health.components.celery.status === 'connected' ? 'success' : 'error'}
                variant="outlined"
              />
            )}
          </Box>
        </Alert>
      )}

      {error && (
        <Alert severity="error" sx={{ mb: 3, borderRadius: 2 }}>
          {error}
        </Alert>
      )}

      {/* Stats Grid */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={6} lg={3}>
          <Reveal delay={0.05} sx={{ height: '100%' }}>
            <StatCard
              title="Images Scanned"
              value={stats?.total_images_scanned || 0}
              subtitle="All time"
              icon={<InventoryIcon />}
              color="#2196f3"
            />
          </Reveal>
        </Grid>
        <Grid item xs={12} sm={6} lg={3}>
          <Reveal delay={0.11} sx={{ height: '100%' }}>
            <StatCard
              title="Active Scanners"
              value={Object.values(stats?.scanners_enabled || {}).filter(Boolean).length}
              subtitle="Grype, Trivy, Syft"
              icon={<SecurityIcon />}
              color="#4caf50"
            />
          </Reveal>
        </Grid>
        <Grid item xs={12} sm={6} lg={3}>
          <Reveal delay={0.17} sx={{ height: '100%' }}>
            <StatCard
              title="Critical + High"
              value={totalVulns}
              subtitle="Recent scans"
              icon={<ErrorIcon />}
              color="#f44336"
            />
          </Reveal>
        </Grid>
        <Grid item xs={12} sm={6} lg={3}>
          <Reveal delay={0.23} sx={{ height: '100%' }}>
            <StatCard
              title="Scan Timeout"
              value={`${stats?.configuration?.scan_timeout || 300}s`}
              subtitle="Max duration"
              icon={<ScheduleIcon />}
              color="#9c27b0"
            />
          </Reveal>
        </Grid>
      </Grid>

      <Grid container spacing={3}>
        {/* Recent Scans */}
        <Grid item xs={12} lg={8}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
                <Typography variant="h6" fontWeight={600}>
                  Recent Scans
                </Typography>
                <Button
                  size="small"
                  endIcon={<ArrowForwardIcon />}
                  onClick={() => navigate('/history')}
                >
                  View All
                </Button>
              </Box>

              {recentScans.length === 0 ? (
                <Box sx={{ textAlign: 'center', py: 4 }}>
                  <InventoryIcon sx={{ fontSize: 48, color: 'text.disabled', mb: 2 }} />
                  <Typography color="text.secondary">No scans yet</Typography>
                  <Button
                    variant="outlined"
                    sx={{ mt: 2 }}
                    onClick={() => navigate('/scan')}
                  >
                    Start your first scan
                  </Button>
                </Box>
              ) : (
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                  {recentScans.map((scan, index) => (
                    <Paper
                      key={scan.scan_id || index}
                      variant="outlined"
                      sx={{
                        p: 2,
                        borderRadius: 2,
                        cursor: 'pointer',
                        '&:hover': {
                          bgcolor: 'action.hover',
                        },
                      }}
                      onClick={() => navigate(`/scan/${scan.scan_id}`)}
                    >
                      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 1.5 }}>
                        <Box>
                          <Typography variant="subtitle2" fontWeight={600} sx={{ fontFamily: 'monospace' }}>
                            {scan.image_name}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            {new Date(scan.timestamp).toLocaleString()}
                          </Typography>
                        </Box>
                        <Chip
                          label={scan.status}
                          size="small"
                          color={scan.status === 'completed' ? 'success' : scan.status === 'failed' ? 'error' : 'warning'}
                        />
                      </Box>
                      {scan.summary && (
                        <SeverityBar
                          critical={scan.summary.critical || 0}
                          high={scan.summary.high || 0}
                          medium={scan.summary.medium || 0}
                          low={scan.summary.low || 0}
                        />
                      )}
                    </Paper>
                  ))}
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Quick Actions & Scanner Status */}
        <Grid item xs={12} lg={4}>
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Typography variant="h6" fontWeight={600} gutterBottom>
                Scanner Status
              </Typography>
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
                {stats?.scanners_enabled &&
                  Object.entries(stats.scanners_enabled).map(([name, enabled]) => (
                    <Box
                      key={name}
                      sx={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        p: 1.5,
                        borderRadius: 2,
                        bgcolor: (theme) =>
                          enabled
                            ? alpha(theme.palette.success.main, 0.1)
                            : alpha(theme.palette.error.main, 0.1),
                      }}
                    >
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
                        <Box
                          sx={{
                            width: 10,
                            height: 10,
                            borderRadius: '50%',
                            bgcolor: enabled ? 'success.main' : 'error.main',
                          }}
                        />
                        <Typography
                          fontWeight={500}
                          sx={{ textTransform: 'capitalize' }}
                        >
                          {name}
                        </Typography>
                      </Box>
                      <Chip
                        label={enabled ? 'Active' : 'Disabled'}
                        size="small"
                        color={enabled ? 'success' : 'default'}
                        variant="outlined"
                      />
                    </Box>
                  ))}
              </Box>
            </CardContent>
          </Card>

          <Card>
            <CardContent>
              <Typography variant="h6" fontWeight={600} gutterBottom>
                Quick Actions
              </Typography>
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
                <Button
                  fullWidth
                  variant="outlined"
                  startIcon={<SecurityIcon />}
                  onClick={() => navigate('/scan')}
                  sx={{ justifyContent: 'flex-start', py: 1.5 }}
                >
                  Scan Single Image
                </Button>
                <Button
                  fullWidth
                  variant="outlined"
                  startIcon={<InventoryIcon />}
                  onClick={() => navigate('/batch')}
                  sx={{ justifyContent: 'flex-start', py: 1.5 }}
                >
                  Batch Scan
                </Button>
                <Button
                  fullWidth
                  variant="outlined"
                  startIcon={<BugReportIcon />}
                  onClick={() => navigate('/search')}
                  sx={{ justifyContent: 'flex-start', py: 1.5 }}
                >
                  Search CVEs
                </Button>
                <Button
                  fullWidth
                  variant="outlined"
                  startIcon={<TrendingUpIcon />}
                  onClick={() => navigate('/trends')}
                  sx={{ justifyContent: 'flex-start', py: 1.5 }}
                >
                  View Trends
                </Button>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
}

export default Dashboard;
