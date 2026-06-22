import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Grid,
  TextField,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  Alert,
  CircularProgress,
  ToggleButton,
  ToggleButtonGroup,
  useTheme,
  alpha,
} from '@mui/material';
import PageHeader from '../components/PageHeader';
import { StatCardsSkeleton, CardGridSkeleton } from '../components/LoadingSkeletons';
import { useToast } from '../components/Feedback';
import { MONO_FONT } from '../theme/tokens';
import {
  TrendingUp,
  TrendingDown,
  TrendingFlat,
  Refresh,
} from '@mui/icons-material';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  Title,
  Tooltip,
  Legend,
  Filler,
} from 'chart.js';
import { Line, Bar } from 'react-chartjs-2';
import { getGlobalTrends, getTopVulnerable, getVulnDistribution, getImageTrends } from '../api';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

function Trends() {
  const theme = useTheme();
  const toast = useToast();
  const [loading, setLoading] = useState(true);
  const [searching, setSearching] = useState(false);
  const [error, setError] = useState(null);
  const [period, setPeriod] = useState(30);
  const [globalTrends, setGlobalTrends] = useState(null);
  const [topVulnerable, setTopVulnerable] = useState([]);
  const [distribution, setDistribution] = useState(null);
  const [imageSearch, setImageSearch] = useState('');
  const [imageTrends, setImageTrends] = useState(null);

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [trendsRes, topRes, distRes] = await Promise.all([
        getGlobalTrends(period),
        getTopVulnerable(7, 10),
        getVulnDistribution(period),
      ]);
      setGlobalTrends(trendsRes.data);
      setTopVulnerable(topRes.data.images || []);
      setDistribution(distRes.data);
    } catch (err) {
      setError('Failed to fetch trends data');
      toast('Failed to fetch trends data: ' + (err.response?.data?.detail || err.message), 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [period]);

  const handleImageSearch = async () => {
    if (!imageSearch.trim()) return;
    setSearching(true);
    try {
      const res = await getImageTrends(imageSearch, period);
      setImageTrends(res.data);
    } catch (err) {
      toast('Image search failed: ' + (err.response?.data?.detail || err.message), 'error');
    } finally {
      setSearching(false);
    }
  };

  const getTrendIcon = (direction) => {
    switch (direction) {
      case 'increasing':
        return <TrendingUp color="error" />;
      case 'decreasing':
        return <TrendingDown color="success" />;
      default:
        return <TrendingFlat color="action" />;
    }
  };

  const chartData = globalTrends?.daily_data
    ? {
        labels: globalTrends.daily_data.map((d) => d.date),
        datasets: [
          {
            label: 'Critical',
            data: globalTrends.daily_data.map((d) => d.total_critical),
            borderColor: theme.palette.severity.critical,
            backgroundColor: alpha(theme.palette.severity.critical, 0.12),
            fill: true,
            tension: 0.4,
          },
          {
            label: 'High',
            data: globalTrends.daily_data.map((d) => d.total_high),
            borderColor: theme.palette.severity.high,
            backgroundColor: alpha(theme.palette.severity.high, 0.12),
            fill: true,
            tension: 0.4,
          },
          {
            label: 'Medium',
            data: globalTrends.daily_data.map((d) => d.total_medium),
            borderColor: theme.palette.severity.medium,
            backgroundColor: alpha(theme.palette.severity.medium, 0.12),
            fill: true,
            tension: 0.4,
          },
        ],
      }
    : null;

  const distributionData = distribution?.distribution
    ? {
        labels: ['Critical', 'High', 'Medium', 'Low'],
        datasets: [
          {
            label: 'Findings by severity',
            data: [
              distribution.distribution.critical?.count || 0,
              distribution.distribution.high?.count || 0,
              distribution.distribution.medium?.count || 0,
              distribution.distribution.low?.count || 0,
            ],
            backgroundColor: [
              theme.palette.severity.critical,
              theme.palette.severity.high,
              theme.palette.severity.medium,
              theme.palette.severity.low,
            ],
          },
        ],
      }
    : null;

  if (loading) {
    return (
      <Box>
        <PageHeader
          title="Vulnerability Trends"
          description="How critical, high, medium and low findings move over time"
        />
        <StatCardsSkeleton count={4} />
        <CardGridSkeleton count={2} height={340} cols={{ xs: 12, md: 6 }} />
      </Box>
    );
  }

  return (
    <Box>
      <PageHeader
        title="Vulnerability Trends"
        description="How critical, high, medium and low findings move over time"
        actions={
          <>
            <ToggleButtonGroup
              value={period}
              exclusive
              onChange={(e, v) => v && setPeriod(v)}
              size="small"
            >
              <ToggleButton value={7}>7 Days</ToggleButton>
              <ToggleButton value={30}>30 Days</ToggleButton>
              <ToggleButton value={90}>90 Days</ToggleButton>
            </ToggleButtonGroup>
            <Button startIcon={<Refresh />} onClick={fetchData} variant="outlined">
              Refresh
            </Button>
          </>
        }
      />

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {/* Summary Cards */}
      <Grid container spacing={3} mb={3}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>
                Total Scans
              </Typography>
              <Typography variant="h4" fontWeight="bold" sx={{ fontVariantNumeric: 'tabular-nums' }}>
                {globalTrends?.totals?.total_scans || 0}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Last {period} days
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>
                Total Critical
              </Typography>
              <Typography
                variant="h4"
                fontWeight="bold"
                sx={{ color: theme.palette.severity.critical, fontVariantNumeric: 'tabular-nums' }}
              >
                {globalTrends?.totals?.total_critical || 0}
              </Typography>
              {globalTrends?.week_over_week && (
                <Box display="flex" alignItems="center" gap={0.5}>
                  {getTrendIcon(globalTrends.week_over_week.direction)}
                  <Typography variant="body2">
                    {globalTrends.week_over_week.percentage}% WoW
                  </Typography>
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>
                Total High
              </Typography>
              <Typography
                variant="h4"
                fontWeight="bold"
                sx={{ color: theme.palette.severity.high, fontVariantNumeric: 'tabular-nums' }}
              >
                {globalTrends?.totals?.total_high || 0}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Needs attention
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>
                Daily Average
              </Typography>
              <Typography variant="h4" fontWeight="bold" sx={{ fontVariantNumeric: 'tabular-nums' }}>
                {globalTrends?.averages?.daily_scans || 0}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Scans per day
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Charts */}
      <Grid container spacing={3} mb={3}>
        <Grid item xs={12} md={8}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Vulnerability Trend Over Time
              </Typography>
              {chartData ? (
                <Box height={300}>
                  <Line
                    data={chartData}
                    options={{
                      responsive: true,
                      maintainAspectRatio: false,
                      interaction: { mode: 'index', intersect: false },
                      plugins: {
                        legend: { position: 'top' },
                        tooltip: { enabled: true },
                      },
                      scales: {
                        y: { beginAtZero: true },
                      },
                    }}
                  />
                </Box>
              ) : (
                <Box
                  height={300}
                  display="flex"
                  alignItems="center"
                  justifyContent="center"
                >
                  <Typography variant="body2" color="text.secondary">
                    No trend data yet — run scans to build history
                  </Typography>
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Severity Distribution
              </Typography>
              {distributionData ? (
                <Box height={300}>
                  <Bar
                    data={distributionData}
                    options={{
                      responsive: true,
                      maintainAspectRatio: false,
                      plugins: {
                        legend: { display: true, position: 'top' },
                        tooltip: { enabled: true },
                      },
                      scales: {
                        x: { ticks: { display: true } },
                        y: { beginAtZero: true },
                      },
                    }}
                  />
                </Box>
              ) : (
                <Box
                  height={300}
                  display="flex"
                  alignItems="center"
                  justifyContent="center"
                >
                  <Typography variant="body2" color="text.secondary">
                    No trend data yet — run scans to build history
                  </Typography>
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Image Search */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Image-Specific Trends
          </Typography>
          <Box display="flex" gap={2} mb={2}>
            <TextField
              fullWidth
              placeholder="Enter image name (e.g., nginx:latest)"
              value={imageSearch}
              onChange={(e) => setImageSearch(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleImageSearch()}
            />
            <Button
              variant="contained"
              onClick={handleImageSearch}
              disabled={searching || !imageSearch.trim()}
              startIcon={searching ? <CircularProgress size={20} color="inherit" /> : null}
            >
              Search
            </Button>
          </Box>
          {imageTrends && (
            <Box>
              <Typography variant="body2" color="text.secondary" mb={2}>
                Found {imageTrends.data_points} data points for {imageTrends.image_name}
              </Typography>
              {imageTrends.trend_direction && (
                <Grid container spacing={2}>
                  {Object.entries(imageTrends.trend_direction).map(([severity, trend]) => (
                    <Grid item xs={6} md={2} key={severity}>
                      <Box display="flex" alignItems="center" gap={1}>
                        {getTrendIcon(trend.direction)}
                        <Box>
                          <Typography variant="body2" textTransform="capitalize">
                            {severity}
                          </Typography>
                          <Typography variant="body2" color="text.secondary">
                            {trend.change > 0 ? '+' : ''}{trend.change}
                          </Typography>
                        </Box>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
              )}
            </Box>
          )}
        </CardContent>
      </Card>

      {/* Top Vulnerable Images */}
      <Card>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Top Vulnerable Images
          </Typography>
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Image</TableCell>
                  <TableCell align="center">Critical</TableCell>
                  <TableCell align="center">High</TableCell>
                  <TableCell align="center">Medium</TableCell>
                  <TableCell align="center">Low</TableCell>
                  <TableCell align="center">Risk Score</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {topVulnerable.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={6} align="center" sx={{ py: 4 }}>
                      <Typography variant="body2" color="text.secondary">
                        No vulnerable images yet — run scans to populate this list
                      </Typography>
                    </TableCell>
                  </TableRow>
                ) : (
                  topVulnerable.map((image, index) => (
                    <TableRow key={index}>
                      <TableCell>
                        <Typography variant="body2" sx={{ fontFamily: MONO_FONT }}>
                          {image.image_name}
                        </Typography>
                      </TableCell>
                      <TableCell align="center" sx={{ fontVariantNumeric: 'tabular-nums' }}>
                        <Chip
                          label={image.critical}
                          size="small"
                          color="error"
                          variant={image.critical > 0 ? 'filled' : 'outlined'}
                        />
                      </TableCell>
                      <TableCell align="center" sx={{ fontVariantNumeric: 'tabular-nums' }}>
                        <Chip
                          label={image.high}
                          size="small"
                          color="warning"
                          variant={image.high > 0 ? 'filled' : 'outlined'}
                        />
                      </TableCell>
                      <TableCell align="center" sx={{ fontVariantNumeric: 'tabular-nums' }}>
                        <Chip label={image.medium} size="small" variant="outlined" />
                      </TableCell>
                      <TableCell align="center" sx={{ fontVariantNumeric: 'tabular-nums' }}>
                        <Chip label={image.low} size="small" color="success" variant="outlined" />
                      </TableCell>
                      <TableCell align="center" sx={{ fontVariantNumeric: 'tabular-nums' }}>
                        <Typography fontWeight="bold">{image.risk_score}</Typography>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </TableContainer>
        </CardContent>
      </Card>
    </Box>
  );
}

export default Trends;
