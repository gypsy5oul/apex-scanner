import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
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
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Alert,
  CircularProgress,
  Grid,
  Divider,
  IconButton,
  Tooltip,
  LinearProgress,
} from '@mui/material';
import {
  ArrowBack,
  Edit,
  Refresh,
  TrendingUp,
  TrendingDown,
  TrendingFlat,
  Security,
  Schedule,
  Assessment,
} from '@mui/icons-material';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts';
import {
  getBaseImageDetails,
  updateBaseImage,
  getBaseImageHistory,
} from '../api';

function BaseImageDetail() {
  const { imageName, tag } = useParams();
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);
  const [imageData, setImageData] = useState(null);
  const [editDialogOpen, setEditDialogOpen] = useState(false);
  const [editDescription, setEditDescription] = useState('');

  const decodedImageName = decodeURIComponent(imageName);
  const decodedTag = decodeURIComponent(tag);

  const fetchDetails = async () => {
    setLoading(true);
    try {
      const res = await getBaseImageDetails(decodedImageName, decodedTag);
      setImageData(res.data);
      setEditDescription(res.data.base_image?.description || '');
    } catch (err) {
      setError('Failed to fetch base image details');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDetails();
  }, [imageName, tag]);

  const handleUpdate = async () => {
    try {
      await updateBaseImage(decodedImageName, decodedTag, {
        description: editDescription,
      });
      setSuccess('Base image updated successfully');
      setEditDialogOpen(false);
      fetchDetails();
    } catch (err) {
      setError('Failed to update base image');
    }
  };

  const getRiskColor = (score) => {
    if (score >= 80) return 'error';
    if (score >= 50) return 'warning';
    if (score >= 20) return 'info';
    return 'success';
  };

  const getRiskLabel = (score) => {
    if (score >= 80) return 'Critical';
    if (score >= 50) return 'High';
    if (score >= 20) return 'Medium';
    return 'Low';
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  if (!imageData) {
    return (
      <Box>
        <Alert severity="error">Base image not found</Alert>
        <Button startIcon={<ArrowBack />} onClick={() => navigate('/base-images')} sx={{ mt: 2 }}>
          Back to Base Images
        </Button>
      </Box>
    );
  }

  const { base_image, recent_scans, vulnerability_trend, risk_score } = imageData;
  const vulns = base_image?.current_vulns || {};

  // Prepare chart data from vulnerability trend
  const chartData = vulnerability_trend?.map((entry) => ({
    date: new Date(entry.timestamp).toLocaleDateString(),
    Critical: entry.vulns?.critical || 0,
    High: entry.vulns?.high || 0,
    Medium: entry.vulns?.medium || 0,
    Low: entry.vulns?.low || 0,
    'Fixable Critical': entry.vulns?.fixable_critical || 0,
    'Fixable High': entry.vulns?.fixable_high || 0,
  })).reverse() || [];

  return (
    <Box>
      {/* Header */}
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Box display="flex" alignItems="center" gap={2}>
          <IconButton onClick={() => navigate('/base-images')}>
            <ArrowBack />
          </IconButton>
          <Box>
            <Typography variant="h4" fontWeight="bold">
              {base_image?.full_name || `${decodedImageName}:${decodedTag}`}
            </Typography>
            <Typography color="textSecondary">
              {base_image?.description || 'No description'}
            </Typography>
          </Box>
        </Box>
        <Box display="flex" gap={2}>
          <Button
            variant="outlined"
            startIcon={<Edit />}
            onClick={() => setEditDialogOpen(true)}
          >
            Edit
          </Button>
          <Button
            variant="contained"
            startIcon={<Refresh />}
            onClick={fetchDetails}
          >
            Refresh
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

      {/* Stats Cards */}
      <Grid container spacing={3} mb={3}>
        {/* Risk Score Card */}
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" gap={1} mb={2}>
                <Security color={getRiskColor(risk_score)} />
                <Typography variant="h6">Risk Score</Typography>
              </Box>
              <Box display="flex" alignItems="baseline" gap={1}>
                <Typography variant="h2" fontWeight="bold" color={`${getRiskColor(risk_score)}.main`}>
                  {risk_score || 0}
                </Typography>
                <Typography variant="h6" color="textSecondary">/ 100</Typography>
              </Box>
              <Chip
                label={getRiskLabel(risk_score)}
                color={getRiskColor(risk_score)}
                size="small"
                sx={{ mt: 1 }}
              />
              <Typography variant="caption" display="block" color="textSecondary" mt={1}>
                Formula: Critical*10 + High*5 + Medium*2 + Low*1
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        {/* Scan Stats Card */}
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" gap={1} mb={2}>
                <Schedule color="primary" />
                <Typography variant="h6">Scan History</Typography>
              </Box>
              <Typography variant="h3" fontWeight="bold">
                {base_image?.scan_count || 0}
              </Typography>
              <Typography color="textSecondary">Total Scans</Typography>
              {base_image?.last_scanned && (
                <Typography variant="body2" mt={2}>
                  Last scanned: {new Date(base_image.last_scanned).toLocaleString()}
                </Typography>
              )}
              <Typography variant="caption" color="textSecondary">
                Registered: {base_image?.registered_at ? new Date(base_image.registered_at).toLocaleDateString() : 'N/A'}
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        {/* Total Vulnerabilities Card */}
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" gap={1} mb={2}>
                <Assessment color="warning" />
                <Typography variant="h6">Total Vulnerabilities</Typography>
              </Box>
              <Typography variant="h3" fontWeight="bold">
                {(vulns.critical || 0) + (vulns.high || 0) + (vulns.medium || 0) + (vulns.low || 0)}
              </Typography>
              <Box display="flex" gap={1} mt={1} flexWrap="wrap">
                <Chip label={`${vulns.critical || 0} Critical`} color="error" size="small" />
                <Chip label={`${vulns.high || 0} High`} color="warning" size="small" />
                <Chip label={`${vulns.medium || 0} Medium`} size="small" />
                <Chip label={`${vulns.low || 0} Low`} color="success" size="small" />
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Vulnerability Breakdown */}
      <Grid container spacing={3} mb={3}>
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom color="success.main">
                Fixable Vulnerabilities
              </Typography>
              <Typography variant="caption" color="textSecondary" display="block" mb={2}>
                Patches are available for these vulnerabilities
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={3}>
                  <Typography variant="caption" color="textSecondary">Critical</Typography>
                  <Typography variant="h4" color="error">{vulns.fixable_critical || 0}</Typography>
                </Grid>
                <Grid item xs={3}>
                  <Typography variant="caption" color="textSecondary">High</Typography>
                  <Typography variant="h4" color="warning.main">{vulns.fixable_high || 0}</Typography>
                </Grid>
                <Grid item xs={3}>
                  <Typography variant="caption" color="textSecondary">Medium</Typography>
                  <Typography variant="h4">{vulns.fixable_medium || 0}</Typography>
                </Grid>
                <Grid item xs={3}>
                  <Typography variant="caption" color="textSecondary">Low</Typography>
                  <Typography variant="h4" color="success.main">{vulns.fixable_low || 0}</Typography>
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom color="text.secondary">
                No Fix Available
              </Typography>
              <Typography variant="caption" color="textSecondary" display="block" mb={2}>
                No patches currently available for these vulnerabilities
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={3}>
                  <Typography variant="caption" color="textSecondary">Critical</Typography>
                  <Typography variant="h4" color="error">
                    {(vulns.critical || 0) - (vulns.fixable_critical || 0)}
                  </Typography>
                </Grid>
                <Grid item xs={3}>
                  <Typography variant="caption" color="textSecondary">High</Typography>
                  <Typography variant="h4" color="warning.main">
                    {(vulns.high || 0) - (vulns.fixable_high || 0)}
                  </Typography>
                </Grid>
                <Grid item xs={3}>
                  <Typography variant="caption" color="textSecondary">Medium</Typography>
                  <Typography variant="h4">
                    {(vulns.medium || 0) - (vulns.fixable_medium || 0)}
                  </Typography>
                </Grid>
                <Grid item xs={3}>
                  <Typography variant="caption" color="textSecondary">Low</Typography>
                  <Typography variant="h4" color="success.main">
                    {(vulns.low || 0) - (vulns.fixable_low || 0)}
                  </Typography>
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Vulnerability Trend Chart */}
      {chartData.length > 0 && (
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Vulnerability Trend
            </Typography>
            <Box height={300}>
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="date" />
                  <YAxis />
                  <RechartsTooltip />
                  <Legend />
                  <Line type="monotone" dataKey="Critical" stroke="#d32f2f" strokeWidth={2} />
                  <Line type="monotone" dataKey="High" stroke="#ed6c02" strokeWidth={2} />
                  <Line type="monotone" dataKey="Medium" stroke="#0288d1" strokeWidth={2} />
                  <Line type="monotone" dataKey="Low" stroke="#2e7d32" strokeWidth={2} />
                </LineChart>
              </ResponsiveContainer>
            </Box>
          </CardContent>
        </Card>
      )}

      {/* Recent Scans Table */}
      <Card>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Recent Scans
          </Typography>
          {recent_scans && recent_scans.length > 0 ? (
            <TableContainer component={Paper} variant="outlined">
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Scan ID</TableCell>
                    <TableCell>Date</TableCell>
                    <TableCell align="center">Critical</TableCell>
                    <TableCell align="center">High</TableCell>
                    <TableCell align="center">Medium</TableCell>
                    <TableCell align="center">Low</TableCell>
                    <TableCell align="center">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {recent_scans.map((scan, index) => (
                    <TableRow key={index} hover>
                      <TableCell>
                        <Typography variant="body2" fontFamily="monospace">
                          {scan.scan_id?.substring(0, 8) || 'N/A'}...
                        </Typography>
                      </TableCell>
                      <TableCell>
                        {scan.timestamp ? new Date(scan.timestamp).toLocaleString() : 'N/A'}
                      </TableCell>
                      <TableCell align="center">
                        <Chip
                          label={scan.vulns?.critical || 0}
                          color="error"
                          size="small"
                          variant={scan.vulns?.critical > 0 ? 'filled' : 'outlined'}
                        />
                      </TableCell>
                      <TableCell align="center">
                        <Chip
                          label={scan.vulns?.high || 0}
                          color="warning"
                          size="small"
                          variant={scan.vulns?.high > 0 ? 'filled' : 'outlined'}
                        />
                      </TableCell>
                      <TableCell align="center">
                        <Chip
                          label={scan.vulns?.medium || 0}
                          size="small"
                          variant={scan.vulns?.medium > 0 ? 'filled' : 'outlined'}
                        />
                      </TableCell>
                      <TableCell align="center">
                        <Chip
                          label={scan.vulns?.low || 0}
                          color="success"
                          size="small"
                          variant={scan.vulns?.low > 0 ? 'filled' : 'outlined'}
                        />
                      </TableCell>
                      <TableCell align="center">
                        {scan.scan_id && (
                          <Button
                            size="small"
                            onClick={() => navigate(`/results/${scan.scan_id}`)}
                          >
                            View Report
                          </Button>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          ) : (
            <Typography color="textSecondary" textAlign="center" py={4}>
              No scans recorded yet. Run "Scan All Now" from the Base Images page.
            </Typography>
          )}
        </CardContent>
      </Card>

      {/* Edit Dialog */}
      <Dialog open={editDialogOpen} onClose={() => setEditDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Edit Base Image</DialogTitle>
        <DialogContent>
          <Box sx={{ mt: 1 }}>
            <Typography variant="subtitle2" color="textSecondary" gutterBottom>
              Image: {decodedImageName}:{decodedTag}
            </Typography>
            <TextField
              fullWidth
              label="Description"
              value={editDescription}
              onChange={(e) => setEditDescription(e.target.value)}
              placeholder="Production base image for Python services"
              multiline
              rows={3}
              sx={{ mt: 2 }}
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditDialogOpen(false)}>Cancel</Button>
          <Button variant="contained" onClick={handleUpdate}>
            Save Changes
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

export default BaseImageDetail;
