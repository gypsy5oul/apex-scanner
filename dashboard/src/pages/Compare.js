import React, { useState } from 'react';
import {
  Box,
  Paper,
  Typography,
  TextField,
  Button,
  Alert,
  CircularProgress,
  Grid,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Divider,
} from '@mui/material';
import CompareArrowsIcon from '@mui/icons-material/CompareArrows';
import AddCircleIcon from '@mui/icons-material/AddCircle';
import RemoveCircleIcon from '@mui/icons-material/RemoveCircle';
import { compareScans } from '../api';
import SeverityChip from '../components/SeverityChip';

function Compare() {
  const [scanId1, setScanId1] = useState('');
  const [scanId2, setScanId2] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleCompare = async (e) => {
    e.preventDefault();
    if (!scanId1.trim() || !scanId2.trim()) {
      setError('Please enter both scan IDs');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const response = await compareScans(scanId1.trim(), scanId2.trim());
      setResult(response.data);
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
      setResult(null);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Compare Scans
      </Typography>

      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          Compare Two Scans
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Enter two scan IDs to compare vulnerabilities. See what's new, fixed, or unchanged.
        </Typography>

        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        <form onSubmit={handleCompare}>
          <Grid container spacing={2} alignItems="center">
            <Grid item xs={12} md={5}>
              <TextField
                fullWidth
                label="Scan ID 1 (Baseline)"
                placeholder="Enter first scan ID"
                value={scanId1}
                onChange={(e) => setScanId1(e.target.value)}
                disabled={loading}
              />
            </Grid>
            <Grid item xs={12} md={2} sx={{ textAlign: 'center' }}>
              <CompareArrowsIcon sx={{ fontSize: 40, color: 'primary.main' }} />
            </Grid>
            <Grid item xs={12} md={5}>
              <TextField
                fullWidth
                label="Scan ID 2 (Compare)"
                placeholder="Enter second scan ID"
                value={scanId2}
                onChange={(e) => setScanId2(e.target.value)}
                disabled={loading}
              />
            </Grid>
          </Grid>

          <Box sx={{ mt: 2, textAlign: 'center' }}>
            <Button
              type="submit"
              variant="contained"
              disabled={loading}
              startIcon={
                loading ? <CircularProgress size={20} /> : <CompareArrowsIcon />
              }
            >
              Compare Scans
            </Button>
          </Box>
        </form>
      </Paper>

      {result && (
        <>
          {/* Summary */}
          <Grid container spacing={3} sx={{ mb: 3 }}>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 3, backgroundColor: '#e8f5e9' }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                  <RemoveCircleIcon color="success" />
                  <Typography variant="h6">Fixed</Typography>
                </Box>
                <Typography variant="h3">
                  {result.fixed_vulnerabilities.length}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  vulnerabilities fixed
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 3, backgroundColor: '#ffebee' }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                  <AddCircleIcon color="error" />
                  <Typography variant="h6">New</Typography>
                </Box>
                <Typography variant="h3">
                  {result.new_vulnerabilities.length}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  new vulnerabilities
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 3, backgroundColor: '#e3f2fd' }}>
                <Typography variant="h6" sx={{ mb: 1 }}>
                  Unchanged
                </Typography>
                <Typography variant="h3">
                  {result.unchanged_vulnerabilities}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  vulnerabilities
                </Typography>
              </Paper>
            </Grid>
          </Grid>

          {/* Comparison Details */}
          <Paper sx={{ p: 3, mb: 3 }}>
            <Typography variant="h6" gutterBottom>
              Comparison Details
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2">Scan 1 (Baseline)</Typography>
                <Typography variant="body2" color="text.secondary">
                  Image: {result.image_1}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Total: {result.summary.scan_1_total} vulnerabilities
                </Typography>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2">Scan 2 (Compare)</Typography>
                <Typography variant="body2" color="text.secondary">
                  Image: {result.image_2}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Total: {result.summary.scan_2_total} vulnerabilities
                </Typography>
              </Grid>
            </Grid>
          </Paper>

          {/* New Vulnerabilities */}
          {result.new_vulnerabilities.length > 0 && (
            <Paper sx={{ p: 3, mb: 3 }}>
              <Typography variant="h6" gutterBottom color="error">
                New Vulnerabilities ({result.new_vulnerabilities.length})
              </Typography>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>CVE ID</TableCell>
                      <TableCell>Severity</TableCell>
                      <TableCell>Package</TableCell>
                      <TableCell>Version</TableCell>
                      <TableCell>Fix Available</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {result.new_vulnerabilities.slice(0, 20).map((vuln, idx) => (
                      <TableRow key={idx}>
                        <TableCell>{vuln.id}</TableCell>
                        <TableCell>
                          <SeverityChip severity={vuln.severity} />
                        </TableCell>
                        <TableCell>{vuln.package_name}</TableCell>
                        <TableCell>{vuln.package_version}</TableCell>
                        <TableCell>
                          <Chip
                            size="small"
                            label={vuln.fix_available ? 'Yes' : 'No'}
                            color={vuln.fix_available ? 'success' : 'default'}
                          />
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
              {result.new_vulnerabilities.length > 20 && (
                <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                  Showing first 20 of {result.new_vulnerabilities.length}
                </Typography>
              )}
            </Paper>
          )}

          {/* Fixed Vulnerabilities */}
          {result.fixed_vulnerabilities.length > 0 && (
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom color="success.main">
                Fixed Vulnerabilities ({result.fixed_vulnerabilities.length})
              </Typography>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>CVE ID</TableCell>
                      <TableCell>Severity</TableCell>
                      <TableCell>Package</TableCell>
                      <TableCell>Version</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {result.fixed_vulnerabilities.slice(0, 20).map((vuln, idx) => (
                      <TableRow key={idx}>
                        <TableCell>{vuln.id}</TableCell>
                        <TableCell>
                          <SeverityChip severity={vuln.severity} />
                        </TableCell>
                        <TableCell>{vuln.package_name}</TableCell>
                        <TableCell>{vuln.package_version}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
              {result.fixed_vulnerabilities.length > 20 && (
                <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                  Showing first 20 of {result.fixed_vulnerabilities.length}
                </Typography>
              )}
            </Paper>
          )}
        </>
      )}
    </Box>
  );
}

export default Compare;
