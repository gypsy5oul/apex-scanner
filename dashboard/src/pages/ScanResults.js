import React, { useState, useEffect } from 'react';
import { useParams, Link as RouterLink } from 'react-router-dom';
import {
  Box,
  Paper,
  Typography,
  Grid,
  Alert,
  CircularProgress,
  Chip,
  Button,
  Card,
  CardContent,
  Divider,
  Link,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  LinearProgress,
  Tabs,
  Tab,
  Tooltip,
  Accordion,
  AccordionSummary,
  AccordionDetails,
} from '@mui/material';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import RefreshIcon from '@mui/icons-material/Refresh';
import AccountTreeIcon from '@mui/icons-material/AccountTree';
import BuildIcon from '@mui/icons-material/Build';
import SecurityIcon from '@mui/icons-material/Security';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import DownloadIcon from '@mui/icons-material/Download';
import SpeedIcon from '@mui/icons-material/Speed';
import WarningIcon from '@mui/icons-material/Warning';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import GppMaybeIcon from '@mui/icons-material/GppMaybe';
import TrendingUpIcon from '@mui/icons-material/TrendingUp';
import SmartToyIcon from '@mui/icons-material/SmartToy';
import GavelIcon from '@mui/icons-material/Gavel';
import { useTheme, alpha } from '@mui/material/styles';
import { DataGrid } from '@mui/x-data-grid';
import { getSeverity, severityAccent } from '../theme/tokens';
import {
  getScanResult,
  getDependencyGraph,
  getRemediationPlan,
  getQuickWins,
  getRiskScore,
  exportCsv,
  exportExecutivePdf,
  getEnrichedVulnerabilities,
  getKevMatches,
  getLicenseCompliance,
} from '../api';
import SeverityChip from '../components/SeverityChip';
import { VulnerabilityDoughnut } from '../components/VulnerabilityChart';
import AITriagePanel from '../components/AITriagePanel';
import { PageHeaderSkeleton, CardGridSkeleton } from '../components/LoadingSkeletons';
import { CountUp } from '../components/Motion';

// Rewrite report/SBOM URLs to use the actual API host instead of whatever the backend stored
const getApiHost = () => {
  if (window.REACT_APP_API_URL) return window.REACT_APP_API_URL;
  if (process.env.REACT_APP_API_URL) return process.env.REACT_APP_API_URL;
  return `${window.location.protocol}//${window.location.hostname}:7070`;
};

const fixReportUrl = (url) => {
  if (!url) return url;
  try {
    const parsed = new URL(url);
    const apiHost = new URL(getApiHost());
    parsed.protocol = apiHost.protocol;
    parsed.host = apiHost.host;
    return parsed.toString();
  } catch {
    return url;
  }
};

// Download a file by fetching it and creating a blob download link
const downloadFile = async (url, filename) => {
  try {
    const response = await fetch(fixReportUrl(url));
    const blob = await response.blob();
    const blobUrl = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = blobUrl;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(blobUrl);
  } catch (err) {
    console.error('Download failed:', err);
    // Fallback: open in new tab
    window.open(fixReportUrl(url), '_blank');
  }
};

// Map a risk/category label to a severity token (guaranteed-contrast solid color).
const RISK_SEVERITY = { critical: 'critical', high: 'high', medium: 'medium', low: 'low' };

// DataGrid columns for the license-violations table (virtualized + sortable).
const LICENSE_COLUMNS = [
  {
    field: 'severity', headerName: 'Severity', width: 110,
    renderCell: (p) => (
      <Chip
        size="small"
        label={(p.value || '').toUpperCase()}
        color={p.value === 'fail' ? 'error' : p.value === 'warn' ? 'warning' : 'default'}
      />
    ),
  },
  { field: 'name', headerName: 'Package', flex: 1, minWidth: 160, renderCell: (p) => <strong>{p.value}</strong> },
  { field: 'version', headerName: 'Version', width: 130, renderCell: (p) => <Box component="code">{p.value}</Box> },
  { field: 'type', headerName: 'Type', width: 100 },
  { field: 'category', headerName: 'Category', width: 160, renderCell: (p) => <Box component="code">{p.value}</Box> },
  {
    field: 'licenses', headerName: 'License(s)', flex: 1, minWidth: 200, sortable: false,
    valueGetter: (p) => (p.row.licenses || []).join(', '),
    renderCell: (p) => (
      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, py: 0.5 }}>
        {(p.row.licenses || []).map((lic, j) => (
          <Chip key={j} size="small" label={lic} variant="outlined" sx={{ fontSize: '0.7rem' }} />
        ))}
      </Box>
    ),
  },
];

function ScanResults() {
  const theme = useTheme();
  const { scanId } = useParams();
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [polling, setPolling] = useState(false);
  const [activeTab, setActiveTab] = useState(0);

  // New feature states
  const [dependencyGraph, setDependencyGraph] = useState(null);
  const [remediation, setRemediation] = useState(null);
  const [quickWins, setQuickWins] = useState(null);
  const [riskScore, setRiskScore] = useState(null);
  const [enrichedData, setEnrichedData] = useState(null);
  const [kevMatches, setKevMatches] = useState(null);
  const [licenseCompliance, setLicenseCompliance] = useState(null);
  const [featuresLoading, setFeaturesLoading] = useState({
    dependency: false,
    remediation: false,
    risk: false,
    enrichment: false,
    licenses: false,
  });

  const fetchEnterpriseFeatures = async () => {
    // Fetch dependency graph
    setFeaturesLoading(prev => ({ ...prev, dependency: true }));
    try {
      const depRes = await getDependencyGraph(scanId);
      setDependencyGraph(depRes.data);
    } catch (err) {
      console.error('Failed to fetch dependency graph:', err);
    } finally {
      setFeaturesLoading(prev => ({ ...prev, dependency: false }));
    }

    // Fetch remediation plan
    setFeaturesLoading(prev => ({ ...prev, remediation: true }));
    try {
      const [remRes, qwRes] = await Promise.all([
        getRemediationPlan(scanId),
        getQuickWins(scanId),
      ]);
      setRemediation(remRes.data);
      setQuickWins(qwRes.data);
    } catch (err) {
      console.error('Failed to fetch remediation:', err);
    } finally {
      setFeaturesLoading(prev => ({ ...prev, remediation: false }));
    }

    // Fetch risk score
    setFeaturesLoading(prev => ({ ...prev, risk: true }));
    try {
      const riskRes = await getRiskScore(scanId);
      setRiskScore(riskRes.data);
    } catch (err) {
      console.error('Failed to fetch risk score:', err);
    } finally {
      setFeaturesLoading(prev => ({ ...prev, risk: false }));
    }

    // Fetch EPSS/KEV enrichment data
    setFeaturesLoading(prev => ({ ...prev, enrichment: true }));
    try {
      const [enrichedRes, kevRes] = await Promise.all([
        getEnrichedVulnerabilities(scanId),
        getKevMatches(scanId),
      ]);
      setEnrichedData(enrichedRes.data);
      setKevMatches(kevRes.data);
    } catch (err) {
      console.error('Failed to fetch enrichment data:', err);
    } finally {
      setFeaturesLoading(prev => ({ ...prev, enrichment: false }));
    }

    // Fetch license compliance (returns 404 for scans that pre-date the feature)
    setFeaturesLoading(prev => ({ ...prev, licenses: true }));
    try {
      const lcRes = await getLicenseCompliance(scanId);
      setLicenseCompliance(lcRes.data);
    } catch (err) {
      // Silently absent for old scans — log to console only.
      if (err?.response?.status !== 404) {
        console.error('Failed to fetch license compliance:', err);
      }
    } finally {
      setFeaturesLoading(prev => ({ ...prev, licenses: false }));
    }
  };

  const handleExportCsv = async () => {
    try {
      const response = await exportCsv(scanId);
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `scan-${scanId}.csv`);
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (err) {
      console.error('Failed to export CSV:', err);
    }
  };

  const handleExportPdf = async () => {
    try {
      const response = await exportExecutivePdf(scanId, true);
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `scan-${scanId}-report.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (err) {
      console.error('Failed to export PDF:', err);
    }
  };

  const fetchResult = async () => {
    try {
      const response = await getScanResult(scanId);
      setResult(response.data);
      if (response.data.status === 'in_progress') {
        setPolling(true);
      } else {
        setPolling(false);
      }
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchResult();
    // eslint-disable-next-line
  }, [scanId]);

  useEffect(() => {
    if (polling) {
      const interval = setInterval(fetchResult, 5000);
      return () => clearInterval(interval);
    }
    // eslint-disable-next-line
  }, [polling]);

  // Fetch enterprise features when scan is completed
  useEffect(() => {
    if (result?.status === 'completed') {
      fetchEnterpriseFeatures();
    }
    // eslint-disable-next-line
  }, [result?.status]);

  if (loading) {
    return (
      <Box>
        <PageHeaderSkeleton />
        <CardGridSkeleton count={3} height={220} cols={{ xs: 12, md: 4 }} />
      </Box>
    );
  }

  if (error) {
    return (
      <Alert severity="error" sx={{ mt: 2 }}>
        {error}
      </Alert>
    );
  }

  if (!result) return null;

  const isPassing = result.status_code === 200;

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 3 }}>
        <Typography variant="h4">Scan Results</Typography>
        <Button
          variant="outlined"
          startIcon={<RefreshIcon />}
          onClick={fetchResult}
        >
          Refresh
        </Button>
      </Box>

      {result.status === 'in_progress' && (
        <Alert severity="info" sx={{ mb: 3 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <CircularProgress size={20} />
            Scan in progress... This page will auto-refresh.
          </Box>
        </Alert>
      )}

      {result.status === 'failed' && (
        <Alert severity="error" sx={{ mb: 3 }}>
          Scan failed: {result.error}
        </Alert>
      )}

      {result.status === 'completed' && (
        <Alert severity={isPassing ? 'success' : 'error'} sx={{ mb: 3 }}>
          {isPassing
            ? 'PASSED - No critical or high vulnerabilities found'
            : 'FAILED - Critical or high vulnerabilities detected'}
        </Alert>
      )}

      {result.multi_scanner?.scan_quality === 'degraded' && (
        <Alert severity="warning" sx={{ mb: 3 }}>
          <strong>DEGRADED SCAN</strong> — Not all scanners completed successfully.
          Requested: {result.multi_scanner.scanners_requested?.join(', ')} |
          Succeeded: {result.multi_scanner.scanners_used?.join(', ') || 'none'}.
          {result.multi_scanner.scanner_errors &&
            Object.entries(result.multi_scanner.scanner_errors).map(([name, err]) => (
              <Box key={name} sx={{ mt: 0.5 }}>
                <strong>{name}:</strong> {err}
              </Box>
            ))
          }
        </Alert>
      )}

      <Grid container spacing={3}>
        {/* Summary Card */}
        <Grid item xs={12} md={4}>
          <Paper sx={{ p: 3, height: '100%' }}>
            <Typography variant="h6" gutterBottom>
              Scan Summary
            </Typography>
            <Divider sx={{ mb: 2 }} />
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
              <Typography>
                <strong>Image:</strong> {result.image_name}
              </Typography>
              <Typography>
                <strong>Scan ID:</strong>{' '}
                <code style={{ fontSize: '0.8em' }}>{result.scan_id}</code>
              </Typography>
              <Typography>
                <strong>Status:</strong>{' '}
                <Chip
                  size="small"
                  label={result.status}
                  color={
                    result.status === 'completed'
                      ? 'success'
                      : result.status === 'failed'
                      ? 'error'
                      : 'warning'
                  }
                />
              </Typography>
              {result.scan_timestamp && (
                <Typography>
                  <strong>Completed:</strong>{' '}
                  {new Date(result.scan_timestamp).toLocaleString()}
                </Typography>
              )}
              {result.multi_scanner?.scanners_used && (
                <Typography>
                  <strong>Scanners:</strong>{' '}
                  {result.multi_scanner.scanners_used.join(', ')}
                </Typography>
              )}
              {result.multi_scanner?.scanner_errors &&
                Object.keys(result.multi_scanner.scanner_errors).length > 0 && (
                <Box sx={{ mt: 1 }}>
                  {Object.entries(result.multi_scanner.scanner_errors).map(
                    ([name, error]) =>
                      error && (
                        <Chip
                          key={name}
                          label={`${name}: ${error.length > 60 ? error.substring(0, 60) + '...' : error}`}
                          size="small"
                          color="warning"
                          variant="outlined"
                          sx={{ mr: 0.5, mb: 0.5 }}
                        />
                      )
                  )}
                </Box>
              )}
            </Box>
          </Paper>
        </Grid>

        {/* Vulnerability Chart */}
        <Grid item xs={12} md={4}>
          <Paper sx={{ p: 3, height: '100%' }}>
            <Typography variant="h6" gutterBottom>
              Vulnerability Distribution
            </Typography>
            <Box sx={{ height: 300 }}>
              <VulnerabilityDoughnut vulnerabilities={result.vulnerabilities} />
            </Box>
          </Paper>
        </Grid>

        {/* Severity Counts */}
        <Grid item xs={12} md={4}>
          <Paper sx={{ p: 3, height: '100%' }}>
            <Typography variant="h6" gutterBottom>
              Vulnerability Counts
            </Typography>
            <Divider sx={{ mb: 2 }} />
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
              <SeverityChip
                severity="Critical"
                count={result.vulnerabilities?.critical || 0}
              />
              <SeverityChip
                severity="High"
                count={result.vulnerabilities?.high || 0}
              />
              <SeverityChip
                severity="Medium"
                count={result.vulnerabilities?.medium || 0}
              />
              <SeverityChip
                severity="Low"
                count={result.vulnerabilities?.low || 0}
              />
              <SeverityChip
                severity="Negligible"
                count={result.vulnerabilities?.negligible || 0}
              />
            </Box>
          </Paper>
        </Grid>

        {/* Multi-Scanner Data */}
        {result.multi_scanner && (
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Multi-Scanner Analysis
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={6}>
                    <Typography variant="body2" color="text.secondary">
                      Found by Both
                    </Typography>
                    <Typography variant="h5">
                      {result.multi_scanner.both_scanners}
                    </Typography>
                  </Grid>
                  <Grid item xs={6}>
                    <Typography variant="body2" color="text.secondary">
                      Grype Only
                    </Typography>
                    <Typography variant="h5">
                      {result.multi_scanner.grype_unique}
                    </Typography>
                  </Grid>
                  <Grid item xs={6}>
                    <Typography variant="body2" color="text.secondary">
                      Trivy Only
                    </Typography>
                    <Typography variant="h5">
                      {result.multi_scanner.trivy_unique}
                    </Typography>
                  </Grid>
                  <Grid item xs={6}>
                    <Typography variant="body2" color="text.secondary">
                      Secrets Found
                    </Typography>
                    <Typography variant="h5" color="error">
                      {result.multi_scanner.total_secrets}
                    </Typography>
                  </Grid>
                </Grid>
              </CardContent>
            </Card>
          </Grid>
        )}

        {/* SBOM Info */}
        {result.sbom && (
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  SBOM Information
                </Typography>
                <Typography>
                  <strong>Total Packages:</strong> {result.sbom.total_packages}
                </Typography>
                <Typography sx={{ mt: 1 }}>
                  <strong>Available Formats:</strong>
                </Typography>
                <Box sx={{ display: 'flex', gap: 1, mt: 1 }}>
                  {result.sbom.available_formats?.map((format) => (
                    <Chip key={format} label={format} size="small" />
                  ))}
                </Box>
              </CardContent>
            </Card>
          </Grid>
        )}

        {/* Links */}
        {result.report_url && (
          <Grid item xs={12}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom>
                Reports & Downloads
              </Typography>
              <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
                <Button
                  variant="contained"
                  component={Link}
                  href={fixReportUrl(result.report_url)}
                  target="_blank"
                  endIcon={<OpenInNewIcon />}
                >
                  View Full Report
                </Button>
                <Button
                  variant="contained"
                  startIcon={<DownloadIcon />}
                  color="primary"
                  onClick={() => downloadFile(result.report_url, `${scanId}_vulnerability_report.html`)}
                >
                  Download Report
                </Button>
                {result.sbom?.html_report_url && (
                  <>
                    <Button
                      variant="outlined"
                      component={Link}
                      href={fixReportUrl(result.sbom.html_report_url)}
                      target="_blank"
                      endIcon={<OpenInNewIcon />}
                    >
                      View SBOM Report
                    </Button>
                    <Button
                      variant="outlined"
                      startIcon={<DownloadIcon />}
                      onClick={() => downloadFile(result.sbom.html_report_url, `${scanId}_sbom_report.html`)}
                    >
                      Download SBOM Report
                    </Button>
                  </>
                )}
              </Box>
              {/* SBOM JSON Downloads */}
              {(result.sbom?.spdx_url || result.sbom?.cyclonedx_url || result.sbom?.syft_url) && (
                <Box sx={{ mt: 2 }}>
                  <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                    Download SBOM (JSON)
                  </Typography>
                  <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                    {result.sbom?.spdx_url && (
                      <Button
                        size="small"
                        variant="outlined"
                        startIcon={<DownloadIcon />}
                        onClick={() => downloadFile(result.sbom.spdx_url, `${scanId}_spdx.json`)}
                      >
                        SPDX
                      </Button>
                    )}
                    {result.sbom?.cyclonedx_url && (
                      <Button
                        size="small"
                        variant="outlined"
                        startIcon={<DownloadIcon />}
                        onClick={() => downloadFile(result.sbom.cyclonedx_url, `${scanId}_cyclonedx.json`)}
                      >
                        CycloneDX
                      </Button>
                    )}
                    {result.sbom?.syft_url && (
                      <Button
                        size="small"
                        variant="outlined"
                        startIcon={<DownloadIcon />}
                        onClick={() => downloadFile(result.sbom.syft_url, `${scanId}_syft.json`)}
                      >
                        Syft
                      </Button>
                    )}
                  </Box>
                </Box>
              )}
              {/* Export & Navigation */}
              <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap', mt: 2 }}>
                <Button
                  variant="outlined"
                  startIcon={<DownloadIcon />}
                  onClick={handleExportCsv}
                >
                  Export CSV
                </Button>
                <Button
                  variant="outlined"
                  startIcon={<DownloadIcon />}
                  onClick={handleExportPdf}
                >
                  Export PDF
                </Button>
                <Button
                  variant="outlined"
                  component={RouterLink}
                  to={`/history`}
                >
                  View History
                </Button>
              </Box>
            </Paper>
          </Grid>
        )}

        {/* Enterprise Features Section */}
        {result.status === 'completed' && (
          <Grid item xs={12}>
            <Paper sx={{ p: 0 }}>
              <Tabs
                value={activeTab}
                onChange={(e, newValue) => setActiveTab(newValue)}
                sx={{ borderBottom: 1, borderColor: 'divider', px: 2 }}
              >
                <Tab icon={<SpeedIcon />} label="Risk Score" iconPosition="start" />
                <Tab
                  icon={<GppMaybeIcon />}
                  label={
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      EPSS/KEV
                      {kevMatches?.total_kev_matches > 0 && (
                        <Chip size="small" label={kevMatches.total_kev_matches} color="error" />
                      )}
                    </Box>
                  }
                  iconPosition="start"
                />
                <Tab icon={<BuildIcon />} label="Remediation" iconPosition="start" />
                <Tab icon={<AccountTreeIcon />} label="Dependencies" iconPosition="start" />
                <Tab icon={<SmartToyIcon />} label="AI Triage" iconPosition="start" />
                <Tab
                  icon={<GavelIcon />}
                  label={
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      License Compliance
                      {licenseCompliance?.status === 'fail' && (
                        <Chip size="small" label="FAIL" color="error" />
                      )}
                      {licenseCompliance?.status === 'warn' && (
                        <Chip size="small" label="WARN" color="warning" />
                      )}
                      {licenseCompliance?.status === 'pass' && (
                        <Chip size="small" label="PASS" color="success" />
                      )}
                    </Box>
                  }
                  iconPosition="start"
                />
              </Tabs>

              <Box sx={{ p: 3 }}>
                {/* Risk Score Tab */}
                {activeTab === 0 && (
                  <Box>
                    {featuresLoading.risk ? (
                      <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
                        <CircularProgress />
                      </Box>
                    ) : riskScore ? (
                      <Grid container spacing={3}>
                        <Grid item xs={12} md={4}>
                          <Card sx={{ bgcolor: getSeverity(RISK_SEVERITY[riskScore.overall_risk_level] || 'low').solid, color: '#fff', border: 'none' }}>
                            <CardContent sx={{ textAlign: 'center' }}>
                              <Typography variant="h2" fontWeight="bold">
                                {riskScore.overall_risk_score?.toFixed(1) || 0}
                              </Typography>
                              <Typography variant="h6">
                                Overall Risk Score
                              </Typography>
                              <Chip
                                label={riskScore.overall_risk_level?.toUpperCase() || 'UNKNOWN'}
                                sx={{ mt: 1, bgcolor: 'rgba(255,255,255,0.2)', color: 'white' }}
                              />
                            </CardContent>
                          </Card>
                        </Grid>
                        <Grid item xs={12} md={8}>
                          <Typography variant="h6" gutterBottom>Risk Distribution</Typography>
                          {riskScore.risk_distribution && Object.entries(riskScore.risk_distribution).map(([severity, count]) => (
                            <Box key={severity} sx={{ mb: 2 }}>
                              <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
                                <Typography variant="body2" sx={{ textTransform: 'capitalize' }}>
                                  {severity}
                                </Typography>
                                <Typography variant="body2" fontWeight="bold">
                                  {count} vulnerabilities
                                </Typography>
                              </Box>
                              <LinearProgress
                                variant="determinate"
                                value={Math.min(count / (riskScore.total_vulnerabilities || 1) * 100, 100)}
                                sx={{ height: 8, borderRadius: 1 }}
                                color={severity === 'critical' ? 'error' : severity === 'high' ? 'warning' : severity === 'medium' ? 'info' : 'success'}
                              />
                            </Box>
                          ))}
                          <Box sx={{ mt: 2 }}>
                            <Typography variant="body2" color="text.secondary">
                              Total Vulnerabilities: {riskScore.total_vulnerabilities || 0}
                            </Typography>
                            <Typography variant="body2" color="text.secondary">
                              Actively Exploited: {riskScore.actively_exploited_count || 0}
                            </Typography>
                          </Box>
                        </Grid>
                        {riskScore.kev_vulnerabilities?.length > 0 && (
                          <Grid item xs={12}>
                            <Alert severity="error" icon={<WarningIcon />}>
                              <Typography variant="subtitle2">
                                {riskScore.kev_vulnerabilities.length} Known Exploited Vulnerabilities (KEV) Found!
                              </Typography>
                              <Box sx={{ mt: 1 }}>
                                {riskScore.kev_vulnerabilities.slice(0, 5).map((cve, idx) => (
                                  <Chip key={idx} label={cve} size="small" color="error" sx={{ mr: 0.5, mb: 0.5 }} />
                                ))}
                                {riskScore.kev_vulnerabilities.length > 5 && (
                                  <Chip label={`+${riskScore.kev_vulnerabilities.length - 5} more`} size="small" />
                                )}
                              </Box>
                            </Alert>
                          </Grid>
                        )}
                      </Grid>
                    ) : (
                      <Typography color="text.secondary">Risk score data not available</Typography>
                    )}
                  </Box>
                )}

                {/* EPSS/KEV Tab */}
                {activeTab === 1 && (
                  <Box>
                    {featuresLoading.enrichment ? (
                      <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
                        <CircularProgress />
                      </Box>
                    ) : (
                      <Grid container spacing={3}>
                        {/* Summary Cards */}
                        <Grid item xs={12}>
                          <Grid container spacing={2}>
                            <Grid item xs={12} sm={4}>
                              <Card sx={{ bgcolor: getSeverity(kevMatches?.total_kev_matches > 0 ? 'critical' : 'low').solid, color: '#fff', border: 'none' }}>
                                <CardContent sx={{ textAlign: 'center' }}>
                                  <GppMaybeIcon sx={{ fontSize: 40, mb: 1 }} />
                                  <Typography variant="h3" fontWeight="bold">
                                    <CountUp value={kevMatches?.total_kev_matches || 0} />
                                  </Typography>
                                  <Typography variant="body2">
                                    Known Exploited (KEV)
                                  </Typography>
                                </CardContent>
                              </Card>
                            </Grid>
                            <Grid item xs={12} sm={4}>
                              <Card sx={{ bgcolor: getSeverity('medium').solid, color: '#fff', border: 'none' }}>
                                <CardContent sx={{ textAlign: 'center' }}>
                                  <TrendingUpIcon sx={{ fontSize: 40, mb: 1 }} />
                                  <Typography variant="h3" fontWeight="bold">
                                    <CountUp value={enrichedData?.enrichment_summary?.high_risk_vulns || 0} />
                                  </Typography>
                                  <Typography variant="body2">
                                    High Risk Priority
                                  </Typography>
                                </CardContent>
                              </Card>
                            </Grid>
                            <Grid item xs={12} sm={4}>
                              <Card sx={{ bgcolor: theme.palette.primary.dark, color: '#fff', border: 'none' }}>
                                <CardContent sx={{ textAlign: 'center' }}>
                                  <SecurityIcon sx={{ fontSize: 40, mb: 1 }} />
                                  <Typography variant="h3" fontWeight="bold">
                                    <CountUp value={enrichedData?.enrichment_summary?.epss_enriched || 0} />
                                  </Typography>
                                  <Typography variant="body2">
                                    EPSS Enriched
                                  </Typography>
                                </CardContent>
                              </Card>
                            </Grid>
                          </Grid>
                        </Grid>

                        {/* KEV Vulnerabilities */}
                        {kevMatches?.total_kev_matches > 0 && (
                          <Grid item xs={12}>
                            <Alert severity="error" icon={<WarningIcon />} sx={{ mb: 2 }}>
                              <Typography variant="subtitle2" fontWeight="bold">
                                CISA Known Exploited Vulnerabilities Found - Immediate Action Required
                              </Typography>
                            </Alert>
                            <TableContainer component={Paper} variant="outlined">
                              <Table size="small">
                                <TableHead>
                                  <TableRow sx={{ bgcolor: 'error.dark' }}>
                                    <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>CVE ID</TableCell>
                                    <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>Package</TableCell>
                                    <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>EPSS Score</TableCell>
                                    <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>KEV Details</TableCell>
                                    <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>Due Date</TableCell>
                                  </TableRow>
                                </TableHead>
                                <TableBody>
                                  {kevMatches?.vulnerabilities?.map((vuln, idx) => (
                                    <TableRow key={idx} sx={{ bgcolor: (t) => alpha(t.palette.error.main, t.palette.mode === 'dark' ? 0.12 : 0.06) }}>
                                      <TableCell>
                                        <Link
                                          href={`https://nvd.nist.gov/vuln/detail/${vuln.id}`}
                                          target="_blank"
                                          rel="noopener"
                                          sx={{ fontWeight: 'bold' }}
                                        >
                                          {vuln.id}
                                        </Link>
                                      </TableCell>
                                      <TableCell>
                                        <Typography variant="body2" fontFamily="monospace">
                                          {vuln.package_name}
                                        </Typography>
                                        <Typography variant="caption" color="text.secondary">
                                          {vuln.package_version}
                                        </Typography>
                                      </TableCell>
                                      <TableCell>
                                        {vuln.epss_score ? (
                                          <Tooltip title={`${(vuln.epss_percentile * 100).toFixed(1)}th percentile`}>
                                            <Chip
                                              label={`${(vuln.epss_score * 100).toFixed(2)}%`}
                                              size="small"
                                              color={vuln.epss_score >= 0.5 ? 'error' : vuln.epss_score >= 0.1 ? 'warning' : 'default'}
                                            />
                                          </Tooltip>
                                        ) : 'N/A'}
                                      </TableCell>
                                      <TableCell>
                                        <Typography variant="body2" fontSize="0.75rem">
                                          {vuln.kev_details?.vulnerability_name || vuln.description?.substring(0, 80)}
                                        </Typography>
                                        {vuln.kev_details?.known_ransomware_use === 'Known' && (
                                          <Chip label="Ransomware" size="small" color="error" sx={{ mt: 0.5 }} />
                                        )}
                                      </TableCell>
                                      <TableCell>
                                        <Typography variant="body2" fontWeight="bold" color="error">
                                          {vuln.kev_details?.due_date || 'N/A'}
                                        </Typography>
                                      </TableCell>
                                    </TableRow>
                                  ))}
                                </TableBody>
                              </Table>
                            </TableContainer>
                          </Grid>
                        )}

                        {/* High EPSS Score Vulnerabilities */}
                        <Grid item xs={12}>
                          <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            <TrendingUpIcon /> Top Vulnerabilities by EPSS Score
                          </Typography>
                          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                            EPSS (Exploit Prediction Scoring System) predicts the probability of exploitation in the next 30 days
                          </Typography>
                          <TableContainer component={Paper} variant="outlined">
                            <Table size="small">
                              <TableHead>
                                <TableRow>
                                  <TableCell>CVE ID</TableCell>
                                  <TableCell>Package</TableCell>
                                  <TableCell>Severity</TableCell>
                                  <TableCell>EPSS Score</TableCell>
                                  <TableCell>Percentile</TableCell>
                                  <TableCell>Risk Priority</TableCell>
                                  <TableCell>Fix Available</TableCell>
                                </TableRow>
                              </TableHead>
                              <TableBody>
                                {enrichedData?.vulnerabilities
                                  ?.filter(v => v.epss_score)
                                  ?.sort((a, b) => (b.epss_score || 0) - (a.epss_score || 0))
                                  ?.slice(0, 15)
                                  ?.map((vuln, idx) => (
                                    <TableRow key={idx}>
                                      <TableCell>
                                        <Link
                                          href={`https://nvd.nist.gov/vuln/detail/${vuln.id}`}
                                          target="_blank"
                                          rel="noopener"
                                        >
                                          {vuln.id}
                                        </Link>
                                        {vuln.in_kev && (
                                          <Chip label="KEV" size="small" color="error" sx={{ ml: 1 }} />
                                        )}
                                      </TableCell>
                                      <TableCell>
                                        <Typography variant="body2" fontFamily="monospace" fontSize="0.75rem">
                                          {vuln.package_name}
                                        </Typography>
                                      </TableCell>
                                      <TableCell>
                                        <SeverityChip severity={vuln.severity} />
                                      </TableCell>
                                      <TableCell>
                                        <Chip
                                          label={`${(vuln.epss_score * 100).toFixed(2)}%`}
                                          size="small"
                                          color={vuln.epss_score >= 0.5 ? 'error' : vuln.epss_score >= 0.1 ? 'warning' : 'default'}
                                        />
                                      </TableCell>
                                      <TableCell>
                                        <LinearProgress
                                          variant="determinate"
                                          value={(vuln.epss_percentile || 0) * 100}
                                          sx={{ width: 60, mr: 1, display: 'inline-block', verticalAlign: 'middle' }}
                                        />
                                        <Typography variant="caption">
                                          {((vuln.epss_percentile || 0) * 100).toFixed(0)}%
                                        </Typography>
                                      </TableCell>
                                      <TableCell>
                                        <Chip
                                          label={vuln.risk_priority || 'unknown'}
                                          size="small"
                                          color={
                                            vuln.risk_priority === 'critical' ? 'error' :
                                            vuln.risk_priority === 'high' ? 'warning' :
                                            vuln.risk_priority === 'medium' ? 'info' : 'default'
                                          }
                                        />
                                      </TableCell>
                                      <TableCell>
                                        {vuln.fix_available ? (
                                          <Chip label="Yes" size="small" color="success" />
                                        ) : (
                                          <Chip label="No" size="small" color="default" />
                                        )}
                                      </TableCell>
                                    </TableRow>
                                  ))}
                              </TableBody>
                            </Table>
                          </TableContainer>
                          {(!enrichedData?.vulnerabilities || enrichedData.vulnerabilities.filter(v => v.epss_score).length === 0) && (
                            <Typography color="text.secondary" sx={{ mt: 2, textAlign: 'center' }}>
                              No EPSS data available for this scan. Run a new scan to get enriched data.
                            </Typography>
                          )}
                        </Grid>
                      </Grid>
                    )}
                  </Box>
                )}

                {/* Remediation Tab */}
                {activeTab === 2 && (
                  <Box>
                    {featuresLoading.remediation ? (
                      <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
                        <CircularProgress />
                      </Box>
                    ) : (
                      <Grid container spacing={3}>
                        {/* Quick Wins */}
                        {quickWins?.quick_wins?.length > 0 && (
                          <Grid item xs={12}>
                            <Alert severity="info" icon={<CheckCircleIcon />} sx={{ mb: 2 }}>
                              <Typography variant="subtitle2">
                                Quick Wins: {quickWins.quick_wins.length} fixes that will resolve {quickWins.summary?.total_vulns_fixed || 0} vulnerabilities
                              </Typography>
                            </Alert>
                            <TableContainer component={Paper} variant="outlined">
                              <Table size="small">
                                <TableHead>
                                  <TableRow>
                                    <TableCell>Package</TableCell>
                                    <TableCell>Current</TableCell>
                                    <TableCell>Upgrade To</TableCell>
                                    <TableCell>Vulns Fixed</TableCell>
                                    <TableCell>Command</TableCell>
                                  </TableRow>
                                </TableHead>
                                <TableBody>
                                  {quickWins.quick_wins.slice(0, 10).map((qw, idx) => (
                                    <TableRow key={idx}>
                                      <TableCell>
                                        <Typography variant="body2" fontFamily="monospace">
                                          {qw.package || qw.package_name}
                                        </Typography>
                                      </TableCell>
                                      <TableCell>
                                        <Typography variant="body2" fontFamily="monospace" fontSize="0.75rem">
                                          {qw.current || qw.current_version}
                                        </Typography>
                                      </TableCell>
                                      <TableCell>
                                        <Chip label={qw.target || qw.recommended_version} size="small" color="success" />
                                      </TableCell>
                                      <TableCell>
                                        <Chip label={qw.vulns_fixed} size="small" color="warning" />
                                      </TableCell>
                                      <TableCell>
                                        <Typography variant="body2" fontFamily="monospace" fontSize="0.7rem" color="text.secondary">
                                          {qw.command}
                                        </Typography>
                                      </TableCell>
                                    </TableRow>
                                  ))}
                                </TableBody>
                              </Table>
                            </TableContainer>
                          </Grid>
                        )}

                        {/* Full Remediation Plan */}
                        {remediation?.actions?.length > 0 && (
                          <Grid item xs={12}>
                            <Typography variant="h6" gutterBottom>Full Remediation Plan</Typography>
                            <Typography variant="body2" color="text.secondary" gutterBottom>
                              {remediation.summary?.packages_requiring_update || remediation.actions?.length || 0} packages need updates to fix {remediation.summary?.total_vulnerabilities || 0} vulnerabilities
                            </Typography>
                            {Object.entries(
                              remediation.actions.reduce((acc, action) => {
                                const type = action.package_type || 'other';
                                if (!acc[type]) acc[type] = [];
                                acc[type].push(action);
                                return acc;
                              }, {})
                            ).map(([type, actions]) => (
                              <Accordion key={type} defaultExpanded={type === 'npm' || type === 'pip'}>
                                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                                  <Typography sx={{ textTransform: 'uppercase', fontWeight: 'bold' }}>
                                    {type} ({actions.length} packages)
                                  </Typography>
                                </AccordionSummary>
                                <AccordionDetails>
                                  <TableContainer>
                                    <Table size="small">
                                      <TableHead>
                                        <TableRow>
                                          <TableCell>Package</TableCell>
                                          <TableCell>Current</TableCell>
                                          <TableCell>Fixed In</TableCell>
                                          <TableCell>Vulnerabilities</TableCell>
                                        </TableRow>
                                      </TableHead>
                                      <TableBody>
                                        {actions.slice(0, 20).map((action, idx) => (
                                          <TableRow key={idx}>
                                            <TableCell>
                                              <Typography variant="body2" fontFamily="monospace">
                                                {action.package_name}
                                              </Typography>
                                            </TableCell>
                                            <TableCell>{action.current_version}</TableCell>
                                            <TableCell>
                                              {action.fixed_version ? (
                                                <Chip label={action.fixed_version} size="small" color="success" />
                                              ) : (
                                                <Chip label="No fix" size="small" color="default" />
                                              )}
                                            </TableCell>
                                            <TableCell>
                                              {action.vulnerabilities_fixed?.slice(0, 3).map((cve, i) => (
                                                <Chip key={i} label={cve} size="small" sx={{ mr: 0.5, mb: 0.5 }} />
                                              ))}
                                              {action.vulnerabilities_fixed?.length > 3 && (
                                                <Chip label={`+${action.vulnerabilities_fixed.length - 3}`} size="small" />
                                              )}
                                            </TableCell>
                                          </TableRow>
                                        ))}
                                      </TableBody>
                                    </Table>
                                  </TableContainer>
                                </AccordionDetails>
                              </Accordion>
                            ))}
                          </Grid>
                        )}

                        {!quickWins?.quick_wins?.length && !remediation?.actions?.length && (
                          <Grid item xs={12}>
                            <Typography color="text.secondary">No remediation data available</Typography>
                          </Grid>
                        )}
                      </Grid>
                    )}
                  </Box>
                )}

                {/* Dependencies Tab */}
                {activeTab === 3 && (
                  <Box>
                    {featuresLoading.dependency ? (
                      <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
                        <CircularProgress />
                      </Box>
                    ) : dependencyGraph ? (
                      <Grid container spacing={3}>
                        <Grid item xs={12} md={4}>
                          <Card variant="outlined">
                            <CardContent>
                              <Typography variant="h6" gutterBottom>Summary</Typography>
                              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                                <Typography>
                                  <strong>Total Packages:</strong> {dependencyGraph.statistics?.total_packages || dependencyGraph.node_count || 0}
                                </Typography>
                                <Typography>
                                  <strong>Vulnerable:</strong>{' '}
                                  <Chip
                                    label={dependencyGraph.statistics?.vulnerable_packages || 0}
                                    size="small"
                                    color={dependencyGraph.statistics?.vulnerable_packages > 0 ? "error" : "success"}
                                  />
                                </Typography>
                                <Typography>
                                  <strong>Critical:</strong>{' '}
                                  <Chip
                                    label={dependencyGraph.statistics?.critical_vulnerabilities || 0}
                                    size="small"
                                    color="error"
                                    variant="outlined"
                                  />
                                  {' '}<strong>High:</strong>{' '}
                                  <Chip
                                    label={dependencyGraph.statistics?.high_vulnerabilities || 0}
                                    size="small"
                                    color="warning"
                                    variant="outlined"
                                  />
                                </Typography>
                                <Typography>
                                  <strong>Dependencies:</strong> {dependencyGraph.edge_count || 0} edges
                                </Typography>
                              </Box>
                            </CardContent>
                          </Card>
                        </Grid>
                        <Grid item xs={12} md={8}>
                          <Typography variant="h6" gutterBottom>Vulnerable Packages</Typography>
                          {dependencyGraph.nodes?.filter(n => n.vuln_count > 0).length > 0 ? (
                            <TableContainer component={Paper} variant="outlined">
                              <Table size="small">
                                <TableHead>
                                  <TableRow>
                                    <TableCell>Package</TableCell>
                                    <TableCell>Version</TableCell>
                                    <TableCell>Type</TableCell>
                                    <TableCell>Vulnerabilities</TableCell>
                                  </TableRow>
                                </TableHead>
                                <TableBody>
                                  {dependencyGraph.nodes?.filter(n => n.vuln_count > 0).slice(0, 15).map((pkg, idx) => (
                                    <TableRow key={idx}>
                                      <TableCell>
                                        <Typography variant="body2" fontFamily="monospace">
                                          {pkg.name}
                                        </Typography>
                                      </TableCell>
                                      <TableCell>{pkg.version}</TableCell>
                                      <TableCell>
                                        <Chip label={pkg.type} size="small" variant="outlined" />
                                      </TableCell>
                                      <TableCell>
                                        <Chip
                                          label={pkg.vuln_count || 0}
                                          size="small"
                                          color={pkg.critical_count > 0 ? 'error' : pkg.high_count > 0 ? 'warning' : 'default'}
                                        />
                                      </TableCell>
                                    </TableRow>
                                  ))}
                                </TableBody>
                              </Table>
                            </TableContainer>
                          ) : (
                            <Typography color="text.secondary">No vulnerable packages found in dependencies</Typography>
                          )}
                        </Grid>
                      </Grid>
                    ) : (
                      <Typography color="text.secondary">Dependency graph data not available</Typography>
                    )}
                  </Box>
                )}

                {/* AI Triage Tab */}
                {activeTab === 4 && (
                  <AITriagePanel scanId={scanId} />
                )}

                {/* License Compliance Tab — shows the same data as the HTML
                    report's License Compliance section, fetched from
                    /api/v2/scan/{id}/licenses. Older scans return 404 and
                    we render an empty state instead of an error. */}
                {activeTab === 5 && (
                  <Box>
                    {featuresLoading.licenses ? (
                      <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
                        <CircularProgress />
                      </Box>
                    ) : licenseCompliance ? (
                      <>
                        {/* Status alert at the top */}
                        {(() => {
                          const status = licenseCompliance.status;
                          const sev = licenseCompliance.severity_counts || {};
                          const counts = licenseCompliance.counts || {};
                          const totalPkgs = licenseCompliance.total_packages || 0;
                          const distinct = licenseCompliance.distinct_licenses || 0;
                          const violations = licenseCompliance.violations || [];

                          const alertProps =
                            status === 'fail' ? { severity: 'error',   title: 'Policy Violations',  } :
                            status === 'warn' ? { severity: 'warning', title: 'Review Required',    } :
                                                { severity: 'success', title: 'No Policy Issues',   };

                          const summaryLine =
                            status === 'fail'
                              ? `${sev.fail || 0} package(s) violate policy${sev.warn ? `, ${sev.warn} need review` : ''} — restricted licenses (AGPL / SSPL) found.`
                              : status === 'warn'
                              ? `${sev.warn || 0} package(s) need review — GPL / source-available / proprietary licenses present.`
                              : `No policy issues. ${totalPkgs} packages scanned, ${distinct} distinct licenses found.`;

                          return (
                            <>
                              <Alert severity={alertProps.severity} sx={{ mb: 3 }}>
                                <strong>{alertProps.title}:</strong> {summaryLine}
                              </Alert>

                              <Typography variant="h6" gutterBottom>License Categories</Typography>
                              <Grid container spacing={2} sx={{ mb: 3 }}>
                                {[
                                  { key: 'network_copyleft', label: 'Network Copyleft', subtitle: 'AGPL / SSPL', sev: 'critical' },
                                  { key: 'source_available', label: 'Source-Available', subtitle: 'BSL / Elastic / Commons', sev: 'high' },
                                  { key: 'strong_copyleft',  label: 'Strong Copyleft',  subtitle: 'GPL / EPL / OSL',     sev: 'high' },
                                  { key: 'proprietary',      label: 'Proprietary',      subtitle: 'Commercial / closed',  sev: 'high' },
                                  { key: 'weak_copyleft',    label: 'Weak Copyleft',    subtitle: 'LGPL / MPL / CDDL',    sev: 'medium' },
                                  { key: 'unknown',          label: 'Unknown / Unparsed', subtitle: 'Review needed',     sev: 'negligible' },
                                  { key: 'permissive',       label: 'Permissive',       subtitle: 'MIT / BSD / Apache',  sev: 'low' },
                                ].filter(c => (counts[c.key] || 0) > 0 || c.key === 'permissive').map(c => (
                                  <Grid item xs={6} sm={4} md={3} key={c.key}>
                                    <Card sx={{ borderLeft: `4px solid ${severityAccent(c.sev, theme.palette.mode)}` }}>
                                      <CardContent sx={{ p: 2, '&:last-child': { pb: 2 } }}>
                                        <Typography variant="caption" color="text.secondary">{c.label}</Typography>
                                        <Typography variant="h4" sx={{ color: getSeverity(c.sev).solid, fontWeight: 700 }}>
                                          {counts[c.key] || 0}
                                        </Typography>
                                        <Typography variant="caption" color="text.secondary">{c.subtitle}</Typography>
                                      </CardContent>
                                    </Card>
                                  </Grid>
                                ))}
                              </Grid>

                              {violations.length > 0 ? (
                                <>
                                  <Typography variant="h6" gutterBottom>
                                    Packages Requiring Review ({violations.length})
                                  </Typography>
                                  <Box sx={{ height: 520, width: '100%' }}>
                                    <DataGrid
                                      rows={violations.map((v, i) => ({ id: i, ...v }))}
                                      columns={LICENSE_COLUMNS}
                                      density="compact"
                                      getRowHeight={() => 'auto'}
                                      pageSizeOptions={[25, 50, 100]}
                                      initialState={{
                                        pagination: { paginationModel: { pageSize: 25 } },
                                        sorting: { sortModel: [{ field: 'severity', sort: 'asc' }] },
                                      }}
                                      disableRowSelectionOnClick
                                      sx={{
                                        border: 0,
                                        '& .MuiDataGrid-cell': { alignItems: 'flex-start', py: 0.75 },
                                      }}
                                    />
                                  </Box>
                                </>
                              ) : (
                                <Alert severity="success">
                                  No license policy violations. {totalPkgs} packages analyzed, {distinct} distinct licenses found.
                                </Alert>
                              )}
                            </>
                          );
                        })()}
                      </>
                    ) : (
                      <Alert severity="info">
                        License compliance data is not available for this scan. It is generated
                        automatically for new scans. Re-run the scan to populate this tab.
                      </Alert>
                    )}
                  </Box>
                )}
              </Box>
            </Paper>
          </Grid>
        )}
      </Grid>
    </Box>
  );
}

export default ScanResults;
