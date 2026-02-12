import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  TextField,
  Button,
  Alert,
  CircularProgress,
  Tabs,
  Tab,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  IconButton,
  Tooltip,
  Card,
  CardContent,
  Grid,
  Link,
  Divider,
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import SecurityIcon from '@mui/icons-material/Security';
import DescriptionIcon from '@mui/icons-material/Description';
import GitHubIcon from '@mui/icons-material/GitHub';
import UploadFileIcon from '@mui/icons-material/UploadFile';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import CancelIcon from '@mui/icons-material/Cancel';
import WarningIcon from '@mui/icons-material/Warning';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import RefreshIcon from '@mui/icons-material/Refresh';
import { useAuth } from '../context/AuthContext';
import axios from 'axios';

// Create apiV2 instance for /api/v2 endpoints
const getApiUrl = () => {
  const host = window.location.hostname;
  return `http://${host}:7070`;
};

const apiV2 = axios.create({
  baseURL: `${getApiUrl()}/api/v2`,
  headers: { 'Content-Type': 'application/json' },
});

// Add auth token if available
apiV2.interceptors.request.use((config) => {
  const token = localStorage.getItem('auth_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

const severityColors = {
  CRITICAL: 'error',
  HIGH: 'error',
  MEDIUM: 'warning',
  LOW: 'info',
  UNKNOWN: 'default',
};

const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4 };

function TabPanel({ children, value, index, ...other }) {
  return (
    <div hidden={value !== index} {...other}>
      {value === index && <Box sx={{ pt: 3 }}>{children}</Box>}
    </div>
  );
}

function IacScan() {
  const { isAuthenticated } = useAuth();
  const [tabValue, setTabValue] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);

  // Content scan state
  const [fileContent, setFileContent] = useState('');
  const [filename, setFilename] = useState('Dockerfile');

  // Repo scan state
  const [repoUrl, setRepoUrl] = useState('');
  const [branch, setBranch] = useState('main');
  const [repoToken, setRepoToken] = useState('');
  const [repoPaths, setRepoPaths] = useState('');

  // Policy state
  const [policies, setPolicies] = useState([]);
  const [selectedPolicy, setSelectedPolicy] = useState('');

  // Load policies
  useEffect(() => {
    const fetchPolicies = async () => {
      try {
        const response = await apiV2.get('/policies');
        setPolicies(response.data.policies || []);
      } catch (err) {
        console.error('Failed to load policies:', err);
      }
    };
    fetchPolicies();
  }, []);

  const handleScanContent = async () => {
    if (!fileContent.trim()) {
      setError('Please enter file content to scan');
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const endpoint = selectedPolicy
        ? `/iac/scan/content/with-policy?policy_id=${selectedPolicy}`
        : '/iac/scan/content';

      const response = await apiV2.post(endpoint, {
        content: fileContent,
        filename: filename,
      });

      setResult(response.data);
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleScanRepo = async () => {
    if (!repoUrl.trim()) {
      setError('Please enter a repository URL');
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await apiV2.post('/iac/scan/repo', {
        repo_url: repoUrl,
        branch: branch,
        token: repoToken || undefined,
        paths: repoPaths ? repoPaths.split(',').map((p) => p.trim()) : undefined,
      });

      setResult(response.data);
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = (event) => {
    const file = event.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (e) => {
        setFileContent(e.target.result);
        setFilename(file.name);
      };
      reader.readAsText(file);
    }
  };

  const loadExample = (type) => {
    const examples = {
      dockerfile: `FROM ubuntu:latest

RUN apt-get update && apt-get install -y nginx

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]`,
      kubernetes: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:latest
        ports:
        - containerPort: 80
        securityContext:
          privileged: true`,
    };

    setFileContent(examples[type] || '');
    setFilename(type === 'dockerfile' ? 'Dockerfile' : 'deployment.yaml');
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
  };

  const sortedFindings = result?.findings
    ? [...result.findings].sort(
        (a, b) =>
          (severityOrder[a.severity] || 99) - (severityOrder[b.severity] || 99)
      )
    : [];

  return (
    <Box>
      <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
        <SecurityIcon sx={{ fontSize: 32, mr: 1, color: 'primary.main' }} />
        <Typography variant="h4">IaC Security Scan</Typography>
      </Box>

      <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
        Scan Infrastructure as Code files for security misconfigurations.
        Supports Dockerfile, Kubernetes manifests, Terraform, Helm charts, and
        more.
      </Typography>

      <Paper sx={{ mb: 3 }}>
        <Tabs
          value={tabValue}
          onChange={(e, v) => setTabValue(v)}
          sx={{ borderBottom: 1, borderColor: 'divider' }}
        >
          <Tab
            icon={<DescriptionIcon />}
            label="Paste Content"
            iconPosition="start"
          />
          <Tab
            icon={<GitHubIcon />}
            label="Git Repository"
            iconPosition="start"
            disabled={!isAuthenticated}
          />
        </Tabs>

        <Box sx={{ p: 3 }}>
          {error && (
            <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
              {error}
            </Alert>
          )}

          {/* Content Scan Tab */}
          <TabPanel value={tabValue} index={0}>
            <Box sx={{ mb: 2 }}>
              <Typography variant="subtitle2" gutterBottom>
                Quick Examples:
              </Typography>
              <Button
                size="small"
                variant="outlined"
                onClick={() => loadExample('dockerfile')}
                sx={{ mr: 1 }}
              >
                Dockerfile
              </Button>
              <Button
                size="small"
                variant="outlined"
                onClick={() => loadExample('kubernetes')}
                sx={{ mr: 1 }}
              >
                Kubernetes
              </Button>
              <input
                type="file"
                id="file-upload"
                style={{ display: 'none' }}
                onChange={handleFileUpload}
                accept=".yaml,.yml,.json,.tf,.dockerfile,Dockerfile"
              />
              <label htmlFor="file-upload">
                <Button
                  size="small"
                  variant="outlined"
                  component="span"
                  startIcon={<UploadFileIcon />}
                >
                  Upload File
                </Button>
              </label>
            </Box>

            <Grid container spacing={2} sx={{ mb: 2 }}>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Filename"
                  value={filename}
                  onChange={(e) => setFilename(e.target.value)}
                  helperText="e.g., Dockerfile, deployment.yaml, main.tf"
                  size="small"
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <FormControl fullWidth size="small">
                  <InputLabel>Policy (Optional)</InputLabel>
                  <Select
                    value={selectedPolicy}
                    onChange={(e) => setSelectedPolicy(e.target.value)}
                    label="Policy (Optional)"
                  >
                    <MenuItem value="">
                      <em>No Policy</em>
                    </MenuItem>
                    {policies.map((p) => (
                      <MenuItem key={p.id} value={p.id}>
                        {p.name}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>
            </Grid>

            <TextField
              fullWidth
              multiline
              rows={15}
              label="File Content"
              placeholder="Paste your Dockerfile, Kubernetes YAML, Terraform, etc."
              value={fileContent}
              onChange={(e) => setFileContent(e.target.value)}
              sx={{ mb: 2, fontFamily: 'monospace' }}
              InputProps={{
                sx: { fontFamily: 'monospace', fontSize: '0.875rem' },
              }}
            />

            <Button
              variant="contained"
              size="large"
              onClick={handleScanContent}
              disabled={loading || !fileContent.trim()}
              startIcon={
                loading ? <CircularProgress size={20} /> : <SecurityIcon />
              }
            >
              {loading ? 'Scanning...' : 'Scan Content'}
            </Button>
          </TabPanel>

          {/* Git Repository Tab */}
          <TabPanel value={tabValue} index={1}>
            {!isAuthenticated && (
              <Alert severity="warning" sx={{ mb: 2 }}>
                Please login as admin to scan Git repositories
              </Alert>
            )}

            <Grid container spacing={2} sx={{ mb: 2 }}>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Repository URL"
                  placeholder="https://github.com/owner/repo.git"
                  value={repoUrl}
                  onChange={(e) => setRepoUrl(e.target.value)}
                  helperText="Git repository URL (GitHub, GitLab, etc.)"
                />
              </Grid>
              <Grid item xs={12} md={4}>
                <TextField
                  fullWidth
                  label="Branch"
                  value={branch}
                  onChange={(e) => setBranch(e.target.value)}
                />
              </Grid>
              <Grid item xs={12} md={4}>
                <TextField
                  fullWidth
                  label="Access Token (Optional)"
                  type="password"
                  value={repoToken}
                  onChange={(e) => setRepoToken(e.target.value)}
                  helperText="For private repositories"
                />
              </Grid>
              <Grid item xs={12} md={4}>
                <TextField
                  fullWidth
                  label="Paths (Optional)"
                  value={repoPaths}
                  onChange={(e) => setRepoPaths(e.target.value)}
                  helperText="Comma-separated: kubernetes/, Dockerfile"
                />
              </Grid>
            </Grid>

            <Button
              variant="contained"
              size="large"
              onClick={handleScanRepo}
              disabled={loading || !repoUrl.trim() || !isAuthenticated}
              startIcon={
                loading ? <CircularProgress size={20} /> : <GitHubIcon />
              }
            >
              {loading ? 'Scanning...' : 'Scan Repository'}
            </Button>
          </TabPanel>
        </Box>
      </Paper>

      {/* Results Section */}
      {result && (
        <Paper sx={{ p: 3 }}>
          <Box
            sx={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              mb: 3,
            }}
          >
            <Typography variant="h5">Scan Results</Typography>
            <Chip
              label={result.status}
              color={result.status === 'completed' ? 'success' : 'error'}
            />
          </Box>

          {/* Summary Cards */}
          <Grid container spacing={2} sx={{ mb: 3 }}>
            <Grid item xs={6} md={3}>
              <Card
                sx={{
                  bgcolor: 'error.dark',
                  color: 'white',
                }}
              >
                <CardContent sx={{ textAlign: 'center', py: 2 }}>
                  <Typography variant="h3">{result.summary?.critical || 0}</Typography>
                  <Typography variant="body2">Critical</Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={6} md={3}>
              <Card
                sx={{
                  bgcolor: 'error.main',
                  color: 'white',
                }}
              >
                <CardContent sx={{ textAlign: 'center', py: 2 }}>
                  <Typography variant="h3">{result.summary?.high || 0}</Typography>
                  <Typography variant="body2">High</Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={6} md={3}>
              <Card
                sx={{
                  bgcolor: 'warning.main',
                  color: 'white',
                }}
              >
                <CardContent sx={{ textAlign: 'center', py: 2 }}>
                  <Typography variant="h3">{result.summary?.medium || 0}</Typography>
                  <Typography variant="body2">Medium</Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={6} md={3}>
              <Card
                sx={{
                  bgcolor: 'info.main',
                  color: 'white',
                }}
              >
                <CardContent sx={{ textAlign: 'center', py: 2 }}>
                  <Typography variant="h3">{result.summary?.low || 0}</Typography>
                  <Typography variant="body2">Low</Typography>
                </CardContent>
              </Card>
            </Grid>
          </Grid>

          {/* Policy Result */}
          {result.policy_result && (
            <Alert
              severity={result.policy_result.passed ? 'success' : 'error'}
              sx={{ mb: 3 }}
              icon={
                result.policy_result.passed ? (
                  <CheckCircleIcon />
                ) : (
                  <CancelIcon />
                )
              }
            >
              <Typography variant="subtitle1">
                Policy: {result.policy_result.policy_name}
              </Typography>
              <Typography variant="body2">
                Status: {result.policy_result.status.toUpperCase()} |
                Violations: {result.policy_result.violations?.length || 0}
              </Typography>
            </Alert>
          )}

          {/* Findings Table */}
          {sortedFindings.length > 0 ? (
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Severity</TableCell>
                    <TableCell>ID</TableCell>
                    <TableCell>Title</TableCell>
                    <TableCell>File</TableCell>
                    <TableCell>Line</TableCell>
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {sortedFindings.map((finding, index) => (
                    <React.Fragment key={index}>
                      <TableRow
                        sx={{
                          '&:hover': { bgcolor: 'action.hover' },
                          cursor: 'pointer',
                        }}
                      >
                        <TableCell>
                          <Chip
                            label={finding.severity}
                            color={severityColors[finding.severity] || 'default'}
                            size="small"
                          />
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                            {finding.id}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" fontWeight="medium">
                            {finding.title}
                          </Typography>
                          <Typography
                            variant="caption"
                            color="text.secondary"
                            sx={{
                              display: 'block',
                              maxWidth: 400,
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                            }}
                          >
                            {finding.message}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                            {finding.file}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          {finding.start_line > 0 && (
                            <Chip
                              label={`L${finding.start_line}`}
                              size="small"
                              variant="outlined"
                            />
                          )}
                        </TableCell>
                        <TableCell>
                          {finding.primary_url && (
                            <Tooltip title="View Details">
                              <IconButton
                                size="small"
                                href={finding.primary_url}
                                target="_blank"
                              >
                                <Link fontSize="small" />
                              </IconButton>
                            </Tooltip>
                          )}
                        </TableCell>
                      </TableRow>
                      <TableRow>
                        <TableCell colSpan={6} sx={{ py: 0 }}>
                          <Accordion elevation={0}>
                            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                              <Typography variant="body2" color="text.secondary">
                                View Details & Remediation
                              </Typography>
                            </AccordionSummary>
                            <AccordionDetails>
                              <Grid container spacing={2}>
                                <Grid item xs={12} md={6}>
                                  <Typography
                                    variant="subtitle2"
                                    color="text.secondary"
                                  >
                                    Description
                                  </Typography>
                                  <Typography variant="body2" sx={{ mb: 2 }}>
                                    {finding.description}
                                  </Typography>

                                  <Typography
                                    variant="subtitle2"
                                    color="text.secondary"
                                  >
                                    Resolution
                                  </Typography>
                                  <Typography variant="body2">
                                    {finding.resolution}
                                  </Typography>
                                </Grid>
                                <Grid item xs={12} md={6}>
                                  {finding.code_snippet && (
                                    <>
                                      <Typography
                                        variant="subtitle2"
                                        color="text.secondary"
                                      >
                                        Code
                                      </Typography>
                                      <Box
                                        sx={{
                                          bgcolor: 'grey.900',
                                          color: 'grey.100',
                                          p: 1,
                                          borderRadius: 1,
                                          fontFamily: 'monospace',
                                          fontSize: '0.75rem',
                                          overflow: 'auto',
                                          position: 'relative',
                                        }}
                                      >
                                        <IconButton
                                          size="small"
                                          sx={{
                                            position: 'absolute',
                                            top: 4,
                                            right: 4,
                                            color: 'grey.400',
                                          }}
                                          onClick={() =>
                                            copyToClipboard(finding.code_snippet)
                                          }
                                        >
                                          <ContentCopyIcon fontSize="small" />
                                        </IconButton>
                                        <pre style={{ margin: 0 }}>
                                          {finding.code_snippet}
                                        </pre>
                                      </Box>
                                    </>
                                  )}
                                </Grid>
                              </Grid>
                            </AccordionDetails>
                          </Accordion>
                        </TableCell>
                      </TableRow>
                    </React.Fragment>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          ) : (
            <Alert severity="success" icon={<CheckCircleIcon />}>
              No misconfigurations found! Your IaC files follow security best
              practices.
            </Alert>
          )}

          {/* Scan Metadata */}
          <Divider sx={{ my: 3 }} />
          <Typography variant="body2" color="text.secondary">
            Scan ID: {result.scan_id} | Scanned at: {result.scanned_at} | Files
            scanned: {result.files_scanned}
          </Typography>
        </Paper>
      )}
    </Box>
  );
}

export default IacScan;
