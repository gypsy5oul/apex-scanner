import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  Button,
  Alert,
  CircularProgress,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControlLabel,
  Switch,
  Grid,
  Card,
  CardContent,
  Tooltip,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Divider,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import EditIcon from '@mui/icons-material/Edit';
import DeleteIcon from '@mui/icons-material/Delete';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import PolicyIcon from '@mui/icons-material/Policy';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import CancelIcon from '@mui/icons-material/Cancel';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
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

const ruleFields = [
  { value: 'severity', label: 'Severity', type: 'select' },
  { value: 'epss_score', label: 'EPSS Score', type: 'number' },
  { value: 'in_kev', label: 'In KEV', type: 'boolean' },
  { value: 'cve_id', label: 'CVE ID', type: 'text' },
];

const ruleOperators = [
  { value: 'equals', label: 'Equals' },
  { value: 'not_equals', label: 'Not Equals' },
  { value: 'greater_than', label: 'Greater Than' },
  { value: 'less_than', label: 'Less Than' },
  { value: 'greater_or_equal', label: 'Greater or Equal' },
  { value: 'less_or_equal', label: 'Less or Equal' },
  { value: 'contains', label: 'Contains' },
];

const ruleActions = [
  { value: 'fail', label: 'Fail', color: 'error' },
  { value: 'warn', label: 'Warn', color: 'warning' },
  { value: 'pass', label: 'Pass', color: 'success' },
];

const severityValues = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

function Policies() {
  const { isAuthenticated } = useAuth();
  const [policies, setPolicies] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);

  // Dialog states
  const [openDialog, setOpenDialog] = useState(false);
  const [editingPolicy, setEditingPolicy] = useState(null);
  const [deleteConfirm, setDeleteConfirm] = useState(null);

  // Form states
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    enabled: true,
    fail_on_warn: false,
    rules: [],
  });

  // Test dialog
  const [testDialog, setTestDialog] = useState(false);
  const [testPolicyId, setTestPolicyId] = useState('');
  const [testScanId, setTestScanId] = useState('');
  const [testResult, setTestResult] = useState(null);
  const [testLoading, setTestLoading] = useState(false);

  useEffect(() => {
    fetchPolicies();
  }, []);

  const fetchPolicies = async () => {
    try {
      setLoading(true);
      const response = await apiV2.get('/policies');
      setPolicies(response.data.policies || []);
    } catch (err) {
      setError('Failed to load policies');
    } finally {
      setLoading(false);
    }
  };

  const handleOpenCreate = () => {
    setEditingPolicy(null);
    setFormData({
      name: '',
      description: '',
      enabled: true,
      fail_on_warn: false,
      rules: [
        {
          field: 'severity',
          operator: 'equals',
          value: 'CRITICAL',
          action: 'fail',
          description: 'Fail on critical vulnerabilities',
        },
      ],
    });
    setOpenDialog(true);
  };

  const handleOpenEdit = async (policy) => {
    try {
      const response = await apiV2.get(`/policies/${policy.id}`);
      setEditingPolicy(response.data);
      setFormData({
        name: response.data.name,
        description: response.data.description,
        enabled: response.data.enabled,
        fail_on_warn: response.data.fail_on_warn,
        rules: response.data.rules || [],
      });
      setOpenDialog(true);
    } catch (err) {
      setError('Failed to load policy details');
    }
  };

  const handleSave = async () => {
    try {
      if (editingPolicy) {
        await apiV2.put(`/policies/${editingPolicy.id}`, formData);
        setSuccess('Policy updated successfully');
      } else {
        await apiV2.post('/policies', formData);
        setSuccess('Policy created successfully');
      }
      setOpenDialog(false);
      fetchPolicies();
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to save policy');
    }
  };

  const handleDelete = async (policyId) => {
    try {
      await apiV2.delete(`/policies/${policyId}`);
      setSuccess('Policy deleted successfully');
      setDeleteConfirm(null);
      fetchPolicies();
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to delete policy');
    }
  };

  const handleToggleEnabled = async (policy) => {
    try {
      await apiV2.put(`/policies/${policy.id}`, {
        enabled: !policy.enabled,
      });
      fetchPolicies();
    } catch (err) {
      setError('Failed to update policy');
    }
  };

  const addRule = () => {
    setFormData({
      ...formData,
      rules: [
        ...formData.rules,
        {
          field: 'severity',
          operator: 'equals',
          value: 'HIGH',
          action: 'fail',
          description: '',
        },
      ],
    });
  };

  const updateRule = (index, field, value) => {
    const newRules = [...formData.rules];
    newRules[index] = { ...newRules[index], [field]: value };
    setFormData({ ...formData, rules: newRules });
  };

  const removeRule = (index) => {
    setFormData({
      ...formData,
      rules: formData.rules.filter((_, i) => i !== index),
    });
  };

  const handleTest = async () => {
    if (!testPolicyId || !testScanId) {
      setError('Please enter both Policy ID and Scan ID');
      return;
    }

    try {
      setTestLoading(true);
      const response = await apiV2.post('/policies/evaluate', {
        policy_id: testPolicyId,
        scan_id: testScanId,
      });
      setTestResult(response.data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to evaluate policy');
    } finally {
      setTestLoading(false);
    }
  };

  const copyPolicyJson = (policy) => {
    const json = JSON.stringify(policy, null, 2);
    navigator.clipboard.writeText(json);
    setSuccess('Policy JSON copied to clipboard');
  };

  if (!isAuthenticated) {
    return (
      <Box>
        <Alert severity="warning">
          Please login as admin to manage security policies
        </Alert>
      </Box>
    );
  }

  return (
    <Box>
      <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
        <PolicyIcon sx={{ fontSize: 32, mr: 1, color: 'primary.main' }} />
        <Typography variant="h4">Security Policies</Typography>
      </Box>

      <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
        Define security gates for CI/CD pipelines. Policies evaluate scan
        results and determine pass/fail status based on vulnerability severity,
        EPSS scores, and KEV status.
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {success && (
        <Alert severity="success" sx={{ mb: 2 }} onClose={() => setSuccess(null)}>
          {success}
        </Alert>
      )}

      {/* Actions */}
      <Box sx={{ mb: 3, display: 'flex', gap: 2 }}>
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          onClick={handleOpenCreate}
        >
          Create Policy
        </Button>
        <Button
          variant="outlined"
          startIcon={<PlayArrowIcon />}
          onClick={() => setTestDialog(true)}
        >
          Test Policy
        </Button>
      </Box>

      {/* Policies Table */}
      <Paper>
        {loading ? (
          <Box sx={{ p: 4, textAlign: 'center' }}>
            <CircularProgress />
          </Box>
        ) : policies.length === 0 ? (
          <Box sx={{ p: 4, textAlign: 'center' }}>
            <Typography color="text.secondary">No policies defined</Typography>
          </Box>
        ) : (
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Name</TableCell>
                  <TableCell>Description</TableCell>
                  <TableCell>Rules</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Fail on Warn</TableCell>
                  <TableCell>Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {policies.map((policy) => (
                  <TableRow key={policy.id} hover>
                    <TableCell>
                      <Typography fontWeight="medium">{policy.name}</Typography>
                      <Typography variant="caption" color="text.secondary">
                        ID: {policy.id.slice(0, 8)}...
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography
                        variant="body2"
                        sx={{
                          maxWidth: 300,
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                        }}
                      >
                        {policy.description || '-'}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={`${policy.rules_count} rules`}
                        size="small"
                        variant="outlined"
                      />
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={policy.enabled ? 'Enabled' : 'Disabled'}
                        color={policy.enabled ? 'success' : 'default'}
                        size="small"
                        onClick={() => handleToggleEnabled(policy)}
                        sx={{ cursor: 'pointer' }}
                      />
                    </TableCell>
                    <TableCell>
                      {policy.fail_on_warn ? (
                        <CheckCircleIcon color="warning" fontSize="small" />
                      ) : (
                        <CancelIcon color="disabled" fontSize="small" />
                      )}
                    </TableCell>
                    <TableCell>
                      <Tooltip title="Edit">
                        <IconButton
                          size="small"
                          onClick={() => handleOpenEdit(policy)}
                        >
                          <EditIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Copy JSON">
                        <IconButton
                          size="small"
                          onClick={() => copyPolicyJson(policy)}
                        >
                          <ContentCopyIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Delete">
                        <IconButton
                          size="small"
                          color="error"
                          onClick={() => setDeleteConfirm(policy)}
                        >
                          <DeleteIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </Paper>

      {/* API Usage Example */}
      <Paper sx={{ mt: 3, p: 3 }}>
        <Typography variant="h6" gutterBottom>
          CI/CD Integration
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Use the policy check endpoint in your CI/CD pipeline:
        </Typography>
        <Box
          sx={{
            bgcolor: 'grey.900',
            color: 'grey.100',
            p: 2,
            borderRadius: 1,
            fontFamily: 'monospace',
            fontSize: '0.875rem',
            overflow: 'auto',
          }}
        >
          <pre style={{ margin: 0 }}>
{`# Check scan against all enabled policies
curl -X GET "http://your-server/api/v2/scan/{scan_id}/policy-check"

# Response:
{
  "scan_id": "...",
  "overall_passed": false,
  "policies_evaluated": 2,
  "results": [
    {"policy_name": "Production", "passed": false, "status": "failed"},
    {"policy_name": "Development", "passed": true, "status": "passed"}
  ]
}

# In GitLab CI / GitHub Actions:
if [ "$(curl -s .../policy-check | jq '.overall_passed')" != "true" ]; then
  echo "Security gate failed!"
  exit 1
fi`}
          </pre>
        </Box>
      </Paper>

      {/* Create/Edit Dialog */}
      <Dialog
        open={openDialog}
        onClose={() => setOpenDialog(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>
          {editingPolicy ? 'Edit Policy' : 'Create Policy'}
        </DialogTitle>
        <DialogContent>
          <Grid container spacing={2} sx={{ mt: 1 }}>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Policy Name"
                value={formData.name}
                onChange={(e) =>
                  setFormData({ ...formData, name: e.target.value })
                }
              />
            </Grid>
            <Grid item xs={12}>
              <TextField
                fullWidth
                multiline
                rows={2}
                label="Description"
                value={formData.description}
                onChange={(e) =>
                  setFormData({ ...formData, description: e.target.value })
                }
              />
            </Grid>
            <Grid item xs={6}>
              <FormControlLabel
                control={
                  <Switch
                    checked={formData.enabled}
                    onChange={(e) =>
                      setFormData({ ...formData, enabled: e.target.checked })
                    }
                  />
                }
                label="Enabled"
              />
            </Grid>
            <Grid item xs={6}>
              <FormControlLabel
                control={
                  <Switch
                    checked={formData.fail_on_warn}
                    onChange={(e) =>
                      setFormData({ ...formData, fail_on_warn: e.target.checked })
                    }
                  />
                }
                label="Fail on Warnings"
              />
            </Grid>
          </Grid>

          <Divider sx={{ my: 3 }} />

          <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 2 }}>
            <Typography variant="h6">Rules</Typography>
            <Button size="small" startIcon={<AddIcon />} onClick={addRule}>
              Add Rule
            </Button>
          </Box>

          {formData.rules.map((rule, index) => (
            <Accordion key={index} defaultExpanded>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <Chip
                    label={rule.action}
                    size="small"
                    color={
                      ruleActions.find((a) => a.value === rule.action)?.color ||
                      'default'
                    }
                  />
                  <Typography>
                    {rule.field} {rule.operator} {String(rule.value)}
                  </Typography>
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={3}>
                    <FormControl fullWidth size="small">
                      <InputLabel>Field</InputLabel>
                      <Select
                        value={rule.field}
                        label="Field"
                        onChange={(e) =>
                          updateRule(index, 'field', e.target.value)
                        }
                      >
                        {ruleFields.map((f) => (
                          <MenuItem key={f.value} value={f.value}>
                            {f.label}
                          </MenuItem>
                        ))}
                      </Select>
                    </FormControl>
                  </Grid>
                  <Grid item xs={12} md={3}>
                    <FormControl fullWidth size="small">
                      <InputLabel>Operator</InputLabel>
                      <Select
                        value={rule.operator}
                        label="Operator"
                        onChange={(e) =>
                          updateRule(index, 'operator', e.target.value)
                        }
                      >
                        {ruleOperators.map((o) => (
                          <MenuItem key={o.value} value={o.value}>
                            {o.label}
                          </MenuItem>
                        ))}
                      </Select>
                    </FormControl>
                  </Grid>
                  <Grid item xs={12} md={3}>
                    {rule.field === 'severity' ? (
                      <FormControl fullWidth size="small">
                        <InputLabel>Value</InputLabel>
                        <Select
                          value={rule.value}
                          label="Value"
                          onChange={(e) =>
                            updateRule(index, 'value', e.target.value)
                          }
                        >
                          {severityValues.map((v) => (
                            <MenuItem key={v} value={v}>
                              {v}
                            </MenuItem>
                          ))}
                        </Select>
                      </FormControl>
                    ) : rule.field === 'in_kev' ? (
                      <FormControl fullWidth size="small">
                        <InputLabel>Value</InputLabel>
                        <Select
                          value={rule.value}
                          label="Value"
                          onChange={(e) =>
                            updateRule(index, 'value', e.target.value === 'true')
                          }
                        >
                          <MenuItem value="true">True</MenuItem>
                          <MenuItem value="false">False</MenuItem>
                        </Select>
                      </FormControl>
                    ) : (
                      <TextField
                        fullWidth
                        size="small"
                        label="Value"
                        type={rule.field === 'epss_score' ? 'number' : 'text'}
                        value={rule.value}
                        onChange={(e) =>
                          updateRule(
                            index,
                            'value',
                            rule.field === 'epss_score'
                              ? parseFloat(e.target.value)
                              : e.target.value
                          )
                        }
                        inputProps={
                          rule.field === 'epss_score'
                            ? { min: 0, max: 1, step: 0.1 }
                            : {}
                        }
                      />
                    )}
                  </Grid>
                  <Grid item xs={12} md={3}>
                    <FormControl fullWidth size="small">
                      <InputLabel>Action</InputLabel>
                      <Select
                        value={rule.action}
                        label="Action"
                        onChange={(e) =>
                          updateRule(index, 'action', e.target.value)
                        }
                      >
                        {ruleActions.map((a) => (
                          <MenuItem key={a.value} value={a.value}>
                            {a.label}
                          </MenuItem>
                        ))}
                      </Select>
                    </FormControl>
                  </Grid>
                  <Grid item xs={12}>
                    <TextField
                      fullWidth
                      size="small"
                      label="Description"
                      value={rule.description || ''}
                      onChange={(e) =>
                        updateRule(index, 'description', e.target.value)
                      }
                    />
                  </Grid>
                  <Grid item xs={12}>
                    <Button
                      size="small"
                      color="error"
                      onClick={() => removeRule(index)}
                    >
                      Remove Rule
                    </Button>
                  </Grid>
                </Grid>
              </AccordionDetails>
            </Accordion>
          ))}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenDialog(false)}>Cancel</Button>
          <Button
            variant="contained"
            onClick={handleSave}
            disabled={!formData.name || formData.rules.length === 0}
          >
            {editingPolicy ? 'Update' : 'Create'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <Dialog open={!!deleteConfirm} onClose={() => setDeleteConfirm(null)}>
        <DialogTitle>Delete Policy</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to delete "{deleteConfirm?.name}"? This action
            cannot be undone.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteConfirm(null)}>Cancel</Button>
          <Button
            variant="contained"
            color="error"
            onClick={() => handleDelete(deleteConfirm?.id)}
          >
            Delete
          </Button>
        </DialogActions>
      </Dialog>

      {/* Test Policy Dialog */}
      <Dialog
        open={testDialog}
        onClose={() => {
          setTestDialog(false);
          setTestResult(null);
        }}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>Test Policy Against Scan</DialogTitle>
        <DialogContent>
          <Grid container spacing={2} sx={{ mt: 1 }}>
            <Grid item xs={12} md={6}>
              <FormControl fullWidth>
                <InputLabel>Policy</InputLabel>
                <Select
                  value={testPolicyId}
                  label="Policy"
                  onChange={(e) => setTestPolicyId(e.target.value)}
                >
                  {policies.map((p) => (
                    <MenuItem key={p.id} value={p.id}>
                      {p.name}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label="Scan ID"
                value={testScanId}
                onChange={(e) => setTestScanId(e.target.value)}
                placeholder="Enter scan ID to test against"
              />
            </Grid>
            <Grid item xs={12}>
              <Button
                variant="contained"
                onClick={handleTest}
                disabled={testLoading || !testPolicyId || !testScanId}
                startIcon={
                  testLoading ? <CircularProgress size={20} /> : <PlayArrowIcon />
                }
              >
                {testLoading ? 'Evaluating...' : 'Evaluate'}
              </Button>
            </Grid>
          </Grid>

          {testResult && (
            <Box sx={{ mt: 3 }}>
              <Alert
                severity={testResult.passed ? 'success' : 'error'}
                icon={
                  testResult.passed ? <CheckCircleIcon /> : <CancelIcon />
                }
              >
                <Typography variant="subtitle1">
                  Policy: {testResult.policy_name} - {testResult.status.toUpperCase()}
                </Typography>
              </Alert>

              <Box sx={{ mt: 2 }}>
                <Typography variant="subtitle2" gutterBottom>
                  Summary
                </Typography>
                <Grid container spacing={1}>
                  <Grid item>
                    <Chip
                      label={`Fail: ${testResult.summary?.fail || 0}`}
                      color="error"
                      size="small"
                    />
                  </Grid>
                  <Grid item>
                    <Chip
                      label={`Warn: ${testResult.summary?.warn || 0}`}
                      color="warning"
                      size="small"
                    />
                  </Grid>
                  <Grid item>
                    <Chip
                      label={`Pass: ${testResult.summary?.pass || 0}`}
                      color="success"
                      size="small"
                    />
                  </Grid>
                </Grid>
              </Box>

              {testResult.violations?.length > 0 && (
                <Box sx={{ mt: 2 }}>
                  <Typography variant="subtitle2" gutterBottom>
                    Violations ({testResult.violations.length})
                  </Typography>
                  {testResult.violations.map((v, i) => (
                    <Card key={i} sx={{ mb: 1 }}>
                      <CardContent sx={{ py: 1 }}>
                        <Box
                          sx={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: 1,
                          }}
                        >
                          <Chip
                            label={v.action}
                            size="small"
                            color={v.action === 'fail' ? 'error' : 'warning'}
                          />
                          <Typography variant="body2">{v.message}</Typography>
                          <Chip
                            label={`${v.matched_count} matches`}
                            size="small"
                            variant="outlined"
                          />
                        </Box>
                      </CardContent>
                    </Card>
                  ))}
                </Box>
              )}
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button
            onClick={() => {
              setTestDialog(false);
              setTestResult(null);
            }}
          >
            Close
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

export default Policies;
