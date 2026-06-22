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
import PageHeader from '../components/PageHeader';
import { TableSkeleton } from '../components/LoadingSkeletons';
import { useToast, useConfirm } from '../components/Feedback';
import AddIcon from '@mui/icons-material/Add';
import EditIcon from '@mui/icons-material/Edit';
import DeleteIcon from '@mui/icons-material/Delete';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import CancelIcon from '@mui/icons-material/Cancel';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import { useAuth } from '../context/AuthContext';
import { apiV2 } from '../api';

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
  const toast = useToast();
  const confirm = useConfirm();
  const [policies, setPolicies] = useState([]);
  const [loading, setLoading] = useState(true);
  const [dialogError, setDialogError] = useState(null);
  const [saving, setSaving] = useState(false);
  const [togglingId, setTogglingId] = useState(null);

  // Dialog states
  const [openDialog, setOpenDialog] = useState(false);
  const [editingPolicy, setEditingPolicy] = useState(null);

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
      toast('Failed to load policies: ' + (err.response?.data?.detail || err.message), 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleOpenCreate = () => {
    setEditingPolicy(null);
    setDialogError(null);
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
      setDialogError(null);
      setFormData({
        name: response.data.name,
        description: response.data.description,
        enabled: response.data.enabled,
        fail_on_warn: response.data.fail_on_warn,
        rules: response.data.rules || [],
      });
      setOpenDialog(true);
    } catch (err) {
      toast('Failed to load policy details: ' + (err.response?.data?.detail || err.message), 'error');
    }
  };

  const handleSave = async () => {
    setSaving(true);
    setDialogError(null);
    try {
      if (editingPolicy) {
        await apiV2.put(`/policies/${editingPolicy.id}`, formData);
        toast('Policy updated successfully', 'success');
      } else {
        await apiV2.post('/policies', formData);
        toast('Policy created successfully', 'success');
      }
      setOpenDialog(false);
      fetchPolicies();
    } catch (err) {
      setDialogError(err.response?.data?.detail || 'Failed to save policy');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (policy) => {
    if (
      !(await confirm({
        title: 'Delete policy?',
        message: `Delete "${policy.name}"? This action cannot be undone.`,
        confirmLabel: 'Delete',
        destructive: true,
      }))
    )
      return;
    try {
      await apiV2.delete(`/policies/${policy.id}`);
      toast('Policy deleted successfully', 'success');
      fetchPolicies();
    } catch (err) {
      toast('Delete policy failed: ' + (err.response?.data?.detail || err.message), 'error');
    }
  };

  // Send the FULL policy object with `enabled` flipped so a non-merge backend
  // can't wipe the policy's other fields. Fetch the current policy first.
  const handleToggleEnabled = async (policy) => {
    setTogglingId(policy.id);
    try {
      const { data: full } = await apiV2.get(`/policies/${policy.id}`);
      await apiV2.put(`/policies/${policy.id}`, {
        name: full.name,
        description: full.description,
        enabled: !full.enabled,
        fail_on_warn: full.fail_on_warn,
        rules: full.rules || [],
      });
      toast(`Policy ${!policy.enabled ? 'enabled' : 'disabled'}`, 'success');
      fetchPolicies();
    } catch (err) {
      toast('Update policy failed: ' + (err.response?.data?.detail || err.message), 'error');
    } finally {
      setTogglingId(null);
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
      toast('Please enter both Policy ID and Scan ID', 'error');
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
      toast('Evaluate policy failed: ' + (err.response?.data?.detail || err.message), 'error');
    } finally {
      setTestLoading(false);
    }
  };

  const copyPolicyJson = (policy) => {
    const json = JSON.stringify(policy, null, 2);
    navigator.clipboard.writeText(json);
    toast('Policy JSON copied to clipboard', 'success');
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
      <PageHeader
        title="Security Policies"
        description="Define CI/CD security gates that pass or fail scans on severity, EPSS and KEV"
      />

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
          <TableSkeleton rows={5} cols={6} />
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
                      <FormControlLabel
                        sx={{ m: 0 }}
                        control={
                          <Switch
                            size="small"
                            checked={!!policy.enabled}
                            disabled={togglingId === policy.id}
                            onChange={() => handleToggleEnabled(policy)}
                            inputProps={{
                              'aria-label': `${policy.enabled ? 'Disable' : 'Enable'} policy ${policy.name}`,
                            }}
                          />
                        }
                        label={
                          <Typography variant="body2">
                            {policy.enabled ? 'Enabled' : 'Disabled'}
                          </Typography>
                        }
                      />
                    </TableCell>
                    <TableCell>
                      {policy.fail_on_warn ? (
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                          <CheckCircleIcon color="warning" fontSize="small" />
                          <Typography variant="body2">Yes</Typography>
                        </Box>
                      ) : (
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                          <CancelIcon color="disabled" fontSize="small" />
                          <Typography variant="body2" color="text.secondary">No</Typography>
                        </Box>
                      )}
                    </TableCell>
                    <TableCell>
                      <Tooltip title="Edit">
                        <IconButton
                          size="small"
                          aria-label={`Edit policy ${policy.name}`}
                          onClick={() => handleOpenEdit(policy)}
                        >
                          <EditIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Copy JSON">
                        <IconButton
                          size="small"
                          aria-label={`Copy JSON for policy ${policy.name}`}
                          onClick={() => copyPolicyJson(policy)}
                        >
                          <ContentCopyIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Delete">
                        <IconButton
                          size="small"
                          color="error"
                          aria-label={`Delete policy ${policy.name}`}
                          onClick={() => handleDelete(policy)}
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
curl -X GET "https://apexscanner.6dcorp.internal/api/v2/scan/{scan_id}/policy-check"

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
          {dialogError && (
            <Alert severity="error" sx={{ mt: 1, mb: 1 }} onClose={() => setDialogError(null)}>
              {dialogError}
            </Alert>
          )}
          <Grid container spacing={2} sx={{ mt: 1 }}>
            <Grid item xs={12}>
              <TextField
                fullWidth
                required
                label="Policy Name"
                value={formData.name}
                onChange={(e) =>
                  setFormData({ ...formData, name: e.target.value })
                }
                error={!formData.name.trim()}
                helperText={!formData.name.trim() ? 'Policy name is required' : ' '}
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
          <Button onClick={() => setOpenDialog(false)} disabled={saving}>Cancel</Button>
          <Button
            variant="contained"
            onClick={handleSave}
            disabled={saving || !formData.name.trim() || formData.rules.length === 0}
            startIcon={saving ? <CircularProgress size={20} /> : null}
          >
            {saving ? 'Saving…' : editingPolicy ? 'Update' : 'Create'}
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
