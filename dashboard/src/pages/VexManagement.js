import React, { useState, useEffect, useCallback } from 'react';
import {
  Box,
  Paper,
  Typography,
  Button,
  TextField,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Alert,
  CircularProgress,
  Tooltip,
  Tabs,
  Tab,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import EditIcon from '@mui/icons-material/Edit';
import DeleteIcon from '@mui/icons-material/Delete';
import UploadIcon from '@mui/icons-material/Upload';
import RefreshIcon from '@mui/icons-material/Refresh';
import {
  listVexStatements,
  createVexStatement,
  updateVexStatement,
  deleteVexStatement,
  importVexDocument,
} from '../api';
import PageHeader from '../components/PageHeader';

const STATUS_COLORS = {
  not_affected: 'success',
  affected: 'error',
  fixed: 'info',
  under_investigation: 'warning',
};

const STATUS_LABELS = {
  not_affected: 'Not Affected',
  affected: 'Affected',
  fixed: 'Fixed',
  under_investigation: 'Under Investigation',
};

const JUSTIFICATIONS = [
  { value: 'component_not_present', label: 'Component Not Present' },
  { value: 'vulnerable_code_not_present', label: 'Vulnerable Code Not Present' },
  { value: 'vulnerable_code_not_in_execute_path', label: 'Code Not in Execute Path' },
  { value: 'vulnerable_code_cannot_be_controlled_by_adversary', label: 'Cannot Be Controlled by Adversary' },
  { value: 'inline_mitigations_already_exist', label: 'Inline Mitigations Exist' },
];

function StatementDialog({ open, onClose, onSave, editData }) {
  const [form, setForm] = useState({
    cve_id: '',
    product: '',
    status: 'under_investigation',
    justification: '',
    impact_statement: '',
    action_statement: '',
  });

  useEffect(() => {
    if (editData) {
      setForm({
        cve_id: editData.cve_id || '',
        product: editData.product || '',
        status: editData.status || 'under_investigation',
        justification: editData.justification || '',
        impact_statement: editData.impact_statement || '',
        action_statement: editData.action_statement || '',
      });
    } else {
      setForm({
        cve_id: '',
        product: '',
        status: 'under_investigation',
        justification: '',
        impact_statement: '',
        action_statement: '',
      });
    }
  }, [editData, open]);

  const handleSubmit = () => {
    onSave(form, editData?.id);
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>{editData ? 'Edit VEX Statement' : 'Create VEX Statement'}</DialogTitle>
      <DialogContent>
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, mt: 1 }}>
          <TextField
            label="CVE ID"
            placeholder="CVE-2024-1234"
            value={form.cve_id}
            onChange={(e) => setForm({ ...form, cve_id: e.target.value })}
            disabled={!!editData}
            required
            size="small"
          />
          <TextField
            label="Product"
            placeholder="e.g. myregistry/myimage:latest"
            value={form.product}
            onChange={(e) => setForm({ ...form, product: e.target.value })}
            disabled={!!editData}
            required
            size="small"
          />
          <FormControl size="small" required>
            <InputLabel>Status</InputLabel>
            <Select
              value={form.status}
              onChange={(e) => setForm({ ...form, status: e.target.value })}
              label="Status"
            >
              <MenuItem value="not_affected">Not Affected</MenuItem>
              <MenuItem value="affected">Affected</MenuItem>
              <MenuItem value="fixed">Fixed</MenuItem>
              <MenuItem value="under_investigation">Under Investigation</MenuItem>
            </Select>
          </FormControl>
          {form.status === 'not_affected' && (
            <FormControl size="small">
              <InputLabel>Justification</InputLabel>
              <Select
                value={form.justification}
                onChange={(e) => setForm({ ...form, justification: e.target.value })}
                label="Justification"
              >
                <MenuItem value="">None</MenuItem>
                {JUSTIFICATIONS.map((j) => (
                  <MenuItem key={j.value} value={j.value}>{j.label}</MenuItem>
                ))}
              </Select>
            </FormControl>
          )}
          <TextField
            label="Impact Statement"
            placeholder="Describe the impact assessment..."
            value={form.impact_statement}
            onChange={(e) => setForm({ ...form, impact_statement: e.target.value })}
            multiline
            rows={2}
            size="small"
          />
          <TextField
            label="Action Statement"
            placeholder="Recommended action to take..."
            value={form.action_statement}
            onChange={(e) => setForm({ ...form, action_statement: e.target.value })}
            multiline
            rows={2}
            size="small"
          />
        </Box>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button
          variant="contained"
          onClick={handleSubmit}
          disabled={!form.cve_id || !form.product}
        >
          {editData ? 'Update' : 'Create'}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

function VexManagement() {
  const [statements, setStatements] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editData, setEditData] = useState(null);
  const [filterCve, setFilterCve] = useState('');
  const [filterStatus, setFilterStatus] = useState('');
  const [activeTab, setActiveTab] = useState(0);
  const [importJson, setImportJson] = useState('');

  const loadStatements = useCallback(async () => {
    setLoading(true);
    try {
      const params = {};
      if (filterCve) params.cve_id = filterCve;
      if (filterStatus) params.status = filterStatus;
      const response = await listVexStatements(params);
      setStatements(response.data.statements || []);
      setTotal(response.data.total || 0);
    } catch (err) {
      setError('Failed to load VEX statements');
    }
    setLoading(false);
  }, [filterCve, filterStatus]);

  useEffect(() => {
    loadStatements();
  }, [loadStatements]);

  const handleSave = async (form, editId) => {
    try {
      if (editId) {
        await updateVexStatement(editId, {
          status: form.status,
          justification: form.justification,
          impact_statement: form.impact_statement,
          action_statement: form.action_statement,
        });
        setSuccess('VEX statement updated');
      } else {
        await createVexStatement(form);
        setSuccess('VEX statement created');
      }
      setDialogOpen(false);
      setEditData(null);
      loadStatements();
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to save VEX statement');
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm('Delete this VEX statement?')) return;
    try {
      await deleteVexStatement(id);
      setSuccess('VEX statement deleted');
      loadStatements();
    } catch (err) {
      setError('Failed to delete VEX statement');
    }
  };

  const handleImport = async () => {
    try {
      const doc = JSON.parse(importJson);
      const response = await importVexDocument(doc);
      setSuccess(`Imported ${response.data.imported} of ${response.data.total} statements`);
      setImportJson('');
      setActiveTab(0);
      loadStatements();
    } catch (err) {
      if (err instanceof SyntaxError) {
        setError('Invalid JSON format');
      } else {
        setError(err.response?.data?.detail || 'Import failed');
      }
    }
  };

  return (
    <Box>
      <PageHeader
        title="VEX Management"
        description="Manage Vulnerability Exploitability eXchange (VEX) statements"
        actions={
          <>
            <Button
              variant="outlined"
              startIcon={<RefreshIcon />}
              onClick={loadStatements}
            >
              Refresh
            </Button>
            <Button
              variant="contained"
              startIcon={<AddIcon />}
              onClick={() => { setEditData(null); setDialogOpen(true); }}
            >
              New Statement
            </Button>
          </>
        }
      />

      {error && <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>{error}</Alert>}
      {success && <Alert severity="success" sx={{ mb: 2 }} onClose={() => setSuccess(null)}>{success}</Alert>}

      <Paper sx={{ mb: 3 }}>
        <Tabs value={activeTab} onChange={(e, v) => setActiveTab(v)}>
          <Tab label={`Statements (${total})`} />
          <Tab label="Import OpenVEX" icon={<UploadIcon />} iconPosition="start" />
        </Tabs>

        {activeTab === 0 && (
          <Box sx={{ p: 2 }}>
            {/* Filters */}
            <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
              <TextField
                label="Filter by CVE"
                placeholder="CVE-2024-..."
                value={filterCve}
                onChange={(e) => setFilterCve(e.target.value)}
                size="small"
                sx={{ width: 200 }}
              />
              <FormControl size="small" sx={{ width: 180 }}>
                <InputLabel>Status</InputLabel>
                <Select
                  value={filterStatus}
                  onChange={(e) => setFilterStatus(e.target.value)}
                  label="Status"
                >
                  <MenuItem value="">All</MenuItem>
                  <MenuItem value="not_affected">Not Affected</MenuItem>
                  <MenuItem value="affected">Affected</MenuItem>
                  <MenuItem value="fixed">Fixed</MenuItem>
                  <MenuItem value="under_investigation">Under Investigation</MenuItem>
                </Select>
              </FormControl>
            </Box>

            {loading ? (
              <Box sx={{ textAlign: 'center', py: 4 }}><CircularProgress /></Box>
            ) : statements.length === 0 ? (
              <Alert severity="info">No VEX statements found. Create one to get started.</Alert>
            ) : (
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>CVE ID</TableCell>
                      <TableCell>Product</TableCell>
                      <TableCell>Status</TableCell>
                      <TableCell>Justification</TableCell>
                      <TableCell>Updated</TableCell>
                      <TableCell align="right">Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {statements.map((stmt) => (
                      <TableRow key={stmt.id} hover>
                        <TableCell>
                          <Typography variant="body2" fontWeight={600} sx={{ fontFamily: 'monospace' }}>
                            {stmt.cve_id}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" noWrap sx={{ maxWidth: 200 }}>
                            {stmt.product}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={STATUS_LABELS[stmt.status] || stmt.status}
                            color={STATUS_COLORS[stmt.status] || 'default'}
                            size="small"
                          />
                        </TableCell>
                        <TableCell>
                          <Typography variant="caption" color="text.secondary">
                            {stmt.justification
                              ? JUSTIFICATIONS.find(j => j.value === stmt.justification)?.label || stmt.justification
                              : '-'}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="caption">
                            {new Date(stmt.updated_at).toLocaleDateString()}
                          </Typography>
                        </TableCell>
                        <TableCell align="right">
                          <Tooltip title="Edit">
                            <IconButton
                              size="small"
                              aria-label={`Edit VEX statement for ${stmt.cve_id}`}
                              onClick={() => { setEditData(stmt); setDialogOpen(true); }}
                            >
                              <EditIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Delete">
                            <IconButton
                              size="small"
                              color="error"
                              aria-label={`Delete VEX statement for ${stmt.cve_id}`}
                              onClick={() => handleDelete(stmt.id)}
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
          </Box>
        )}

        {activeTab === 1 && (
          <Box sx={{ p: 3 }}>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              Paste an OpenVEX format JSON document to import statements.
            </Typography>
            <TextField
              multiline
              rows={12}
              fullWidth
              placeholder='{"@context": "https://openvex.dev/ns/v0.2.0", "statements": [...]}'
              value={importJson}
              onChange={(e) => setImportJson(e.target.value)}
              sx={{ fontFamily: 'monospace', fontSize: '0.8rem', mb: 2 }}
            />
            <Button
              variant="contained"
              startIcon={<UploadIcon />}
              onClick={handleImport}
              disabled={!importJson.trim()}
            >
              Import Document
            </Button>
          </Box>
        )}
      </Paper>

      <StatementDialog
        open={dialogOpen}
        onClose={() => { setDialogOpen(false); setEditData(null); }}
        onSave={handleSave}
        editData={editData}
      />
    </Box>
  );
}

export default VexManagement;
