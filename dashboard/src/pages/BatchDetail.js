import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Box,
  Paper,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  IconButton,
  Tooltip,
  Button,
  LinearProgress,
  Stack,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Link,
} from '@mui/material';
import RefreshIcon from '@mui/icons-material/Refresh';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import DescriptionIcon from '@mui/icons-material/Description';
import ReplayIcon from '@mui/icons-material/Replay';
import DownloadIcon from '@mui/icons-material/Download';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import CancelIcon from '@mui/icons-material/Cancel';
import PageHeader from '../components/PageHeader';
import SeverityChip from '../components/SeverityChip';
import { TableSkeleton } from '../components/LoadingSkeletons';
import { useToast } from '../components/Feedback';
import { getBatchDetail, getBatchPolicyCheck, startBatchScan, apiV2 } from '../api';
import { MONO_FONT, getSeverity } from '../theme/tokens';

const STATUS = {
  completed: { label: 'Completed', color: 'success' },
  failed: { label: 'Failed', color: 'error' },
  in_progress: { label: 'Running', color: 'info' },
};
const TERMINAL = new Set(['completed', 'failed']);

function StatusChip({ status }) {
  const st = STATUS[status] || { label: status || 'unknown', color: 'default' };
  return <Chip size="small" variant="outlined" label={st.label} color={st.color} />;
}

function BatchDetail() {
  const { batchId } = useParams();
  const navigate = useNavigate();
  const toast = useToast();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [rescanning, setRescanning] = useState(false);

  // Policy gate
  const [policies, setPolicies] = useState([]);
  const [policyId, setPolicyId] = useState('');
  const [gate, setGate] = useState(null); // { scan_id: {passed, fail} }

  const pollRef = useRef(null);

  const fetchDetail = useCallback(async () => {
    try {
      const res = await getBatchDetail(batchId);
      setData(res.data);
      return res.data;
    } catch (err) {
      toast('Failed to load batch: ' + (err.response?.data?.detail || err.message), 'error');
      return null;
    } finally {
      setLoading(false);
    }
  }, [batchId, toast]);

  // Initial load + load policies
  useEffect(() => {
    fetchDetail();
    apiV2.get('/policies').then((r) => setPolicies(r.data.policies || [])).catch(() => {});
  }, [fetchDetail]);

  // Poll while not terminal
  useEffect(() => {
    if (data && !TERMINAL.has(data.status)) {
      pollRef.current = setTimeout(async () => {
        const fresh = await fetchDetail();
        if (fresh && TERMINAL.has(fresh.status) && pollRef.current) {
          clearTimeout(pollRef.current);
        }
      }, 5000);
    }
    return () => { if (pollRef.current) clearTimeout(pollRef.current); };
  }, [data, fetchDetail]);

  const runPolicyCheck = async (pid) => {
    setPolicyId(pid);
    if (!pid) { setGate(null); return; }
    try {
      const res = await getBatchPolicyCheck(batchId, pid);
      const map = {};
      (res.data.results || []).forEach((x) => { map[x.scan_id] = x; });
      setGate(map);
    } catch (err) {
      toast('Policy check failed: ' + (err.response?.data?.detail || err.message), 'error');
    }
  };

  const rescan = async (images, label) => {
    if (!images.length) { toast('Nothing to re-scan', 'info'); return; }
    setRescanning(true);
    try {
      const res = await startBatchScan(images);
      toast(`${label}: started a new batch of ${images.length}`, 'success');
      navigate(`/batches/${res.data.batch_id}`);
    } catch (err) {
      toast('Re-scan failed: ' + (err.response?.data?.detail || err.message), 'error');
    } finally {
      setRescanning(false);
    }
  };

  const exportCsv = () => {
    const rows = [['image', 'status', 'critical', 'high', 'medium', 'low', 'report_url']];
    (data.images || []).forEach((i) =>
      rows.push([i.image_name, i.status, i.critical, i.high, i.medium, i.low, i.report_url || '']));
    const csv = rows.map((r) => r.map((c) => `"${String(c ?? '').replace(/"/g, '""')}"`).join(',')).join('\n');
    const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
    const a = document.createElement('a');
    a.href = url; a.download = `batch-${batchId.slice(0, 8)}.csv`; a.click();
    URL.revokeObjectURL(url);
  };

  if (loading) {
    return (
      <Box>
        <PageHeader title="Batch" description="Loading…" />
        <TableSkeleton rows={6} cols={6} />
      </Box>
    );
  }
  if (!data) return null;

  const failedImages = (data.images || []).filter((i) => i.status === 'failed').map((i) => i.image_name);
  const allImages = (data.images || []).map((i) => i.image_name);
  const pct = data.total_images ? Math.round((data.completed / data.total_images) * 100) : 0;
  const isRunning = !TERMINAL.has(data.status);

  return (
    <Box>
      <PageHeader
        title={`Batch ${batchId.slice(0, 8)}`}
        description={data.created_at ? `Created ${new Date(data.created_at).toLocaleString()}` : ''}
        actions={
          <Tooltip title="Refresh">
            <IconButton onClick={fetchDetail} aria-label="Refresh batch" sx={{ bgcolor: 'action.hover' }}>
              <RefreshIcon />
            </IconButton>
          </Tooltip>
        }
      />

      {/* Rollup */}
      <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
        <Stack direction="row" spacing={2} useFlexGap flexWrap="wrap" alignItems="center" sx={{ mb: isRunning ? 1.5 : 0 }}>
          <StatusChip status={data.status} />
          <Typography variant="body2" sx={{ fontVariantNumeric: 'tabular-nums' }}>
            {data.completed}/{data.total_images} completed{data.failed > 0 ? ` · ${data.failed} failed` : ''}
          </Typography>
          <Box sx={{ flexGrow: 1 }} />
          <SeverityChip severity="critical" count={data.totals.critical} />
          <SeverityChip severity="high" count={data.totals.high} />
          <SeverityChip severity="medium" count={data.totals.medium} />
          <SeverityChip severity="low" count={data.totals.low} />
        </Stack>
        {isRunning && <LinearProgress variant="determinate" value={pct} sx={{ height: 6, borderRadius: 3 }} />}
      </Paper>

      {/* Actions + policy gate */}
      <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
        <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} alignItems={{ md: 'center' }}>
          <Button size="small" startIcon={<ReplayIcon />} disabled={rescanning || !failedImages.length}
            onClick={() => rescan(failedImages, 'Re-scan failed')}>
            Re-scan failed{failedImages.length ? ` (${failedImages.length})` : ''}
          </Button>
          <Button size="small" startIcon={<ReplayIcon />} disabled={rescanning || !allImages.length}
            onClick={() => rescan(allImages, 'Re-scan all')}>
            Re-scan all
          </Button>
          <Button size="small" startIcon={<DownloadIcon />} onClick={exportCsv}>Export CSV</Button>
          <Box sx={{ flexGrow: 1 }} />
          <FormControl size="small" sx={{ minWidth: 220 }}>
            <InputLabel id="batch-policy-label">Policy gate</InputLabel>
            <Select labelId="batch-policy-label" label="Policy gate" value={policyId}
              onChange={(e) => runPolicyCheck(e.target.value)}>
              <MenuItem value=""><em>None</em></MenuItem>
              {policies.map((p) => <MenuItem key={p.id} value={p.id}>{p.name}</MenuItem>)}
            </Select>
          </FormControl>
        </Stack>
      </Paper>

      {/* Per-image table */}
      <TableContainer component={Paper} variant="outlined">
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Image</TableCell>
              <TableCell>Status</TableCell>
              <Tooltip title="Critical / High / Medium / Low"><TableCell>C / H / M / L</TableCell></Tooltip>
              {policyId && <TableCell>Gate</TableCell>}
              <TableCell align="center">Report</TableCell>
              <TableCell align="center">SBOM</TableCell>
              <TableCell align="center">Retry</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {(data.images || []).map((i) => {
              const g = gate && gate[i.scan_id];
              return (
                <TableRow key={i.scan_id} hover>
                  <TableCell>
                    <Typography variant="body2" sx={{ fontFamily: MONO_FONT, fontSize: '0.8rem', maxWidth: 360 }} noWrap title={i.image_name}>
                      {i.image_name}
                    </Typography>
                  </TableCell>
                  <TableCell><StatusChip status={i.status} /></TableCell>
                  <TableCell>
                    <Box sx={{ display: 'flex', gap: 1.5, fontVariantNumeric: 'tabular-nums' }}>
                      {['critical', 'high', 'medium', 'low'].map((s) => (
                        <Box key={s} component="span" sx={{ minWidth: 16, textAlign: 'right',
                          fontWeight: i[s] > 0 ? 700 : 400, color: i[s] > 0 ? getSeverity(s).solid : 'text.disabled' }}>
                          {i[s]}
                        </Box>
                      ))}
                    </Box>
                  </TableCell>
                  {policyId && (
                    <TableCell>
                      {!g || g.passed === null ? (
                        <Typography variant="caption" color="text.disabled">—</Typography>
                      ) : g.passed ? (
                        <Chip size="small" color="success" variant="outlined" icon={<CheckCircleIcon />} label="Pass" />
                      ) : (
                        <Chip size="small" color="error" variant="outlined" icon={<CancelIcon />} label={`Fail${g.fail ? ` (${g.fail})` : ''}`} />
                      )}
                    </TableCell>
                  )}
                  <TableCell align="center">
                    {i.report_url ? (
                      <Tooltip title="View report">
                        <IconButton size="small" component={Link} href={i.report_url} target="_blank" rel="noopener noreferrer" aria-label={`Report for ${i.image_name}`}>
                          <OpenInNewIcon sx={{ fontSize: 18 }} />
                        </IconButton>
                      </Tooltip>
                    ) : <Typography variant="caption" color="text.disabled">—</Typography>}
                  </TableCell>
                  <TableCell align="center">
                    {i.sbom_report_url ? (
                      <Tooltip title="View SBOM">
                        <IconButton size="small" component={Link} href={i.sbom_report_url} target="_blank" rel="noopener noreferrer" aria-label={`SBOM for ${i.image_name}`}>
                          <DescriptionIcon sx={{ fontSize: 18 }} />
                        </IconButton>
                      </Tooltip>
                    ) : <Typography variant="caption" color="text.disabled">—</Typography>}
                  </TableCell>
                  <TableCell align="center">
                    {i.status === 'failed' && (
                      <Tooltip title="Re-scan this image">
                        <IconButton size="small" disabled={rescanning} onClick={() => rescan([i.image_name], 'Retry')} aria-label={`Re-scan ${i.image_name}`}>
                          <ReplayIcon sx={{ fontSize: 18 }} />
                        </IconButton>
                      </Tooltip>
                    )}
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
}

export default BatchDetail;
