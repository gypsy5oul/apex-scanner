import React, { useState, useEffect, useMemo, useCallback } from 'react';
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
  TextField,
  InputAdornment,
  ToggleButton,
  ToggleButtonGroup,
  Alert,
  Link,
  Stack,
} from '@mui/material';
import { useTheme } from '@mui/material/styles';
import SearchIcon from '@mui/icons-material/Search';
import RefreshIcon from '@mui/icons-material/Refresh';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';
import PageHeader from '../components/PageHeader';
import { useTableSort, SortableHeadCell } from '../components/SortableTable';
import { TableSkeleton } from '../components/LoadingSkeletons';
import { useToast } from '../components/Feedback';
import { getApprovedBaseImages } from '../api';
import { getSeverity, MONO_FONT } from '../theme/tokens';

// Color-coded C/H/M/L counts — column header carries the labels, the status
// chip carries the color-independent signal, so this stays accessible.
function SevCounts({ scan }) {
  const theme = useTheme();
  const cells = [
    ['critical', scan?.critical || 0],
    ['high', scan?.high || 0],
    ['medium', scan?.medium || 0],
    ['low', scan?.low || 0],
  ];
  return (
    <Box sx={{ display: 'flex', gap: 1.5, fontVariantNumeric: 'tabular-nums' }}>
      {cells.map(([sev, n]) => (
        <Typography
          key={sev}
          component="span"
          variant="body2"
          sx={{
            minWidth: 18,
            textAlign: 'right',
            fontWeight: n > 0 ? 700 : 400,
            color: n > 0 ? getSeverity(sev).solid : 'text.disabled',
          }}
        >
          {n}
        </Typography>
      ))}
    </Box>
  );
}

function StatusChip({ status }) {
  if (status === 'clean') {
    return <Chip size="small" icon={<CheckCircleIcon />} label="Clean" color="success" variant="outlined" />;
  }
  if (status === 'attention') {
    return <Chip size="small" icon={<WarningAmberIcon />} label="Attention" color="warning" variant="outlined" />;
  }
  return <Chip size="small" label={status || 'unknown'} variant="outlined" />;
}

const TYPE_LABELS = { 'runtime-base': 'Runtime base', 'app-server': 'App server' };

const ACCESSORS = {
  name: (r) => r.name || '',
  type: (r) => r.type || '',
  status: (r) => r.status || '',
  critical: (r) => (r.scan?.critical || 0) * 1000 + (r.scan?.high || 0), // sort by risk
  scanned_on: (r) => r.scanned_on || '',
};

function ApprovedBaseImages() {
  const toast = useToast();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState(null);
  const [query, setQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');

  const load = useCallback(async (refresh = false) => {
    refresh ? setRefreshing(true) : setLoading(true);
    setError(null);
    try {
      const res = await getApprovedBaseImages(refresh);
      setData(res.data);
      if (refresh) toast('Catalog refreshed', 'success');
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Failed to load the catalog');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [toast]);

  useEffect(() => { load(false); }, [load]);

  const images = useMemo(() => data?.images || [], [data]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return images.filter((img) => {
      if (typeFilter !== 'all' && img.type !== typeFilter) return false;
      if (statusFilter !== 'all' && img.status !== statusFilter) return false;
      if (q && !(`${img.name} ${img.pull_url} ${img.description}`.toLowerCase().includes(q))) return false;
      return true;
    });
  }, [images, query, typeFilter, statusFilter]);

  const { sorted, orderBy, order, handleSort } = useTableSort(filtered, ACCESSORS, { key: 'name', dir: 'asc' });

  const copy = (text, label) => {
    navigator.clipboard.writeText(text);
    toast(`${label} copied`, 'success');
  };

  const meta = data?.meta;

  return (
    <Box>
      <PageHeader
        title="Approved Base Images"
        description="Hardened, Apex-verified base images approved for use. Pull from the internal registry below."
        actions={
          <Tooltip title="Re-fetch the latest catalog from source">
            <span>
              <IconButton onClick={() => load(true)} disabled={refreshing} aria-label="Refresh catalog" sx={{ bgcolor: 'action.hover' }}>
                <RefreshIcon sx={refreshing ? { animation: 'spin 1s linear infinite', '@keyframes spin': { to: { transform: 'rotate(360deg)' } } } : undefined} />
              </IconButton>
            </span>
          </Tooltip>
        }
      />

      {/* Catalog context */}
      {data && (
        <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
          <Stack direction="row" spacing={3} useFlexGap flexWrap="wrap" alignItems="center">
            <Typography variant="body2" color="text.secondary">
              Registry: <Box component="span" sx={{ fontFamily: MONO_FONT, color: 'text.primary' }}>{data.registry}</Box>
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Namespace: <Box component="span" sx={{ fontFamily: MONO_FONT, color: 'text.primary' }}>{data.namespace}</Box>
            </Typography>
            <Typography variant="body2" color="text.secondary">
              {images.length} images · generated {data.generated}
            </Typography>
            {meta && (
              <Chip
                size="small"
                variant="outlined"
                color={meta.source === 'live' ? 'success' : meta.source === 'stale' ? 'warning' : 'default'}
                label={meta.source === 'live' ? 'Live' : meta.source === 'stale' ? 'Cached (source unreachable)' : 'Cached'}
              />
            )}
          </Stack>
          {data._note && (
            <Typography variant="caption" color="text.disabled" sx={{ display: 'block', mt: 1 }}>
              {data._note}
            </Typography>
          )}
        </Paper>
      )}

      {/* Filters */}
      <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
        <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} alignItems={{ md: 'center' }}>
          <TextField
            size="small"
            placeholder="Search name, path, description…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            sx={{ minWidth: 260 }}
            InputProps={{ startAdornment: <InputAdornment position="start"><SearchIcon fontSize="small" /></InputAdornment> }}
          />
          <ToggleButtonGroup size="small" exclusive value={typeFilter} onChange={(_e, v) => v && setTypeFilter(v)} aria-label="Filter by type">
            <ToggleButton value="all">All types</ToggleButton>
            <ToggleButton value="runtime-base">Runtime base</ToggleButton>
            <ToggleButton value="app-server">App server</ToggleButton>
          </ToggleButtonGroup>
          <ToggleButtonGroup size="small" exclusive value={statusFilter} onChange={(_e, v) => v && setStatusFilter(v)} aria-label="Filter by status">
            <ToggleButton value="all">All status</ToggleButton>
            <ToggleButton value="clean">Clean</ToggleButton>
            <ToggleButton value="attention">Attention</ToggleButton>
          </ToggleButtonGroup>
        </Stack>
      </Paper>

      {error && <Alert severity="error" sx={{ mb: 2 }} action={<IconButton size="small" onClick={() => load(true)} aria-label="Retry"><RefreshIcon fontSize="small" /></IconButton>}>{error}</Alert>}

      {loading ? (
        <TableSkeleton rows={8} cols={6} />
      ) : (
        <TableContainer component={Paper} variant="outlined">
          <Table size="small">
            <TableHead>
              <TableRow>
                <SortableHeadCell columnKey="name" orderBy={orderBy} order={order} onSort={handleSort}>Image</SortableHeadCell>
                <SortableHeadCell columnKey="type" orderBy={orderBy} order={order} onSort={handleSort}>Type</SortableHeadCell>
                <SortableHeadCell columnKey="status" orderBy={orderBy} order={order} onSort={handleSort}>Status</SortableHeadCell>
                <Tooltip title="Critical / High / Medium / Low"><TableCell>C / H / M / L</TableCell></Tooltip>
                <TableCell>Pull path</TableCell>
                <SortableHeadCell columnKey="scanned_on" orderBy={orderBy} order={order} onSort={handleSort}>Scanned</SortableHeadCell>
                <TableCell align="center">Report</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {sorted.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} sx={{ textAlign: 'center', py: 6, color: 'text.secondary' }}>
                    {images.length === 0 ? 'No approved base images in the catalog yet.' : 'No images match your filters.'}
                  </TableCell>
                </TableRow>
              ) : (
                sorted.map((img) => (
                  <TableRow key={img.pull_url || img.name} hover>
                    <TableCell>
                      <Typography variant="body2" fontWeight={600}>{img.name}</Typography>
                      {img.description && (
                        <Typography variant="caption" color="text.secondary" sx={{ display: 'block', maxWidth: 360 }} noWrap title={img.description}>
                          {img.description}
                        </Typography>
                      )}
                    </TableCell>
                    <TableCell><Typography variant="body2" color="text.secondary">{TYPE_LABELS[img.type] || img.type}</Typography></TableCell>
                    <TableCell><StatusChip status={img.status} /></TableCell>
                    <TableCell><SevCounts scan={img.scan} /></TableCell>
                    <TableCell>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, maxWidth: 340 }}>
                        <Typography variant="body2" sx={{ fontFamily: MONO_FONT, fontSize: '0.8rem' }} noWrap title={img.pull_url}>
                          {img.pull_url}
                        </Typography>
                        <Tooltip title="Copy pull path">
                          <IconButton size="small" onClick={() => copy(img.pull_url, 'Pull path')} aria-label={`Copy pull path for ${img.name}`}>
                            <ContentCopyIcon sx={{ fontSize: 16 }} />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Copy docker pull command">
                          <IconButton size="small" onClick={() => copy(`docker pull ${img.pull_url}`, 'docker pull command')} aria-label={`Copy docker pull command for ${img.name}`}>
                            <Typography component="span" sx={{ fontFamily: MONO_FONT, fontSize: 11, fontWeight: 700 }}>$</Typography>
                          </IconButton>
                        </Tooltip>
                      </Box>
                    </TableCell>
                    <TableCell><Typography variant="body2" color="text.secondary" sx={{ fontVariantNumeric: 'tabular-nums' }}>{img.scanned_on || '—'}</Typography></TableCell>
                    <TableCell align="center">
                      {img.report_url ? (
                        <Tooltip title="View scan report">
                          <IconButton size="small" component={Link} href={img.report_url} target="_blank" rel="noopener noreferrer" aria-label={`Open scan report for ${img.name}`}>
                            <OpenInNewIcon sx={{ fontSize: 18 }} />
                          </IconButton>
                        </Tooltip>
                      ) : <Typography variant="caption" color="text.disabled">—</Typography>}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </Box>
  );
}

export default ApprovedBaseImages;
