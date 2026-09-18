import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
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
  Collapse,
  Button,
} from '@mui/material';
import AutoFixHighIcon from '@mui/icons-material/AutoFixHigh';

import SearchIcon from '@mui/icons-material/Search';
import RefreshIcon from '@mui/icons-material/Refresh';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';
import KeyboardArrowDownIcon from '@mui/icons-material/KeyboardArrowDown';
import KeyboardArrowRightIcon from '@mui/icons-material/KeyboardArrowRight';
import InfoOutlinedIcon from '@mui/icons-material/InfoOutlined';
import PageHeader from '../components/PageHeader';
import { useTableSort, SortableHeadCell } from '../components/SortableTable';
import { TableSkeleton } from '../components/LoadingSkeletons';
import { useToast } from '../components/Feedback';
import { getApprovedBaseImages } from '../api';
import { getSeverity, MONO_FONT } from '../theme/tokens';

// Color-coded C/H/M/L counts — column header carries the labels, the status
// chip carries the color-independent signal, so this stays accessible.
function SevCounts({ scan }) {
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

// Known `removed_notable` categories, prettified. Deliberately NOT exhaustive:
// the producer defines these keys and they already vary per image (jre8 ships
// two, most ship six), so anything unrecognised is humanized and rendered
// anyway. A fixed whitelist would silently drop a newly added category.
const REMOVED_CATEGORY_LABELS = {
  'package-manager': 'Package manager',
  'download-net': 'Download / network',
  'dev-build': 'Dev / build',
  runtime: 'Runtime',
  fonts: 'Fonts',
  utils: 'Utilities',
};

const humanizeCategory = (key) =>
  REMOVED_CATEGORY_LABELS[key] || key.replace(/[-_]/g, ' ').replace(/^./, (c) => c.toUpperCase());

function TokenChips({ items, color }) {
  return (
    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
      {items.map((t) => (
        <Chip
          key={t}
          size="small"
          label={t}
          variant="outlined"
          color={color}
          sx={{ height: 22, fontFamily: MONO_FONT, fontSize: '0.72rem' }}
        />
      ))}
    </Box>
  );
}

function PanelField({ label, children }) {
  return (
    <Box sx={{ mb: 1.75 }}>
      <Typography
        variant="caption"
        sx={{
          display: 'block',
          mb: 0.5,
          fontWeight: 700,
          textTransform: 'uppercase',
          letterSpacing: '.05em',
          color: 'text.secondary',
        }}
      >
        {label}
      </Typography>
      {children}
    </Box>
  );
}

// What actually changed vs the vendor image this base replaces. This is the
// "will my Dockerfile still build?" answer, so removals are the headline.
function ChangesPanel({ changes, imageName, onDiagnose }) {
  if (!changes || typeof changes !== 'object') {
    return (
      <Box>
        <Typography variant="body2" color="text.disabled" sx={{ mb: 1 }}>
          No change details published for this image.
        </Typography>
        {imageName && onDiagnose && (
          <Button
            variant="outlined"
            color="primary"
            size="small"
            startIcon={<AutoFixHighIcon />}
            onClick={() => onDiagnose(imageName)}
          >
            Diagnose App Dockerfile for {imageName}
          </Button>
        )}
      </Box>
    );
  }

  const removed = (changes.removed_notable && typeof changes.removed_notable === 'object')
    ? Object.entries(changes.removed_notable).filter(([, v]) => Array.isArray(v) && v.length > 0)
    : [];
  const hints = Array.isArray(changes.migration_hints) ? changes.migration_hints : [];

  return (
    <Box>
      <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', lg: '1fr 1fr' }, gap: 3 }}>
        <Box>
          {Array.isArray(changes.replaces) && changes.replaces.length > 0 && (
            <PanelField label="Replaces">
              <TokenChips items={changes.replaces} />
            </PanelField>
          )}
          {changes.base_os && (
            <PanelField label="Base OS">
              <Typography variant="body2" sx={{ fontFamily: MONO_FONT, fontSize: '0.8rem' }}>
                {changes.base_os}
              </Typography>
            </PanelField>
          )}
          {Array.isArray(changes.available_commands) && changes.available_commands.length > 0 && (
            <PanelField label="Commands still available">
              <TokenChips items={changes.available_commands} color="success" />
            </PanelField>
          )}
          {Array.isArray(changes.adds_back) && changes.adds_back.length > 0 && (
            <PanelField label="Added back">
              <TokenChips items={changes.adds_back} color="info" />
            </PanelField>
          )}
          {typeof changes.rpm_package_count === 'number' && (
            <PanelField label="RPM packages">
              <Typography variant="body2" sx={{ fontVariantNumeric: 'tabular-nums' }}>
                {changes.rpm_package_count}
              </Typography>
            </PanelField>
          )}
        </Box>

        <Box>
          {removed.length > 0 && (
            <PanelField label="Removed — not installable on micro bases">
              <Stack spacing={1}>
                {removed.map(([category, items]) => (
                  <Box key={category}>
                    <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 0.25 }}>
                      {humanizeCategory(category)}
                    </Typography>
                    <TokenChips items={items} color="error" />
                  </Box>
                ))}
              </Stack>
            </PanelField>
          )}
          {changes.note && (
            <PanelField label="Note">
              <Typography variant="body2" color="text.secondary">{changes.note}</Typography>
            </PanelField>
          )}
          {hints.length > 0 && (
            <PanelField label="Migration hints">
              <Stack component="ul" spacing={0.5} sx={{ m: 0, pl: 2 }}>
                {hints.map((h) => (
                  <Typography key={h} component="li" variant="body2" color="text.secondary">{h}</Typography>
                ))}
              </Stack>
            </PanelField>
          )}
        </Box>
      </Box>

      {imageName && onDiagnose && (
        <Box sx={{ mt: 2.5, pt: 1.5, borderTop: 1, borderColor: 'divider' }}>
          <Button
            variant="outlined"
            color="primary"
            size="small"
            startIcon={<AutoFixHighIcon />}
            onClick={() => onDiagnose(imageName)}
          >
            Diagnose App Dockerfile for {imageName}
          </Button>
        </Box>
      )}
    </Box>
  );
}


const ACCESSORS = {
  name: (r) => r.name || '',
  type: (r) => r.type || '',
  status: (r) => r.status || '',
  critical: (r) => (r.scan?.critical || 0) * 1000 + (r.scan?.high || 0), // sort by risk
  scanned_on: (r) => r.scanned_on || '',
};

function ApprovedBaseImages() {
  const toast = useToast();
  const navigate = useNavigate();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState(null);
  const [query, setQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [expanded, setExpanded] = useState(() => new Set());
  const [hintsOpen, setHintsOpen] = useState(false);

  const toggleRow = useCallback((key) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key); else next.add(key);
      return next;
    });
  }, []);

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
      if (q) {
        // Search the change delta too, not just the identity fields. The most
        // common question this page answers is "what replaces
        // eclipse-temurin:17?" — which only matches via `replaces`. Commands
        // are included so "curl" finds the bases that still ship it.
        const c = img.changes || {};
        const haystack = [
          img.name, img.pull_url, img.description,
          ...(Array.isArray(c.replaces) ? c.replaces : []),
          ...(Array.isArray(c.available_commands) ? c.available_commands : []),
        ].join(' ').toLowerCase();
        if (!haystack.includes(q)) return false;
      }
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
          <Stack direction="row" spacing={1.5} alignItems="center">
            <Button
              variant="contained"
              color="primary"
              startIcon={<AutoFixHighIcon />}
              onClick={() => navigate('/hardened-image-advisor')}
            >
              App Migration Advisor
            </Button>
            <Tooltip title="Re-fetch the latest catalog from source">
              <span>
                <IconButton onClick={() => load(true)} disabled={refreshing} aria-label="Refresh catalog" sx={{ bgcolor: 'action.hover' }}>
                  <RefreshIcon sx={refreshing ? { animation: 'spin 1s linear infinite', '@keyframes spin': { to: { transform: 'rotate(360deg)' } } } : undefined} />
                </IconButton>
              </span>
            </Tooltip>
          </Stack>
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

      {/* Migration hints — identical for every image, so the backend hoists
          them out of the per-image `changes` and we show them once. Collapsed
          by default to keep the page dense. */}
      {Array.isArray(data?.migration_hints) && data.migration_hints.length > 0 && (
        <Paper variant="outlined" sx={{ mb: 2 }}>
          <Button
            fullWidth
            onClick={() => setHintsOpen((v) => !v)}
            startIcon={<InfoOutlinedIcon fontSize="small" />}
            endIcon={hintsOpen ? <KeyboardArrowDownIcon /> : <KeyboardArrowRightIcon />}
            sx={{ justifyContent: 'flex-start', px: 2, py: 1.25, color: 'text.primary', textTransform: 'none' }}
            aria-expanded={hintsOpen}
          >
            <Typography variant="body2" sx={{ flexGrow: 1, textAlign: 'left', fontWeight: 600 }}>
              Migration hints — these bases are UBI9-micro and have no package manager
            </Typography>
          </Button>
          <Collapse in={hintsOpen} unmountOnExit>
            <Box sx={{ px: 2, pb: 2 }}>
              <Stack component="ul" spacing={0.75} sx={{ m: 0, pl: 2 }}>
                {data.migration_hints.map((h) => (
                  <Typography key={h} component="li" variant="body2" color="text.secondary">{h}</Typography>
                ))}
              </Stack>
            </Box>
          </Collapse>
        </Paper>
      )}

      {/* Filters */}
      <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
        <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} alignItems={{ md: 'center' }}>
          <TextField
            size="small"
            placeholder="Search name, path, description, replaces…"
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
        <TableSkeleton rows={8} cols={8} />
      ) : (
        <TableContainer component={Paper} variant="outlined">
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell sx={{ width: 40 }} />
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
                  <TableCell colSpan={8} sx={{ textAlign: 'center', py: 6, color: 'text.secondary' }}>
                    {images.length === 0 ? 'No approved base images in the catalog yet.' : 'No images match your filters.'}
                  </TableCell>
                </TableRow>
              ) : (
                sorted.map((img) => {
                  const rowKey = img.pull_url || img.name;
                  const isOpen = expanded.has(rowKey);
                  const hasChanges = !!img.changes;
                  return (
                  <React.Fragment key={rowKey}>
                  <TableRow hover sx={isOpen ? { '& > *': { borderBottom: 'unset' } } : undefined}>
                    <TableCell sx={{ width: 40 }}>
                      <Tooltip title={hasChanges ? (isOpen ? 'Hide what changed' : 'Show what changed vs the image it replaces') : 'No change details published'}>
                        <span>
                          <IconButton
                            size="small"
                            disabled={!hasChanges}
                            onClick={() => toggleRow(rowKey)}
                            aria-label={`${isOpen ? 'Hide' : 'Show'} change details for ${img.name}`}
                            aria-expanded={isOpen}
                          >
                            {isOpen ? <KeyboardArrowDownIcon fontSize="small" /> : <KeyboardArrowRightIcon fontSize="small" />}
                          </IconButton>
                        </span>
                      </Tooltip>
                    </TableCell>
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
                      <Stack direction="row" spacing={0.5} justifyContent="center" alignItems="center">
                        <Tooltip title={`Diagnose App Dockerfile for ${img.name}`}>
                          <IconButton
                            size="small"
                            color="primary"
                            onClick={() => navigate(`/hardened-image-advisor?base=${img.name}`)}
                            aria-label={`Diagnose Dockerfile for ${img.name}`}
                          >
                            <AutoFixHighIcon sx={{ fontSize: 18 }} />
                          </IconButton>
                        </Tooltip>
                        {img.report_url ? (
                          <Tooltip title="View scan report">
                            <IconButton size="small" component={Link} href={img.report_url} target="_blank" rel="noopener noreferrer" aria-label={`Open scan report for ${img.name}`}>
                              <OpenInNewIcon sx={{ fontSize: 18 }} />
                            </IconButton>
                          </Tooltip>
                        ) : <Typography variant="caption" color="text.disabled">—</Typography>}
                      </Stack>
                    </TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell colSpan={8} sx={{ py: 0, ...(isOpen ? {} : { border: 0 }) }}>
                      <Collapse in={isOpen} timeout="auto" unmountOnExit>
                        <Box sx={{ py: 2.5, px: 2 }}>
                          <ChangesPanel
                            changes={img.changes}
                            imageName={img.name}
                            onDiagnose={(name) => navigate(`/hardened-image-advisor?base=${name}`)}
                          />
                        </Box>
                      </Collapse>
                    </TableCell>
                  </TableRow>

                  </React.Fragment>
                  );
                })
              )}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </Box>
  );
}

export default ApprovedBaseImages;
