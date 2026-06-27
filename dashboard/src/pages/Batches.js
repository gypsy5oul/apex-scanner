import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  IconButton,
  Tooltip,
  Typography,
  Button,
} from '@mui/material';
import RefreshIcon from '@mui/icons-material/Refresh';
import ViewListIcon from '@mui/icons-material/ViewList';
import PageHeader from '../components/PageHeader';
import { useTableSort, SortableHeadCell } from '../components/SortableTable';
import { TableSkeleton } from '../components/LoadingSkeletons';
import { useToast } from '../components/Feedback';
import { getBatches } from '../api';
import { MONO_FONT } from '../theme/tokens';

const STATUS = {
  completed: { label: 'Completed', color: 'success' },
  failed: { label: 'Failed', color: 'error' },
  in_progress: { label: 'Running', color: 'info' },
};

const ACCESSORS = {
  batch_id: (b) => b.batch_id || '',
  created_at: (b) => b.created_at || '',
  total_images: (b) => b.total_images || 0,
  status: (b) => b.status || '',
};

function Batches() {
  const navigate = useNavigate();
  const toast = useToast();
  const [batches, setBatches] = useState([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await getBatches();
      setBatches(res.data.batches || []);
    } catch (err) {
      toast('Failed to load batches: ' + (err.response?.data?.detail || err.message), 'error');
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => { load(); }, [load]);

  const { sorted, orderBy, order, handleSort } = useTableSort(batches, ACCESSORS, {
    key: 'created_at', dir: 'desc',
  });

  return (
    <Box>
      <PageHeader
        title="Batch Results"
        description="Past batch scans and their per-image results"
        actions={
          <>
            <Tooltip title="Refresh">
              <IconButton onClick={load} aria-label="Refresh batches" sx={{ bgcolor: 'action.hover' }}>
                <RefreshIcon />
              </IconButton>
            </Tooltip>
            <Button variant="contained" onClick={() => navigate('/batch')}>New Batch Scan</Button>
          </>
        }
      />

      {loading ? (
        <TableSkeleton rows={6} cols={5} />
      ) : (
        <TableContainer component={Paper} variant="outlined">
          <Table size="small">
            <TableHead>
              <TableRow>
                <SortableHeadCell columnKey="batch_id" orderBy={orderBy} order={order} onSort={handleSort}>Batch</SortableHeadCell>
                <SortableHeadCell columnKey="created_at" orderBy={orderBy} order={order} onSort={handleSort}>Created</SortableHeadCell>
                <SortableHeadCell columnKey="total_images" orderBy={orderBy} order={order} onSort={handleSort}>Images</SortableHeadCell>
                <TableCell>Progress</TableCell>
                <SortableHeadCell columnKey="status" orderBy={orderBy} order={order} onSort={handleSort}>Status</SortableHeadCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {sorted.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} sx={{ textAlign: 'center', py: 6, color: 'text.secondary' }}>
                    <ViewListIcon sx={{ fontSize: 40, opacity: 0.4, display: 'block', mx: 'auto', mb: 1 }} />
                    No batch scans yet — run a Batch Scan to get started.
                  </TableCell>
                </TableRow>
              ) : (
                sorted.map((b) => {
                  const st = STATUS[b.status] || { label: b.status, color: 'default' };
                  return (
                    <TableRow
                      key={b.batch_id}
                      hover
                      sx={{ cursor: 'pointer' }}
                      onClick={() => navigate(`/batches/${b.batch_id}`)}
                    >
                      <TableCell>
                        <Typography variant="body2" sx={{ fontFamily: MONO_FONT }}>{(b.batch_id || '').slice(0, 8)}</Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" color="text.secondary">
                          {b.created_at ? new Date(b.created_at).toLocaleString() : '—'}
                        </Typography>
                      </TableCell>
                      <TableCell sx={{ fontVariantNumeric: 'tabular-nums' }}>{b.total_images}</TableCell>
                      <TableCell>
                        <Typography variant="body2" sx={{ fontVariantNumeric: 'tabular-nums' }}>
                          {b.completed}/{b.total_images} done
                          {b.failed > 0 && (
                            <Box component="span" sx={{ color: 'error.main', ml: 1 }}>· {b.failed} failed</Box>
                          )}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip size="small" variant="outlined" label={st.label} color={st.color} />
                      </TableCell>
                    </TableRow>
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

export default Batches;
