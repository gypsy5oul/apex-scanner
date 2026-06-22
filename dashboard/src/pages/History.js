import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Paper,
  Typography,
  TextField,
  Button,
  Alert,
  CircularProgress,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  Chip,
  Card,
  CardContent,
} from '@mui/material';
import SearchIcon from '@mui/icons-material/Search';
import TrendingUpIcon from '@mui/icons-material/TrendingUp';
import TrendingDownIcon from '@mui/icons-material/TrendingDown';
import HistoryIcon from '@mui/icons-material/History';
import RefreshIcon from '@mui/icons-material/Refresh';
import { getImageHistory, getRecentScans } from '../api';
import SeverityChip from '../components/SeverityChip';
import { VulnerabilityBar } from '../components/VulnerabilityChart';
import { TableSkeleton } from '../components/LoadingSkeletons';
import PageHeader from '../components/PageHeader';
import { useTableSort, SortableHeadCell } from '../components/SortableTable';
import { useToast } from '../components/Feedback';
import { MONO_FONT } from '../theme/tokens';

// Stable accessor maps (defined once so the sort memo doesn't thrash).
const RECENT_ACCESSORS = {
  image_name: (s) => s.image_name,
  status: (s) => s.status,
  critical: (s) => s.summary?.critical || 0,
  high: (s) => s.summary?.high || 0,
  medium: (s) => s.summary?.medium || 0,
  low: (s) => s.summary?.low || 0,
  timestamp: (s) => (s.timestamp ? new Date(s.timestamp).getTime() : 0),
};

const HISTORY_ACCESSORS = {
  scan_timestamp: (s) => (s.scan_timestamp ? new Date(s.scan_timestamp).getTime() : 0),
  status: (s) => s.status,
  critical: (s) => s.critical || 0,
  high: (s) => s.high || 0,
  medium: (s) => s.medium || 0,
  low: (s) => s.low || 0,
  total_packages: (s) => s.total_packages || 0,
};

function History() {
  const navigate = useNavigate();
  const toast = useToast();
  const [imageName, setImageName] = useState('');
  const [history, setHistory] = useState(null);
  const [recentScans, setRecentScans] = useState([]);
  const [loading, setLoading] = useState(false);
  const [recentLoading, setRecentLoading] = useState(true);
  const [error, setError] = useState(null);
  const [historyPage, setHistoryPage] = useState(0);
  const [historyRowsPerPage, setHistoryRowsPerPage] = useState(10);

  const recentSort = useTableSort(recentScans, RECENT_ACCESSORS, { key: 'timestamp', dir: 'desc' });
  const historySort = useTableSort(history?.history || [], HISTORY_ACCESSORS, { key: 'scan_timestamp', dir: 'desc' });
  const pagedHistory = historySort.sorted.slice(
    historyPage * historyRowsPerPage,
    historyPage * historyRowsPerPage + historyRowsPerPage
  );

  // Fetch recent scans on component mount
  const fetchRecentScans = async () => {
    setRecentLoading(true);
    try {
      const response = await getRecentScans(10);
      setRecentScans(response.data?.scans || []);
    } catch (err) {
      toast('Failed to load recent scans: ' + (err.response?.data?.detail || err.message), 'error');
    } finally {
      setRecentLoading(false);
    }
  };

  useEffect(() => {
    fetchRecentScans();
  }, []);

  const handleSearch = async (e) => {
    e.preventDefault();
    if (!imageName.trim()) {
      setError('Please enter an image name');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const response = await getImageHistory(imageName.trim());
      setHistory(response.data);
      setHistoryPage(0);
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
      setHistory(null);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box>
      <PageHeader
        title="Scan History"
        description="Search an image's scan history and review recent scans"
      />

      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          Search by Image Name
        </Typography>
        <form onSubmit={handleSearch}>
          <Box sx={{ display: 'flex', gap: 2 }}>
            <TextField
              fullWidth
              label="Docker Image Name"
              placeholder="e.g., nginx:latest"
              value={imageName}
              onChange={(e) => setImageName(e.target.value)}
              disabled={loading}
            />
            <Button
              type="submit"
              variant="contained"
              disabled={loading}
              startIcon={loading ? <CircularProgress size={20} /> : <SearchIcon />}
              sx={{ minWidth: 150 }}
            >
              Search
            </Button>
          </Box>
        </form>
      </Paper>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {/* Recent Scans Section */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <HistoryIcon color="primary" />
              <Typography variant="h6">Recent Scans (Last 10)</Typography>
            </Box>
            <Button
              size="small"
              startIcon={recentLoading ? <CircularProgress size={16} /> : <RefreshIcon />}
              onClick={fetchRecentScans}
              disabled={recentLoading}
            >
              Refresh
            </Button>
          </Box>

          {recentLoading ? (
            <TableSkeleton rows={6} cols={8} />
          ) : recentScans.length === 0 ? (
            <Typography color="text.secondary" textAlign="center" py={3}>
              No scans found. Start by scanning an image.
            </Typography>
          ) : (
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    {[
                      ['image_name', 'Image Name'],
                      ['status', 'Status'],
                      ['critical', 'Critical'],
                      ['high', 'High'],
                      ['medium', 'Medium'],
                      ['low', 'Low'],
                      ['timestamp', 'Scanned At'],
                    ].map(([key, label]) => (
                      <SortableHeadCell
                        key={key}
                        columnKey={key}
                        orderBy={recentSort.orderBy}
                        order={recentSort.order}
                        onSort={recentSort.handleSort}
                      >
                        {label}
                      </SortableHeadCell>
                    ))}
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {recentSort.sorted.map((scan) => (
                    <TableRow key={scan.scan_id} hover>
                      <TableCell>
                        <Typography
                          variant="body2"
                          sx={{
                            fontFamily: MONO_FONT,
                            maxWidth: 300,
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap',
                          }}
                          title={scan.image_name}
                        >
                          {scan.image_name}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip
                          size="small"
                          label={scan.status}
                          color={
                            scan.status === 'completed'
                              ? 'success'
                              : scan.status === 'failed'
                              ? 'error'
                              : 'warning'
                          }
                        />
                      </TableCell>
                      <TableCell>
                        <SeverityChip severity="Critical" count={scan.summary?.critical || 0} />
                      </TableCell>
                      <TableCell>
                        <SeverityChip severity="High" count={scan.summary?.high || 0} />
                      </TableCell>
                      <TableCell>
                        <SeverityChip severity="Medium" count={scan.summary?.medium || 0} />
                      </TableCell>
                      <TableCell>
                        <SeverityChip severity="Low" count={scan.summary?.low || 0} />
                      </TableCell>
                      <TableCell>
                        {scan.timestamp
                          ? new Date(scan.timestamp).toLocaleString()
                          : 'N/A'}
                      </TableCell>
                      <TableCell>
                        <Button
                          size="small"
                          onClick={() => navigate(`/scan/${scan.scan_id}`)}
                          disabled={scan.status !== 'completed'}
                        >
                          View
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </CardContent>
      </Card>

      {history && (
        <>
          {/* Trends */}
          {history.trends && (
            <Paper sx={{ p: 3, mb: 3 }}>
              <Typography variant="h6" gutterBottom>
                Trends (Latest vs Previous)
              </Typography>
              <Box sx={{ display: 'flex', gap: 3, flexWrap: 'wrap' }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <Typography>Critical:</Typography>
                  <Chip
                    icon={
                      history.trends.critical_change > 0 ? (
                        <TrendingUpIcon />
                      ) : (
                        <TrendingDownIcon />
                      )
                    }
                    label={
                      history.trends.critical_change > 0
                        ? `+${history.trends.critical_change}`
                        : history.trends.critical_change
                    }
                    color={history.trends.critical_change > 0 ? 'error' : 'success'}
                    size="small"
                  />
                </Box>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <Typography>High:</Typography>
                  <Chip
                    icon={
                      history.trends.high_change > 0 ? (
                        <TrendingUpIcon />
                      ) : (
                        <TrendingDownIcon />
                      )
                    }
                    label={
                      history.trends.high_change > 0
                        ? `+${history.trends.high_change}`
                        : history.trends.high_change
                    }
                    color={history.trends.high_change > 0 ? 'error' : 'success'}
                    size="small"
                  />
                </Box>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <Typography>Status:</Typography>
                  <Chip
                    label={history.trends.improving ? 'Improving' : 'Degrading'}
                    color={history.trends.improving ? 'success' : 'error'}
                    size="small"
                  />
                </Box>
              </Box>
            </Paper>
          )}

          {/* Chart */}
          {history.history && history.history.length > 1 && (
            <Paper sx={{ p: 3, mb: 3 }}>
              <Typography variant="h6" gutterBottom>
                Vulnerability Trend
              </Typography>
              <Box sx={{ height: 300 }}>
                <VulnerabilityBar history={history.history} />
              </Box>
            </Paper>
          )}

          {/* History Table */}
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Scan History for:{' '}
              <Box component="span" sx={{ fontFamily: MONO_FONT }}>
                {history.image_name}
              </Box>
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              Total scans: {history.total_scans}
            </Typography>

            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    {[
                      ['scan_timestamp', 'Date'],
                      ['status', 'Status'],
                      ['critical', 'Critical'],
                      ['high', 'High'],
                      ['medium', 'Medium'],
                      ['low', 'Low'],
                      ['total_packages', 'Packages'],
                    ].map(([key, label]) => (
                      <SortableHeadCell
                        key={key}
                        columnKey={key}
                        orderBy={historySort.orderBy}
                        order={historySort.order}
                        onSort={historySort.handleSort}
                      >
                        {label}
                      </SortableHeadCell>
                    ))}
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {pagedHistory.map((scan) => (
                    <TableRow key={scan.scan_id} hover>
                      <TableCell>
                        {scan.scan_timestamp
                          ? new Date(scan.scan_timestamp).toLocaleString()
                          : 'N/A'}
                      </TableCell>
                      <TableCell>
                        <Chip
                          size="small"
                          label={scan.status}
                          color={
                            scan.status === 'completed'
                              ? 'success'
                              : scan.status === 'failed'
                              ? 'error'
                              : 'warning'
                          }
                        />
                      </TableCell>
                      <TableCell>
                        <SeverityChip severity="Critical" count={scan.critical} />
                      </TableCell>
                      <TableCell>
                        <SeverityChip severity="High" count={scan.high} />
                      </TableCell>
                      <TableCell>
                        <SeverityChip severity="Medium" count={scan.medium} />
                      </TableCell>
                      <TableCell>
                        <SeverityChip severity="Low" count={scan.low} />
                      </TableCell>
                      <TableCell sx={{ fontVariantNumeric: 'tabular-nums' }}>
                        {scan.total_packages}
                      </TableCell>
                      <TableCell>
                        <Button
                          size="small"
                          onClick={() => navigate(`/scan/${scan.scan_id}`)}
                        >
                          View
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
            <TablePagination
              rowsPerPageOptions={[10, 25, 50, 100]}
              component="div"
              count={historySort.sorted.length}
              rowsPerPage={historyRowsPerPage}
              page={historyPage}
              onPageChange={(e, newPage) => setHistoryPage(newPage)}
              onRowsPerPageChange={(e) => {
                setHistoryRowsPerPage(parseInt(e.target.value, 10));
                setHistoryPage(0);
              }}
            />
          </Paper>
        </>
      )}
    </Box>
  );
}

export default History;
