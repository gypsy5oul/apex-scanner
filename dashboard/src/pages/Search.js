import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Paper,
  Typography,
  TextField,
  Button,
  Alert,
  CircularProgress,
  Grid,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  Chip,
} from '@mui/material';
import PageHeader from '../components/PageHeader';
import SearchIcon from '@mui/icons-material/Search';
import { searchVulnerabilities } from '../api';
import SeverityChip from '../components/SeverityChip';
import { useTableSort, SortableHeadCell } from '../components/SortableTable';
import { MONO_FONT, SEVERITY_ORDER } from '../theme/tokens';

// Stable accessors for client-side sorting of search results.
const SEARCH_ACCESSORS = {
  cve_id: (v) => v.cve_id,
  severity: (v) => {
    const i = SEVERITY_ORDER.indexOf(String(v.severity || '').toLowerCase());
    return i === -1 ? SEVERITY_ORDER.length : i;
  },
  package_name: (v) => v.package_name,
  package_version: (v) => v.package_version,
  image_name: (v) => v.image_name,
  fix_available: (v) => (v.fix_available ? 1 : 0),
};

function Search() {
  const navigate = useNavigate();
  const [cve, setCve] = useState('');
  const [packageName, setPackageName] = useState('');
  const [severity, setSeverity] = useState('');
  const [image, setImage] = useState('');
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);

  const resultsSort = useTableSort(results?.results || [], SEARCH_ACCESSORS, { key: 'severity', dir: 'asc' });

  const handleSearch = async (e) => {
    e.preventDefault();
    if (!cve && !packageName && !severity && !image) {
      setError('Please enter at least one search parameter');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const params = {
        ...(cve && { cve }),
        ...(packageName && { package: packageName }),
        ...(severity && { severity }),
        ...(image && { image }),
        limit: 1000,
      };
      const response = await searchVulnerabilities(params);
      setResults(response.data);
      setPage(0);
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
      setResults(null);
    } finally {
      setLoading(false);
    }
  };

  const handleChangePage = (event, newPage) => {
    setPage(newPage);
  };

  const handleChangeRowsPerPage = (event) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  const paginatedResults = resultsSort.sorted.slice(
    page * rowsPerPage,
    page * rowsPerPage + rowsPerPage
  );

  return (
    <Box>
      <PageHeader
        title="Search CVEs"
        description="Look up vulnerabilities by CVE ID or keyword across all scans"
      />

      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          Search Parameters
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Search for vulnerabilities across all scans by CVE ID, package name, severity, or image.
        </Typography>

        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        <form onSubmit={handleSearch}>
          <Grid container spacing={2}>
            <Grid item xs={12} md={3}>
              <TextField
                fullWidth
                label="CVE ID"
                placeholder="e.g., CVE-2023-1234"
                value={cve}
                onChange={(e) => setCve(e.target.value)}
                disabled={loading}
              />
            </Grid>
            <Grid item xs={12} md={3}>
              <TextField
                fullWidth
                label="Package Name"
                placeholder="e.g., openssl"
                value={packageName}
                onChange={(e) => setPackageName(e.target.value)}
                disabled={loading}
              />
            </Grid>
            <Grid item xs={12} md={3}>
              <FormControl fullWidth>
                <InputLabel id="search-severity-label">Severity</InputLabel>
                <Select
                  labelId="search-severity-label"
                  id="search-severity"
                  value={severity}
                  label="Severity"
                  onChange={(e) => setSeverity(e.target.value)}
                  disabled={loading}
                >
                  <MenuItem value="">All</MenuItem>
                  <MenuItem value="critical">Critical</MenuItem>
                  <MenuItem value="high">High</MenuItem>
                  <MenuItem value="medium">Medium</MenuItem>
                  <MenuItem value="low">Low</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} md={3}>
              <TextField
                fullWidth
                label="Image Name"
                placeholder="e.g., nginx"
                value={image}
                onChange={(e) => setImage(e.target.value)}
                disabled={loading}
              />
            </Grid>
          </Grid>

          <Box sx={{ mt: 2 }}>
            <Button
              type="submit"
              variant="contained"
              disabled={loading}
              startIcon={loading ? <CircularProgress size={20} /> : <SearchIcon />}
            >
              Search
            </Button>
          </Box>
        </form>
      </Paper>

      {results && (
        <Paper sx={{ p: 3 }}>
          <Typography variant="h6" gutterBottom>
            Search Results
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Found {results.total} vulnerabilities
            {results.results && results.total > results.results.length && (
              <> (showing first {results.results.length})</>
            )}
          </Typography>

          {results.results && results.results.length > 0 ? (
            <>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      {[
                        ['cve_id', 'CVE ID'],
                        ['severity', 'Severity'],
                        ['package_name', 'Package'],
                        ['package_version', 'Version'],
                        ['image_name', 'Image'],
                        ['fix_available', 'Fix'],
                      ].map(([key, label]) => (
                        <SortableHeadCell
                          key={key}
                          columnKey={key}
                          orderBy={resultsSort.orderBy}
                          order={resultsSort.order}
                          onSort={resultsSort.handleSort}
                        >
                          {label}
                        </SortableHeadCell>
                      ))}
                      <TableCell>Found By</TableCell>
                      <TableCell>Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {paginatedResults.map((vuln, idx) => (
                      <TableRow key={`${vuln.scan_id}-${vuln.cve_id}-${idx}`} hover>
                        <TableCell>
                          <Typography variant="body2" sx={{ fontFamily: MONO_FONT, fontWeight: 700 }}>
                            {vuln.cve_id}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <SeverityChip severity={vuln.severity} />
                        </TableCell>
                        <TableCell sx={{ fontFamily: MONO_FONT }}>{vuln.package_name}</TableCell>
                        <TableCell sx={{ fontFamily: MONO_FONT }}>{vuln.package_version}</TableCell>
                        <TableCell>
                          <Typography
                            variant="body2"
                            title={vuln.image_name}
                            sx={{
                              maxWidth: 150,
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap',
                            }}
                          >
                            {vuln.image_name}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Chip
                            size="small"
                            label={vuln.fix_available ? vuln.fix_version || 'Yes' : 'No'}
                            color={vuln.fix_available ? 'success' : 'default'}
                          />
                        </TableCell>
                        <TableCell>
                          <Box sx={{ display: 'flex', gap: 0.5 }}>
                            {vuln.found_by?.map((scanner) => (
                              <Chip
                                key={scanner}
                                label={scanner}
                                size="small"
                                variant="outlined"
                              />
                            ))}
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Button
                            size="small"
                            onClick={() => navigate(`/scan/${vuln.scan_id}`)}
                          >
                            View Scan
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
                count={results.results.length}
                rowsPerPage={rowsPerPage}
                page={page}
                onPageChange={handleChangePage}
                onRowsPerPageChange={handleChangeRowsPerPage}
              />
            </>
          ) : (
            <Alert severity="info">No vulnerabilities found matching your criteria</Alert>
          )}
        </Paper>
      )}
    </Box>
  );
}

export default Search;
