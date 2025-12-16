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
import SearchIcon from '@mui/icons-material/Search';
import { searchVulnerabilities } from '../api';
import SeverityChip from '../components/SeverityChip';

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

  const paginatedResults = results?.results?.slice(
    page * rowsPerPage,
    page * rowsPerPage + rowsPerPage
  );

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Search Vulnerabilities
      </Typography>

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
                <InputLabel>Severity</InputLabel>
                <Select
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
          </Typography>

          {results.results && results.results.length > 0 ? (
            <>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>CVE ID</TableCell>
                      <TableCell>Severity</TableCell>
                      <TableCell>Package</TableCell>
                      <TableCell>Version</TableCell>
                      <TableCell>Image</TableCell>
                      <TableCell>Fix</TableCell>
                      <TableCell>Found By</TableCell>
                      <TableCell>Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {paginatedResults.map((vuln, idx) => (
                      <TableRow key={`${vuln.scan_id}-${vuln.cve_id}-${idx}`} hover>
                        <TableCell>
                          <Typography variant="body2" fontWeight="bold">
                            {vuln.cve_id}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <SeverityChip severity={vuln.severity} />
                        </TableCell>
                        <TableCell>{vuln.package_name}</TableCell>
                        <TableCell>{vuln.package_version}</TableCell>
                        <TableCell>
                          <Typography
                            variant="body2"
                            sx={{
                              maxWidth: 150,
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
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
