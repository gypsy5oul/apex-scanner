import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  Box,
  Paper,
  Typography,
  TextField,
  Button,
  CircularProgress,
  Alert,
  Chip,
  Grid,
  Card,
  CardContent,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Tooltip,
  Divider,
  IconButton,
} from '@mui/material';
import AccountTreeIcon from '@mui/icons-material/AccountTree';
import SearchIcon from '@mui/icons-material/Search';
import { useTheme } from '@mui/material/styles';
import { getSeverity, severityAccent } from '../theme/tokens';
import SeverityChip from '../components/SeverityChip';
import { getDependencyGraph, getPackageImpact } from '../api';

// Mini count chip with guaranteed-contrast severity colors from tokens.
function CountChip({ count, severity, suffix }) {
  const t = getSeverity(severity);
  return (
    <Chip
      label={`${count}${suffix}`}
      size="small"
      sx={{ bgcolor: t.solid, color: t.onSolid, height: 20, fontSize: '0.65rem', fontWeight: 700 }}
    />
  );
}

function PackageNode({ node, selected, onClick }) {
  const theme = useTheme();
  const maxSeverity = node.critical_count > 0
    ? 'critical'
    : node.high_count > 0
      ? 'high'
      : node.vuln_count > 0
        ? 'medium'
        : 'none';
  const borderColor = selected
    ? theme.palette.primary.main
    : maxSeverity === 'none'
      ? theme.palette.divider
      : severityAccent(maxSeverity, theme.palette.mode);

  return (
    <Box
      role="button"
      tabIndex={0}
      aria-pressed={selected}
      aria-label={`${node.name} ${node.version}, ${node.vuln_count} vulnerabilities`}
      onClick={() => onClick(node)}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onClick(node);
        }
      }}
      sx={{
        p: 1.5,
        border: 2,
        borderColor,
        borderRadius: 2,
        bgcolor: selected ? 'action.selected' : 'background.paper',
        cursor: 'pointer',
        transition: 'border-color 0.15s, box-shadow 0.15s',
        '&:hover': { boxShadow: 2 },
        minWidth: 180,
      }}
    >
      <Typography variant="body2" fontWeight={600} noWrap sx={{ fontFamily: theme.custom?.monoFont }}>
        {node.name}
      </Typography>
      <Typography variant="caption" color="text.secondary" sx={{ fontFamily: theme.custom?.monoFont }}>
        {node.version}
      </Typography>
      {node.vuln_count > 0 && (
        <Box sx={{ display: 'flex', gap: 0.5, mt: 0.5, flexWrap: 'wrap' }}>
          {node.critical_count > 0 && (
            <CountChip count={node.critical_count} severity="critical" suffix="C" />
          )}
          {node.high_count > 0 && (
            <CountChip count={node.high_count} severity="high" suffix="H" />
          )}
          {(node.vuln_count - node.critical_count - node.high_count) > 0 && (
            <CountChip count={node.vuln_count - node.critical_count - node.high_count} severity="medium" suffix="M/L" />
          )}
        </Box>
      )}
    </Box>
  );
}

function DependencyGraph() {
  const theme = useTheme();
  const [scanId, setScanId] = useState('');
  const [graphData, setGraphData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [impact, setImpact] = useState(null);
  const [impactLoading, setImpactLoading] = useState(false);

  const loadGraph = async () => {
    if (!scanId.trim()) return;
    setLoading(true);
    setError(null);
    setGraphData(null);
    setSelectedNode(null);
    setImpact(null);

    try {
      const response = await getDependencyGraph(scanId.trim());
      setGraphData(response.data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to load dependency graph');
    }
    setLoading(false);
  };

  const handleNodeClick = async (node) => {
    setSelectedNode(node);
    setImpactLoading(true);
    try {
      const response = await getPackageImpact(scanId, node.name);
      setImpact(response.data);
    } catch {
      setImpact(null);
    }
    setImpactLoading(false);
  };

  const getFilteredNodes = () => {
    if (!graphData?.nodes) return [];
    let nodes = Object.values(graphData.nodes);

    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      nodes = nodes.filter(n =>
        n.name.toLowerCase().includes(q) ||
        n.version.toLowerCase().includes(q)
      );
    }

    if (filterSeverity === 'critical') {
      nodes = nodes.filter(n => n.critical_count > 0);
    } else if (filterSeverity === 'high') {
      nodes = nodes.filter(n => n.high_count > 0 || n.critical_count > 0);
    } else if (filterSeverity === 'vulnerable') {
      nodes = nodes.filter(n => n.vuln_count > 0);
    }

    return nodes.sort((a, b) => {
      // Sort by severity: critical first, then high, then by vuln count
      if (b.critical_count !== a.critical_count) return b.critical_count - a.critical_count;
      if (b.high_count !== a.high_count) return b.high_count - a.high_count;
      return b.vuln_count - a.vuln_count;
    });
  };

  const stats = graphData ? {
    totalPackages: Object.keys(graphData.nodes || {}).length,
    vulnerablePackages: Object.values(graphData.nodes || {}).filter(n => n.vuln_count > 0).length,
    criticalPackages: Object.values(graphData.nodes || {}).filter(n => n.critical_count > 0).length,
    totalEdges: (graphData.edges || []).length,
  } : null;

  return (
    <Box>
      <Box sx={{ mb: 3, display: 'flex', alignItems: 'center', gap: 2 }}>
        <AccountTreeIcon color="primary" sx={{ fontSize: 32 }} />
        <Box>
          <Typography variant="h5" fontWeight={700}>Dependency Graph</Typography>
          <Typography variant="body2" color="text.secondary">
            Visualize package dependencies and vulnerability hotspots
          </Typography>
        </Box>
      </Box>

      {/* Scan ID Input */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Box sx={{ display: 'flex', gap: 2 }}>
          <TextField
            label="Scan ID"
            placeholder="Enter a scan ID..."
            value={scanId}
            onChange={(e) => setScanId(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && loadGraph()}
            fullWidth
            size="small"
          />
          <Button
            variant="contained"
            onClick={loadGraph}
            disabled={loading || !scanId.trim()}
            startIcon={loading ? <CircularProgress size={20} /> : <AccountTreeIcon />}
          >
            Load Graph
          </Button>
        </Box>
      </Paper>

      {error && <Alert severity="error" sx={{ mb: 3 }}>{error}</Alert>}

      {stats && (
        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={6} md={3}>
            <Card variant="outlined">
              <CardContent sx={{ textAlign: 'center', py: 1.5 }}>
                <Typography variant="h4" fontWeight={700} color="primary">{stats.totalPackages}</Typography>
                <Typography variant="caption" color="text.secondary">Total Packages</Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={6} md={3}>
            <Card variant="outlined">
              <CardContent sx={{ textAlign: 'center', py: 1.5 }}>
                <Typography variant="h4" fontWeight={700} color="error">{stats.vulnerablePackages}</Typography>
                <Typography variant="caption" color="text.secondary">Vulnerable</Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={6} md={3}>
            <Card variant="outlined">
              <CardContent sx={{ textAlign: 'center', py: 1.5 }}>
                <Typography variant="h4" fontWeight={700} sx={{ color: severityAccent('critical', theme.palette.mode) }}>{stats.criticalPackages}</Typography>
                <Typography variant="caption" color="text.secondary">Critical</Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={6} md={3}>
            <Card variant="outlined">
              <CardContent sx={{ textAlign: 'center', py: 1.5 }}>
                <Typography variant="h4" fontWeight={700} color="text.secondary">{stats.totalEdges}</Typography>
                <Typography variant="caption" color="text.secondary">Dependencies</Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {graphData && (
        <Grid container spacing={3}>
          {/* Left: Package List */}
          <Grid item xs={12} md={selectedNode ? 7 : 12}>
            <Paper sx={{ p: 2 }}>
              <Box sx={{ display: 'flex', gap: 2, mb: 2, flexWrap: 'wrap' }}>
                <TextField
                  label="Search packages"
                  placeholder="Filter by name..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  size="small"
                  sx={{ flexGrow: 1, minWidth: 200 }}
                  InputProps={{ startAdornment: <SearchIcon sx={{ mr: 1, color: 'text.secondary' }} /> }}
                />
                <FormControl size="small" sx={{ minWidth: 160 }}>
                  <InputLabel>Severity Filter</InputLabel>
                  <Select
                    value={filterSeverity}
                    onChange={(e) => setFilterSeverity(e.target.value)}
                    label="Severity Filter"
                  >
                    <MenuItem value="all">All Packages</MenuItem>
                    <MenuItem value="vulnerable">Vulnerable Only</MenuItem>
                    <MenuItem value="high">High & Critical</MenuItem>
                    <MenuItem value="critical">Critical Only</MenuItem>
                  </Select>
                </FormControl>
              </Box>

              <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1.5, maxHeight: 600, overflow: 'auto' }}>
                {getFilteredNodes().map((node) => (
                  <PackageNode
                    key={node.id}
                    node={node}
                    selected={selectedNode?.id === node.id}
                    onClick={handleNodeClick}
                  />
                ))}
                {getFilteredNodes().length === 0 && (
                  <Alert severity="info" sx={{ width: '100%' }}>No packages match the current filter.</Alert>
                )}
              </Box>
            </Paper>
          </Grid>

          {/* Right: Selected Package Details */}
          {selectedNode && (
            <Grid item xs={12} md={5}>
              <Paper sx={{ p: 2, position: 'sticky', top: 80 }}>
                <Typography variant="h6" fontWeight={700} gutterBottom>
                  {selectedNode.name}
                </Typography>
                <Box sx={{ display: 'flex', gap: 1, mb: 2, flexWrap: 'wrap' }}>
                  <Chip label={`v${selectedNode.version}`} size="small" />
                  <Chip label={selectedNode.type} size="small" variant="outlined" />
                  {selectedNode.has_fix && <Chip label="Fix Available" size="small" color="success" />}
                </Box>

                <Divider sx={{ my: 2 }} />

                {/* Vulnerability Summary */}
                <Typography variant="subtitle2" gutterBottom>Vulnerabilities</Typography>
                {selectedNode.vuln_count === 0 ? (
                  <Typography variant="body2" color="success.main">No vulnerabilities</Typography>
                ) : (
                  <Box sx={{ display: 'flex', gap: 1, mb: 2 }}>
                    {selectedNode.critical_count > 0 && (
                      <SeverityChip severity="critical" count={selectedNode.critical_count} />
                    )}
                    {selectedNode.high_count > 0 && (
                      <SeverityChip severity="high" count={selectedNode.high_count} />
                    )}
                  </Box>
                )}

                {/* Vulnerability Details */}
                {selectedNode.vulnerabilities && selectedNode.vulnerabilities.length > 0 && (
                  <TableContainer sx={{ maxHeight: 200, mb: 2 }}>
                    <Table size="small" stickyHeader>
                      <TableHead>
                        <TableRow>
                          <TableCell>CVE</TableCell>
                          <TableCell>Severity</TableCell>
                          <TableCell>Fix</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {selectedNode.vulnerabilities.map((v, i) => (
                          <TableRow key={i}>
                            <TableCell sx={{ fontFamily: theme.custom?.monoFont, fontSize: '0.75rem' }}>
                              {v.id || v.cve_id || 'N/A'}
                            </TableCell>
                            <TableCell>
                              <SeverityChip severity={v.severity} />
                            </TableCell>
                            <TableCell sx={{ fontSize: '0.75rem', fontFamily: theme.custom?.monoFont }}>
                              {v.fix_version || v.fixedInVersion || '-'}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                )}

                {/* Impact Analysis */}
                <Divider sx={{ my: 2 }} />
                <Typography variant="subtitle2" gutterBottom>Impact Analysis</Typography>
                {impactLoading ? (
                  <CircularProgress size={24} />
                ) : impact ? (
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      Dependents: <strong>{impact.dependent_count || 0}</strong>
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Dependencies: <strong>{impact.dependency_count || 0}</strong>
                    </Typography>
                    {impact.impact_score !== undefined && (
                      <Typography variant="body2" color="text.secondary">
                        Impact Score: <strong>{impact.impact_score}</strong>
                      </Typography>
                    )}
                    {impact.vulnerable_paths && impact.vulnerable_paths.length > 0 && (
                      <Box sx={{ mt: 1 }}>
                        <Typography variant="caption" fontWeight={600}>Vulnerable Paths:</Typography>
                        {impact.vulnerable_paths.slice(0, 5).map((path, i) => (
                          <Typography key={i} variant="caption" display="block" sx={{ ml: 1, fontFamily: 'monospace' }}>
                            {Array.isArray(path) ? path.join(' -> ') : path}
                          </Typography>
                        ))}
                      </Box>
                    )}
                  </Box>
                ) : (
                  <Typography variant="body2" color="text.secondary">Click a package to see impact</Typography>
                )}
              </Paper>
            </Grid>
          )}
        </Grid>
      )}
    </Box>
  );
}

export default DependencyGraph;
