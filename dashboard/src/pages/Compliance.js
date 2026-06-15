import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Paper,
  Typography,
  Grid,
  Card,
  CardContent,
  CardActions,
  Button,
  Chip,
  TextField,
  CircularProgress,
  Alert,
  Divider,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Collapse,
  IconButton,
  LinearProgress,
  alpha,
} from '@mui/material';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import CancelIcon from '@mui/icons-material/Cancel';
import WarningIcon from '@mui/icons-material/Warning';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import SecurityIcon from '@mui/icons-material/Security';
import AssessmentIcon from '@mui/icons-material/Assessment';
import SearchIcon from '@mui/icons-material/Search';
import { getComplianceFrameworks, getComplianceAssessment } from '../api';
import { CardGridSkeleton } from '../components/LoadingSkeletons';

const statusColors = {
  compliant: 'success',
  non_compliant: 'error',
  partial: 'warning',
  pass: 'success',
  fail: 'error',
  warning: 'warning',
};

const statusLabels = {
  compliant: 'Compliant',
  non_compliant: 'Non-Compliant',
  partial: 'Partial',
};

const StatusIcon = ({ status }) => {
  if (status === 'pass' || status === 'compliant') return <CheckCircleIcon color="success" />;
  if (status === 'fail' || status === 'non_compliant') return <CancelIcon color="error" />;
  return <WarningIcon color="warning" />;
};

function ControlItem({ control }) {
  const [expanded, setExpanded] = useState(control.status === 'fail');

  return (
    <ListItem
      sx={{
        flexDirection: 'column',
        alignItems: 'stretch',
        border: 1,
        borderColor: 'divider',
        borderRadius: 1,
        mb: 1,
        p: 0,
      }}
    >
      <Box
        role="button"
        tabIndex={0}
        aria-expanded={expanded}
        aria-label={`${control.control_id} ${control.title}, ${control.status}`}
        onClick={() => setExpanded(!expanded)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            setExpanded(!expanded);
          }
        }}
        sx={{
          display: 'flex',
          alignItems: 'center',
          p: 1.5,
          cursor: 'pointer',
          '&:hover': { bgcolor: 'action.hover' },
        }}
      >
        <ListItemIcon sx={{ minWidth: 36 }}>
          <StatusIcon status={control.status} />
        </ListItemIcon>
        <ListItemText
          primary={
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Chip label={control.control_id} size="small" variant="outlined" />
              <Typography variant="body2" fontWeight={600}>
                {control.title}
              </Typography>
            </Box>
          }
          secondary={control.description}
        />
        <IconButton size="small" tabIndex={-1} aria-hidden sx={{ pointerEvents: 'none' }}>
          {expanded ? <ExpandLessIcon /> : <ExpandMoreIcon />}
        </IconButton>
      </Box>
      <Collapse in={expanded}>
        <Box sx={{ px: 2, pb: 2 }}>
          <Divider sx={{ mb: 1 }} />
          {control.details && (
            <Typography variant="body2" color="success.main" sx={{ mb: 1 }}>
              {control.details}
            </Typography>
          )}
          {control.findings && control.findings.length > 0 && (
            <Box>
              <Typography variant="caption" color="text.secondary" fontWeight={600}>
                Findings:
              </Typography>
              {control.findings.map((f, i) => (
                <Typography key={i} variant="body2" color="error.main" sx={{ ml: 2 }}>
                  - {f}
                </Typography>
              ))}
            </Box>
          )}
        </Box>
      </Collapse>
    </ListItem>
  );
}

function FrameworkCard({ framework, result, onExpand }) {
  const [expanded, setExpanded] = useState(false);
  const passRate = result
    ? Math.round((result.controls_passed / result.controls_total) * 100)
    : 0;

  return (
    <Card
      variant="outlined"
      sx={{
        borderColor: result ? `${statusColors[result.status]}.main` : 'divider',
        borderWidth: result ? 2 : 1,
      }}
    >
      <CardContent>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
          <Box>
            <Typography variant="h6" fontWeight={700}>
              {framework.name}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              {framework.description}
            </Typography>
          </Box>
          {result && (
            <Chip
              icon={<StatusIcon status={result.status} />}
              label={statusLabels[result.status] || result.status}
              color={statusColors[result.status]}
              variant="outlined"
            />
          )}
        </Box>

        {result && (
          <>
            <Box sx={{ mb: 2 }}>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
                <Typography variant="caption" color="text.secondary">
                  Compliance Score
                </Typography>
                <Typography variant="caption" fontWeight={600}>
                  {passRate}%
                </Typography>
              </Box>
              <LinearProgress
                variant="determinate"
                value={passRate}
                color={passRate === 100 ? 'success' : passRate >= 70 ? 'warning' : 'error'}
                sx={{ height: 8, borderRadius: 4 }}
              />
            </Box>

            <Grid container spacing={1}>
              {[
                { value: result.controls_passed, label: 'Passed', color: 'success' },
                { value: result.controls_failed, label: 'Failed', color: 'error' },
                { value: result.controls_warning, label: 'Warning', color: 'warning' },
              ].map((stat) => (
                <Grid item xs={4} key={stat.label}>
                  <Box
                    sx={{
                      textAlign: 'center',
                      p: 1,
                      borderRadius: 1,
                      bgcolor: (theme) => alpha(theme.palette[stat.color].main, 0.12),
                      color: `${stat.color}.main`,
                    }}
                  >
                    <Typography variant="h6" fontWeight={700}>{stat.value}</Typography>
                    <Typography variant="caption" sx={{ color: 'text.secondary' }}>{stat.label}</Typography>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </>
        )}

        {!result && (
          <Typography variant="body2" color="text.secondary">
            {framework.controls_count} controls to evaluate
          </Typography>
        )}
      </CardContent>

      {result && (
        <CardActions>
          <Button
            size="small"
            onClick={() => setExpanded(!expanded)}
            endIcon={expanded ? <ExpandLessIcon /> : <ExpandMoreIcon />}
          >
            {expanded ? 'Hide Controls' : 'View Controls'}
          </Button>
        </CardActions>
      )}

      {result && expanded && (
        <Box sx={{ px: 2, pb: 2 }}>
          <Divider sx={{ mb: 2 }} />
          <List disablePadding>
            {result.controls.map((ctrl) => (
              <ControlItem key={ctrl.control_id} control={ctrl} />
            ))}
          </List>
        </Box>
      )}
    </Card>
  );
}

function Compliance() {
  const [frameworks, setFrameworks] = useState([]);
  const [scanId, setScanId] = useState('');
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [frameworksLoading, setFrameworksLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    loadFrameworks();
  }, []);

  const loadFrameworks = async () => {
    try {
      const response = await getComplianceFrameworks();
      setFrameworks(response.data.frameworks);
    } catch (err) {
      setError('Failed to load compliance frameworks');
    }
    setFrameworksLoading(false);
  };

  const runAssessment = async () => {
    if (!scanId.trim()) return;
    setLoading(true);
    setError(null);
    setResults(null);

    try {
      const response = await getComplianceAssessment(scanId.trim());
      setResults(response.data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to run compliance assessment');
    }
    setLoading(false);
  };

  return (
    <Box>
      <Box sx={{ mb: 3, display: 'flex', alignItems: 'center', gap: 2 }}>
        <SecurityIcon color="primary" sx={{ fontSize: 32 }} />
        <Box>
          <Typography variant="h5" fontWeight={700}>
            Compliance Assessment
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Evaluate container scans against security compliance frameworks
          </Typography>
        </Box>
      </Box>

      {/* Scan ID Input */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Box sx={{ display: 'flex', gap: 2, alignItems: 'flex-start' }}>
          <TextField
            label="Scan ID"
            placeholder="Enter a scan ID to evaluate..."
            value={scanId}
            onChange={(e) => setScanId(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && runAssessment()}
            fullWidth
            size="small"
          />
          <Button
            variant="contained"
            onClick={runAssessment}
            disabled={loading || !scanId.trim()}
            startIcon={loading ? <CircularProgress size={20} /> : <AssessmentIcon />}
          >
            Evaluate
          </Button>
        </Box>
      </Paper>

      {error && <Alert severity="error" sx={{ mb: 3 }}>{error}</Alert>}

      {/* Overall Status */}
      {results && (
        <Alert
          severity={statusColors[results.overall_status] || 'info'}
          sx={{ mb: 3 }}
          icon={<StatusIcon status={results.overall_status} />}
        >
          <Typography fontWeight={600}>
            Overall Status: {statusLabels[results.overall_status] || results.overall_status}
          </Typography>
        </Alert>
      )}

      {/* Framework Cards */}
      {frameworksLoading ? (
        <CardGridSkeleton count={4} height={200} cols={{ xs: 12, md: 6 }} />
      ) : (
        <Grid container spacing={3}>
          {frameworks.map((fw) => (
            <Grid item xs={12} md={6} key={fw.id}>
              <FrameworkCard
                framework={fw}
                result={results?.frameworks?.[fw.id]}
              />
            </Grid>
          ))}
        </Grid>
      )}
    </Box>
  );
}

export default Compliance;
