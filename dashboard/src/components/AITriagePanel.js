import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  Chip,
  CircularProgress,
  Alert,
  Button,
  Card,
  CardContent,
  Divider,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Collapse,
} from '@mui/material';
import AutoFixHighIcon from '@mui/icons-material/AutoFixHigh';
import PriorityHighIcon from '@mui/icons-material/PriorityHigh';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';
import CheckCircleOutlineIcon from '@mui/icons-material/CheckCircleOutline';
import RefreshIcon from '@mui/icons-material/Refresh';
import SmartToyIcon from '@mui/icons-material/SmartToy';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import { getAiTriage, getAiRemediation, getAiTriageStatus } from '../api';

const classificationConfig = {
  critical_action: {
    color: 'error',
    icon: <PriorityHighIcon />,
    label: 'Critical Action Required',
    bgcolor: '#fce4ec',
  },
  high_priority: {
    color: 'warning',
    icon: <WarningAmberIcon />,
    label: 'High Priority',
    bgcolor: '#fff3e0',
  },
  monitor: {
    color: 'info',
    icon: <CheckCircleOutlineIcon />,
    label: 'Monitor',
    bgcolor: '#e3f2fd',
  },
  accept_risk: {
    color: 'success',
    icon: <CheckCircleOutlineIcon />,
    label: 'Accept Risk',
    bgcolor: '#e8f5e9',
  },
};

function AITriagePanel({ scanId }) {
  const [triage, setTriage] = useState(null);
  const [remediation, setRemediation] = useState(null);
  const [loading, setLoading] = useState(false);
  const [remLoading, setRemLoading] = useState(false);
  const [error, setError] = useState(null);
  const [aiEnabled, setAiEnabled] = useState(null);
  const [showRemediation, setShowRemediation] = useState(false);
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    checkAiStatus();
  }, []);

  const checkAiStatus = async () => {
    try {
      const response = await getAiTriageStatus();
      setAiEnabled(response.data.enabled);
    } catch {
      setAiEnabled(false);
    }
    setChecking(false);
  };

  const loadTriage = async (force = false) => {
    setLoading(true);
    setError(null);
    try {
      const response = await getAiTriage(scanId, force);
      if (response.data.error) {
        setError(response.data.error);
      } else {
        setTriage(response.data);
      }
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to generate AI triage');
    }
    setLoading(false);
  };

  const loadRemediation = async () => {
    setRemLoading(true);
    try {
      const response = await getAiRemediation(scanId);
      if (response.data.error) {
        setError(response.data.error);
      } else {
        setRemediation(response.data);
      }
    } catch (err) {
      setError('Failed to generate remediation guide');
    }
    setRemLoading(false);
  };

  if (checking) {
    return <CircularProgress size={24} />;
  }

  if (aiEnabled === false) {
    return (
      <Alert severity="info" icon={<SmartToyIcon />}>
        AI-powered triage is not configured. Set the <code>ANTHROPIC_API_KEY</code> environment
        variable to enable intelligent vulnerability analysis and remediation recommendations.
      </Alert>
    );
  }

  const config = triage ? classificationConfig[triage.risk_classification] || classificationConfig.monitor : null;

  return (
    <Box>
      {/* Generate Button */}
      {!triage && !loading && (
        <Box sx={{ textAlign: 'center', py: 4 }}>
          <SmartToyIcon sx={{ fontSize: 48, color: 'primary.main', mb: 2 }} />
          <Typography variant="h6" gutterBottom>AI-Powered Vulnerability Triage</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            Use Claude to analyze vulnerabilities, assess exploitability, and generate
            prioritized remediation recommendations.
          </Typography>
          <Button
            variant="contained"
            size="large"
            onClick={() => loadTriage()}
            startIcon={<AutoFixHighIcon />}
          >
            Generate AI Triage
          </Button>
        </Box>
      )}

      {loading && (
        <Box sx={{ textAlign: 'center', py: 4 }}>
          <CircularProgress sx={{ mb: 2 }} />
          <Typography variant="body2" color="text.secondary">
            Analyzing vulnerabilities with AI...
          </Typography>
        </Box>
      )}

      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

      {/* Triage Results */}
      {triage && (
        <Box>
          {/* Risk Classification Header */}
          <Paper
            sx={{
              p: 3,
              mb: 3,
              bgcolor: config?.bgcolor || '#f5f5f5',
              border: 2,
              borderColor: `${config?.color || 'grey'}.main`,
            }}
          >
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
              {config?.icon}
              <Chip
                label={config?.label || triage.risk_classification}
                color={config?.color || 'default'}
                sx={{ fontWeight: 700, fontSize: '1rem', py: 2.5, px: 1 }}
              />
              {triage.cached && (
                <Chip label="Cached" size="small" variant="outlined" />
              )}
              <Box sx={{ flexGrow: 1 }} />
              <Button
                size="small"
                startIcon={<RefreshIcon />}
                onClick={() => loadTriage(true)}
              >
                Regenerate
              </Button>
            </Box>

            <Typography variant="body1" sx={{ lineHeight: 1.8 }}>
              {triage.executive_summary}
            </Typography>
          </Paper>

          {/* Prioritized Actions */}
          <Typography variant="h6" fontWeight={700} gutterBottom>
            Prioritized Actions
          </Typography>
          <Box sx={{ mb: 3 }}>
            {triage.prioritized_actions?.map((action, i) => (
              <Card key={i} variant="outlined" sx={{ mb: 1.5 }}>
                <CardContent sx={{ py: 1.5 }}>
                  <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 2 }}>
                    <Chip
                      label={`#${action.priority || i + 1}`}
                      color="primary"
                      size="small"
                      sx={{ fontWeight: 700, minWidth: 36 }}
                    />
                    <Box sx={{ flexGrow: 1 }}>
                      <Typography variant="body2" fontWeight={600}>
                        {action.action}
                      </Typography>
                      {action.packages && action.packages.length > 0 && (
                        <Box sx={{ display: 'flex', gap: 0.5, mt: 0.5, flexWrap: 'wrap' }}>
                          {action.packages.map((pkg, j) => (
                            <Chip key={j} label={pkg} size="small" variant="outlined" sx={{ fontSize: '0.7rem' }} />
                          ))}
                        </Box>
                      )}
                      {action.impact && (
                        <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 0.5 }}>
                          Impact: {action.impact}
                        </Typography>
                      )}
                    </Box>
                    {action.effort && (
                      <Chip
                        label={action.effort}
                        size="small"
                        color={action.effort === 'minimal' ? 'success' : action.effort === 'moderate' ? 'warning' : 'error'}
                        variant="outlined"
                      />
                    )}
                  </Box>
                </CardContent>
              </Card>
            ))}
          </Box>

          {/* Exploit Context */}
          {triage.exploit_context && (
            <Paper sx={{ p: 2, mb: 3, bgcolor: 'grey.50' }}>
              <Typography variant="subtitle2" gutterBottom>Exploit Context</Typography>
              <Typography variant="body2" color="text.secondary">
                {triage.exploit_context}
              </Typography>
            </Paper>
          )}

          {/* Remediation Effort */}
          <Box sx={{ display: 'flex', gap: 2, mb: 3 }}>
            <Chip
              label={`Overall Effort: ${triage.remediation_effort || 'unknown'}`}
              color={
                triage.remediation_effort === 'minimal' ? 'success'
                  : triage.remediation_effort === 'moderate' ? 'warning'
                    : 'error'
              }
            />
            <Typography variant="caption" color="text.secondary" sx={{ alignSelf: 'center' }}>
              Generated: {triage.generated_at ? new Date(triage.generated_at).toLocaleString() : 'N/A'}
            </Typography>
          </Box>

          <Divider sx={{ my: 2 }} />

          {/* AI Remediation Guide */}
          <Button
            onClick={() => {
              if (!remediation && !remLoading) loadRemediation();
              setShowRemediation(!showRemediation);
            }}
            endIcon={showRemediation ? <ExpandLessIcon /> : <ExpandMoreIcon />}
            startIcon={<AutoFixHighIcon />}
          >
            AI Remediation Guide
          </Button>

          <Collapse in={showRemediation}>
            {remLoading ? (
              <Box sx={{ textAlign: 'center', py: 2 }}>
                <CircularProgress size={24} />
              </Box>
            ) : remediation ? (
              <Paper sx={{ p: 2, mt: 1 }}>
                <Typography variant="subtitle1" fontWeight={700} gutterBottom>
                  {remediation.title}
                </Typography>

                {remediation.immediate_actions && (
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="subtitle2" color="error.main">Immediate Actions:</Typography>
                    <List dense>
                      {remediation.immediate_actions.map((action, i) => (
                        <ListItem key={i}>
                          <ListItemIcon sx={{ minWidth: 28 }}>
                            <PriorityHighIcon fontSize="small" color="error" />
                          </ListItemIcon>
                          <ListItemText primary={action} />
                        </ListItem>
                      ))}
                    </List>
                  </Box>
                )}

                {remediation.package_updates && remediation.package_updates.length > 0 && (
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="subtitle2">Package Updates:</Typography>
                    {remediation.package_updates.map((pkg, i) => (
                      <Box key={i} sx={{ ml: 2, mb: 1, p: 1, bgcolor: 'grey.50', borderRadius: 1 }}>
                        <Typography variant="body2" fontWeight={600}>
                          {pkg.package}: {pkg.current} → {pkg.target}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          Fixes {pkg.cves_fixed} CVEs
                        </Typography>
                        {pkg.command && (
                          <Typography variant="caption" display="block" sx={{ fontFamily: 'monospace', mt: 0.5 }}>
                            $ {pkg.command}
                          </Typography>
                        )}
                      </Box>
                    ))}
                  </Box>
                )}

                {remediation.base_image_recommendation && (
                  <Alert severity="info" sx={{ mb: 2 }}>
                    {remediation.base_image_recommendation}
                  </Alert>
                )}

                {remediation.estimated_effort && (
                  <Typography variant="body2" color="text.secondary">
                    Estimated Effort: <strong>{remediation.estimated_effort}</strong>
                  </Typography>
                )}
              </Paper>
            ) : null}
          </Collapse>
        </Box>
      )}
    </Box>
  );
}

export default AITriagePanel;
