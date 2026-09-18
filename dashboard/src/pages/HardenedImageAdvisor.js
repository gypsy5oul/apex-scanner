import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { useLocation } from 'react-router-dom';
import {
  Box,
  Paper,
  Typography,
  Grid,
  Card,
  CardContent,
  CardHeader,
  TextField,
  Button,
  Chip,
  Alert,
  Tabs,
  Tab,
  CircularProgress,
  Stack,
  Divider,
  IconButton,
  Tooltip,
  MenuItem,
  Select,
  FormControl,
  InputLabel,
  Collapse,
  Badge,
  ToggleButton,
  ToggleButtonGroup,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
} from '@mui/material';
import AutoFixHighIcon from '@mui/icons-material/AutoFixHigh';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import DownloadIcon from '@mui/icons-material/Download';
import ErrorOutlineIcon from '@mui/icons-material/ErrorOutline';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';
import InfoOutlinedIcon from '@mui/icons-material/InfoOutlined';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import CancelIcon from '@mui/icons-material/Cancel';
import CloudDownloadIcon from '@mui/icons-material/CloudDownload';
import SendIcon from '@mui/icons-material/Send';
import SecurityIcon from '@mui/icons-material/Security';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import ChatIcon from '@mui/icons-material/Chat';
import CodeIcon from '@mui/icons-material/Code';
import TrendingDownIcon from '@mui/icons-material/TrendingDown';
import CompareIcon from '@mui/icons-material/Compare';
import ViewColumnIcon from '@mui/icons-material/ViewColumn';
import FormatAlignJustifyIcon from '@mui/icons-material/FormatAlignJustify';

import PageHeader from '../components/PageHeader';
import { useToast } from '../components/Feedback';
import {
  diagnoseHardenedApp,
  fetchGitLabDockerfile,
  chatWithAdvisor,
  getAdvisorImages,
} from '../api';
import { MONO_FONT, DISPLAY_FONT } from '../theme/tokens';

const SAMPLE_BROKEN_DOCKERFILE = `# Example legacy Dockerfile failing on hardened base
FROM 10.0.14.79:5009/tools/hardened-images/jdk21:latest

USER root
# Fails: microdnf is stripped on minimal micro bases
RUN microdnf install -y curl git

# Fails: curl is removed (wget is retained)
RUN curl -fsSL -o /app/app.jar https://nexus.internal/repo/my-app.jar

# Fails: root ownership causes permission denied for non-root runtime
COPY . /app

# Fails: non-root cannot bind to privileged port 80 (< 1024)
EXPOSE 80

# Shell format does not forward Linux signals properly
ENTRYPOINT /start.sh
`;

const PROMPT_CHIPS = [
  "Why was curl removed and how do I use wget?",
  "How do I compile native C extensions for python314?",
  "How do I fix permission denied when running as non-root?",
  "How to support JasperReports/PDFBox font rendering?",
  "Show me a GitLab CI pipeline for multi-stage build",
];

// ==============================================================================
// CVE & Attack Surface Reduction Matrix Component
// ==============================================================================
function CVEReductionMatrix({ matrix }) {
  if (!matrix || !matrix.cve_delta) return null;

  const { cve_delta, attack_surface_delta, compliance, source_base_detected, target_base } = matrix;

  return (
    <Card variant="outlined" sx={{ borderRadius: 2, mb: 3, overflow: 'hidden' }}>
      <Box
        sx={{
          p: 2,
          backgroundColor: (theme) =>
            theme.palette.mode === 'dark' ? 'rgba(46, 125, 50, 0.15)' : 'rgba(46, 125, 50, 0.08)',
          borderBottom: 1,
          borderColor: 'success.main',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: 1,
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <TrendingDownIcon color="success" sx={{ fontSize: 28 }} />
          <Box>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: 'success.main' }}>
              Security & Attack Surface Reduction Matrix
            </Typography>
            <Typography variant="caption" color="text.secondary">
              Comparison: <Box component="span" sx={{ fontFamily: MONO_FONT, fontWeight: 600 }}>{source_base_detected}</Box> &rarr; <Box component="span" sx={{ fontFamily: MONO_FONT, fontWeight: 700, color: 'success.main' }}>{target_base}</Box>
            </Typography>
          </Box>
        </Box>
        <Chip
          icon={<VerifiedUserIcon />}
          label={compliance?.overall_posture || "ZERO-TRUST COMPLIANT"}
          color="success"
          size="small"
          sx={{ fontWeight: 700, letterSpacing: 0.5 }}
        />
      </Box>

      <CardContent sx={{ p: 2.5 }}>
        {/* KPI Scorecards */}
        <Grid container spacing={2} sx={{ mb: 3 }}>
          {/* Critical CVEs */}
          <Grid item xs={6} md={3}>
            <Paper
              variant="outlined"
              sx={{
                p: 2,
                borderRadius: 2,
                textAlign: 'center',
                borderColor: 'error.light',
                backgroundColor: (theme) =>
                  theme.palette.mode === 'dark' ? 'rgba(211, 47, 47, 0.06)' : 'rgba(211, 47, 47, 0.03)',
              }}
            >
              <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.5 }}>
                Critical CVEs
              </Typography>
              <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 1, my: 0.5 }}>
                <Typography variant="h5" sx={{ textDecoration: 'line-through', color: 'error.main', fontWeight: 600 }}>
                  {cve_delta.critical.before}
                </Typography>
                <Typography variant="h4" sx={{ color: 'success.main', fontWeight: 800 }}>
                  0
                </Typography>
              </Box>
              <Chip size="small" color="success" label="100% ELIMINATED" sx={{ height: 20, fontSize: '0.68rem', fontWeight: 700 }} />
            </Paper>
          </Grid>

          {/* High CVEs */}
          <Grid item xs={6} md={3}>
            <Paper
              variant="outlined"
              sx={{
                p: 2,
                borderRadius: 2,
                textAlign: 'center',
                borderColor: 'warning.light',
                backgroundColor: (theme) =>
                  theme.palette.mode === 'dark' ? 'rgba(237, 108, 2, 0.06)' : 'rgba(237, 108, 2, 0.03)',
              }}
            >
              <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.5 }}>
                High CVEs
              </Typography>
              <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 1, my: 0.5 }}>
                <Typography variant="h5" sx={{ textDecoration: 'line-through', color: 'warning.main', fontWeight: 600 }}>
                  {cve_delta.high.before}
                </Typography>
                <Typography variant="h4" sx={{ color: 'success.main', fontWeight: 800 }}>
                  0
                </Typography>
              </Box>
              <Chip size="small" color="success" label="100% ELIMINATED" sx={{ height: 20, fontSize: '0.68rem', fontWeight: 700 }} />
            </Paper>
          </Grid>

          {/* Total CVEs */}
          <Grid item xs={6} md={3}>
            <Paper
              variant="outlined"
              sx={{
                p: 2,
                borderRadius: 2,
                textAlign: 'center',
                borderColor: 'primary.light',
                backgroundColor: (theme) =>
                  theme.palette.mode === 'dark' ? 'rgba(25, 118, 210, 0.06)' : 'rgba(25, 118, 210, 0.03)',
              }}
            >
              <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.5 }}>
                Total Vulnerabilities
              </Typography>
              <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 1, my: 0.5 }}>
                <Typography variant="h5" sx={{ textDecoration: 'line-through', color: 'text.secondary', fontWeight: 600 }}>
                  {cve_delta.total.before}
                </Typography>
                <Typography variant="h4" sx={{ color: 'primary.main', fontWeight: 800 }}>
                  {cve_delta.total.after}
                </Typography>
              </Box>
              <Chip
                size="small"
                color="primary"
                label={`-${cve_delta.total.eliminated} CVEs (${cve_delta.total.reduction_pct}%)`}
                sx={{ height: 20, fontSize: '0.68rem', fontWeight: 700 }}
              />
            </Paper>
          </Grid>

          {/* Attack Surface & Size */}
          <Grid item xs={6} md={3}>
            <Paper
              variant="outlined"
              sx={{
                p: 2,
                borderRadius: 2,
                textAlign: 'center',
                borderColor: 'divider',
              }}
            >
              <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.5 }}>
                OS Packages
              </Typography>
              <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 1, my: 0.5 }}>
                <Typography variant="h5" sx={{ textDecoration: 'line-through', color: 'text.secondary', fontWeight: 600 }}>
                  {attack_surface_delta?.packages?.before || 480}
                </Typography>
                <Typography variant="h4" sx={{ color: 'text.primary', fontWeight: 800 }}>
                  {attack_surface_delta?.packages?.after || 58}
                </Typography>
              </Box>
              <Chip
                size="small"
                variant="outlined"
                color="success"
                label={`-${attack_surface_delta?.packages?.reduction_pct || 88}% attack surface`}
                sx={{ height: 20, fontSize: '0.68rem', fontWeight: 700 }}
              />
            </Paper>
          </Grid>
        </Grid>

        {/* Attack Surface & Compliance Comparison Table */}
        <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
          Attack Surface & CIS Benchmark Hardening Breakdown:
        </Typography>
        <TableContainer component={Paper} variant="outlined" sx={{ borderRadius: 1.5 }}>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ backgroundColor: 'action.hover' }}>
                <TableCell sx={{ fontWeight: 700, width: '25%' }}>Hardening Dimension</TableCell>
                <TableCell sx={{ fontWeight: 700, width: '35%' }}>Legacy Container State</TableCell>
                <TableCell sx={{ fontWeight: 700, width: '40%' }}>Hardened Architecture State</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              <TableRow hover>
                <TableCell sx={{ fontWeight: 600 }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75 }}>
                    <CheckCircleIcon color="success" sx={{ fontSize: 16 }} />
                    CIS 4.1 Non-Root User
                  </Box>
                </TableCell>
                <TableCell sx={{ color: 'error.main', fontFamily: MONO_FONT, fontSize: '0.8rem' }}>
                  Root (UID 0) execution
                </TableCell>
                <TableCell sx={{ color: 'success.main', fontWeight: 600, fontFamily: MONO_FONT, fontSize: '0.8rem' }}>
                  Non-Root (UID 10001 / appuser) enforced
                </TableCell>
              </TableRow>

              <TableRow hover>
                <TableCell sx={{ fontWeight: 600 }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75 }}>
                    <CheckCircleIcon color="success" sx={{ fontSize: 16 }} />
                    CIS 4.3 Package Managers
                  </Box>
                </TableCell>
                <TableCell sx={{ color: 'error.main', fontFamily: MONO_FONT, fontSize: '0.8rem' }}>
                  dnf / microdnf / apt / rpm present
                </TableCell>
                <TableCell sx={{ color: 'success.main', fontWeight: 600, fontFamily: MONO_FONT, fontSize: '0.8rem' }}>
                  0 Package Managers (Immutable rootfs)
                </TableCell>
              </TableRow>

              <TableRow hover>
                <TableCell sx={{ fontWeight: 600 }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75 }}>
                    <CheckCircleIcon color="success" sx={{ fontSize: 16 }} />
                    Build Tools & Compilers
                  </Box>
                </TableCell>
                <TableCell sx={{ color: 'warning.main', fontFamily: MONO_FONT, fontSize: '0.8rem' }}>
                  gcc / make / git in runtime image
                </TableCell>
                <TableCell sx={{ color: 'success.main', fontWeight: 600, fontFamily: MONO_FONT, fontSize: '0.8rem' }}>
                  0 in runtime (Isolated in AS builder stage)
                </TableCell>
              </TableRow>

              <TableRow hover>
                <TableCell sx={{ fontWeight: 600 }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75 }}>
                    <CheckCircleIcon color="success" sx={{ fontSize: 16 }} />
                    Network Tools & Vectors
                  </Box>
                </TableCell>
                <TableCell sx={{ color: 'warning.main', fontFamily: MONO_FONT, fontSize: '0.8rem' }}>
                  curl, ssh, rsync, telnet present
                </TableCell>
                <TableCell sx={{ color: 'success.main', fontWeight: 600, fontFamily: MONO_FONT, fontSize: '0.8rem' }}>
                  Minimal wget only (No outbound ssh/rsync)
                </TableCell>
              </TableRow>

              <TableRow hover>
                <TableCell sx={{ fontWeight: 600 }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75 }}>
                    <CheckCircleIcon color="success" sx={{ fontSize: 16 }} />
                    Image Size & Network Load
                  </Box>
                </TableCell>
                <TableCell sx={{ color: 'text.secondary', fontFamily: MONO_FONT, fontSize: '0.8rem' }}>
                  ~{attack_surface_delta?.image_size_est?.before_mb || 470} MB
                </TableCell>
                <TableCell sx={{ color: 'success.main', fontWeight: 600, fontFamily: MONO_FONT, fontSize: '0.8rem' }}>
                  ~{attack_surface_delta?.image_size_est?.after_mb || 180} MB (-{attack_surface_delta?.image_size_est?.reduction_pct || 62}% storage saved)
                </TableCell>
              </TableRow>
            </TableBody>
          </Table>
        </TableContainer>
      </CardContent>
    </Card>
  );
}

// ==============================================================================
// Visual Side-by-Side & Unified Diff Viewer Component
// ==============================================================================
function VisualDiffViewer({ diffData, originalText, remediatedText, onCopy, onDownload }) {
  const [diffMode, setDiffMode] = useState('split'); // 'split' | 'unified' | 'raw'
  const toast = useToast();

  const sideBySideRows = diffData?.side_by_side || [];
  const unifiedDiffText = diffData?.unified_diff || '';
  const stats = diffData?.stats || { added_lines: 0, removed_lines: 0 };

  const handleCopyDiff = () => {
    navigator.clipboard.writeText(unifiedDiffText);
    toast.show('Unified diff copied to clipboard!', { severity: 'success' });
  };

  return (
    <Card variant="outlined" sx={{ borderRadius: 2 }}>
      {/* Header Toolbar */}
      <Box
        sx={{
          p: 2,
          borderBottom: 1,
          borderColor: 'divider',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: 1.5,
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
          <Typography variant="h6" sx={{ fontWeight: 600 }}>
            Visual Dockerfile Diff
          </Typography>
          <Chip size="small" color="success" label={`+${stats.added_lines} additions`} sx={{ fontWeight: 600 }} />
          <Chip size="small" color="error" label={`-${stats.removed_lines} deletions`} sx={{ fontWeight: 600 }} />
        </Box>

        <Stack direction="row" spacing={1.5} alignItems="center">
          <ToggleButtonGroup
            value={diffMode}
            exclusive
            onChange={(_, val) => val && setDiffMode(val)}
            size="small"
            aria-label="diff mode"
          >
            <ToggleButton value="split" aria-label="Side by side">
              <Tooltip title="Side-by-Side Split View">
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                  <ViewColumnIcon fontSize="small" />
                  <Typography variant="caption" sx={{ display: { xs: 'none', sm: 'inline' } }}>Side-by-Side</Typography>
                </Box>
              </Tooltip>
            </ToggleButton>
            <ToggleButton value="unified" aria-label="Unified Diff">
              <Tooltip title="Unified Patch View">
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                  <FormatAlignJustifyIcon fontSize="small" />
                  <Typography variant="caption" sx={{ display: { xs: 'none', sm: 'inline' } }}>Unified</Typography>
                </Box>
              </Tooltip>
            </ToggleButton>
            <ToggleButton value="raw" aria-label="Raw Remediated">
              <Tooltip title="Raw Remediated Dockerfile">
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                  <CodeIcon fontSize="small" />
                  <Typography variant="caption" sx={{ display: { xs: 'none', sm: 'inline' } }}>Raw</Typography>
                </Box>
              </Tooltip>
            </ToggleButton>
          </ToggleButtonGroup>

          <Tooltip title="Copy Remediated Dockerfile">
            <Button
              variant="outlined"
              size="small"
              startIcon={<ContentCopyIcon />}
              onClick={() => onCopy(remediatedText, 'Remediated Dockerfile')}
            >
              Copy
            </Button>
          </Tooltip>

          <Tooltip title="Download Dockerfile">
            <Button
              variant="contained"
              size="small"
              startIcon={<DownloadIcon />}
              onClick={() => onDownload(remediatedText)}
            >
              Download
            </Button>
          </Tooltip>
        </Stack>
      </Box>

      {/* Mode 1: Side-by-Side Split View */}
      {diffMode === 'split' && (
        <Box sx={{ overflowX: 'auto', maxHeight: 560 }}>
          <Table size="small" sx={{ tableLayout: 'fixed', width: '100%', borderCollapse: 'collapse' }}>
            <TableHead>
              <TableRow sx={{ backgroundColor: 'action.hover' }}>
                <TableCell sx={{ width: '50%', fontWeight: 700, borderRight: 1, borderColor: 'divider', py: 1 }}>
                  Original Application Dockerfile
                </TableCell>
                <TableCell sx={{ width: '50%', fontWeight: 700, py: 1, color: 'success.main' }}>
                  Remediated Hardened Dockerfile
                </TableCell>
              </TableRow>
            </TableHead>
            <TableBody sx={{ fontFamily: MONO_FONT, fontSize: '0.8rem' }}>
              {sideBySideRows.map((row, idx) => {
                const isDelete = row.type === 'delete';
                const isInsert = row.type === 'insert';
                const isReplace = row.type === 'replace';

                // Left cell background
                const leftBg =
                  isDelete || (isReplace && row.left_text)
                    ? 'rgba(239, 68, 68, 0.14)'
                    : 'transparent';

                // Right cell background
                const rightBg =
                  isInsert || (isReplace && row.right_text)
                    ? 'rgba(34, 197, 94, 0.14)'
                    : 'transparent';

                return (
                  <TableRow key={idx} sx={{ '&:hover': { opacity: 0.9 } }}>
                    {/* Left Side (Original) */}
                    <TableCell
                      sx={{
                        p: 0.5,
                        width: '50%',
                        borderRight: 1,
                        borderColor: 'divider',
                        backgroundColor: leftBg,
                        verticalAlign: 'top',
                      }}
                    >
                      <Box sx={{ display: 'flex', alignItems: 'flex-start' }}>
                        <Typography
                          variant="caption"
                          sx={{
                            fontFamily: MONO_FONT,
                            color: 'text.disabled',
                            width: 32,
                            textAlign: 'right',
                            pr: 1,
                            userSelect: 'none',
                            flexShrink: 0,
                          }}
                        >
                          {row.left_num || ''}
                        </Typography>
                        <Box
                          component="pre"
                          sx={{
                            m: 0,
                            fontFamily: MONO_FONT,
                            fontSize: '0.8rem',
                            whiteSpace: 'pre-wrap',
                            wordBreak: 'break-all',
                            color: (isDelete || (isReplace && row.left_text)) ? 'error.main' : 'text.primary',
                          }}
                        >
                          {(isDelete || (isReplace && row.left_text)) && (
                            <Box component="span" sx={{ fontWeight: 700, mr: 0.5, userSelect: 'none' }}>-</Box>
                          )}
                          {row.left_text}
                        </Box>
                      </Box>
                    </TableCell>

                    {/* Right Side (Remediated) */}
                    <TableCell
                      sx={{
                        p: 0.5,
                        width: '50%',
                        backgroundColor: rightBg,
                        verticalAlign: 'top',
                      }}
                    >
                      <Box sx={{ display: 'flex', alignItems: 'flex-start' }}>
                        <Typography
                          variant="caption"
                          sx={{
                            fontFamily: MONO_FONT,
                            color: 'text.disabled',
                            width: 32,
                            textAlign: 'right',
                            pr: 1,
                            userSelect: 'none',
                            flexShrink: 0,
                          }}
                        >
                          {row.right_num || ''}
                        </Typography>
                        <Box
                          component="pre"
                          sx={{
                            m: 0,
                            fontFamily: MONO_FONT,
                            fontSize: '0.8rem',
                            whiteSpace: 'pre-wrap',
                            wordBreak: 'break-all',
                            color: (isInsert || (isReplace && row.right_text)) ? 'success.main' : 'text.primary',
                          }}
                        >
                          {(isInsert || (isReplace && row.right_text)) && (
                            <Box component="span" sx={{ fontWeight: 700, mr: 0.5, userSelect: 'none' }}>+</Box>
                          )}
                          {row.right_text}
                        </Box>
                      </Box>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </Box>
      )}

      {/* Mode 2: Unified Diff View */}
      {diffMode === 'unified' && (
        <Box sx={{ p: 2, maxHeight: 560, overflowY: 'auto' }}>
          <Box sx={{ display: 'flex', justifyContent: 'flex-end', mb: 1 }}>
            <Button size="small" variant="text" onClick={handleCopyDiff} startIcon={<ContentCopyIcon />}>
              Copy Unified Diff
            </Button>
          </Box>
          <Paper
            variant="outlined"
            sx={{
              p: 2,
              backgroundColor: (theme) =>
                theme.palette.mode === 'dark' ? 'rgba(0, 0, 0, 0.4)' : 'rgba(0, 0, 0, 0.03)',
              fontFamily: MONO_FONT,
              fontSize: '0.82rem',
              lineHeight: 1.5,
              overflowX: 'auto',
            }}
          >
            {unifiedDiffText.split('\n').map((line, idx) => {
              let color = 'text.primary';
              let bg = 'transparent';
              if (line.startsWith('+') && !line.startsWith('+++')) {
                color = 'success.main';
                bg = 'rgba(34, 197, 94, 0.12)';
              } else if (line.startsWith('-') && !line.startsWith('---')) {
                color = 'error.main';
                bg = 'rgba(239, 68, 68, 0.12)';
              } else if (line.startsWith('@@')) {
                color = 'primary.main';
                bg = 'rgba(25, 118, 210, 0.08)';
              }
              return (
                <Box key={idx} sx={{ backgroundColor: bg, px: 0.5, py: 0.1, whiteSpace: 'pre-wrap' }}>
                  <Typography component="span" sx={{ fontFamily: MONO_FONT, fontSize: '0.8rem', color }}>
                    {line}
                  </Typography>
                </Box>
              );
            })}
          </Paper>
        </Box>
      )}

      {/* Mode 3: Raw Remediated View */}
      {diffMode === 'raw' && (
        <Box sx={{ p: 2 }}>
          <TextField
            multiline
            rows={15}
            fullWidth
            value={remediatedText}
            InputProps={{ readOnly: true }}
            sx={{
              fontFamily: MONO_FONT,
              '& textarea': { fontFamily: MONO_FONT, fontSize: '0.82rem', lineHeight: 1.4 },
            }}
          />
        </Box>
      )}
    </Card>
  );
}

// ==============================================================================
// Main HardenedImageAdvisor Page
// ==============================================================================
export default function HardenedImageAdvisor() {
  const toast = useToast();
  const location = useLocation();

  // URL query params (e.g. ?base=jdk21)
  const searchParams = useMemo(() => new URLSearchParams(location.search), [location.search]);
  const initialBase = searchParams.get('base') || 'jdk21';

  // Base image selection
  const [images, setImages] = useState([]);
  const [selectedBase, setSelectedBase] = useState(initialBase);
  const [loadingImages, setLoadingImages] = useState(true);

  // Active top-level mode: 0 = Diagnose & Remediate, 1 = Interactive Chat
  const [mainTab, setMainTab] = useState(0);

  // Input state
  const [inputTab, setInputTab] = useState(0); // 0 = Paste, 1 = GitLab
  const [dockerfileContent, setDockerfileContent] = useState(SAMPLE_BROKEN_DOCKERFILE);
  const [buildLogs, setBuildLogs] = useState('');
  const [showLogs, setShowLogs] = useState(false);

  // GitLab state
  const [glProject, setGlProject] = useState('14729');
  const [glRef, setGlRef] = useState('development');
  const [glPath, setGlPath] = useState('Dockerfile');
  const [fetchingGl, setFetchingGl] = useState(false);

  // Diagnosis state
  const [diagnosing, setDiagnosing] = useState(false);
  const [diagnosisResult, setDiagnosisResult] = useState(null);

  // Chat state
  const [chatSessionId] = useState(() => `session_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`);
  const [chatMessages, setChatMessages] = useState([
    {
      role: 'assistant',
      content: 'Hello! I am your Enterprise Hardened Image Migration Advisor.\n\nApproved base images are permanently hardened and immutable to maintain a zero-vulnerability security posture. Share your Application Dockerfile or ask any questions regarding missing tools, permissions, or multi-stage builds.',
    }
  ]);
  const [chatInput, setChatInput] = useState('');
  const [sendingChat, setSendingChat] = useState(false);

  // Load catalog on mount
  useEffect(() => {
    async function loadCatalog() {
      try {
        const resp = await getAdvisorImages();
        const list = resp.data?.images || [];
        setImages(list);
        if (initialBase && list.some(img => img.name === initialBase)) {
          setSelectedBase(initialBase);
        } else if (list.length > 0) {
          setSelectedBase(list[0].name);
        }
      } catch (err) {
        console.warn('Failed to load advisor images catalog:', err);
      } finally {
        setLoadingImages(false);
      }
    }
    loadCatalog();
  }, [initialBase]);

  // Fetch Dockerfile from GitLab
  const handleFetchFromGitLab = async () => {
    if (!glProject.trim()) {
      toast.show('Please enter a GitLab Project ID or Path (e.g. devops/my-app)', { severity: 'warning' });
      return;
    }
    setFetchingGl(true);
    try {
      const resp = await fetchGitLabDockerfile({
        project_target: glProject.trim(),
        file_path: glPath.trim() || 'Dockerfile',
        ref: glRef.trim() || undefined,
      });
      if (resp.data?.content) {
        setDockerfileContent(resp.data.content);
        toast.show(`Successfully fetched ${glPath} from ${resp.data.project} (${resp.data.ref})`, { severity: 'success' });
        setInputTab(0); // Switch to editor tab to show content
      } else {
        toast.show('File was empty or not found', { severity: 'error' });
      }
    } catch (err) {
      toast.show(err.response?.data?.detail || 'Failed to fetch file from GitLab', { severity: 'error' });
    } finally {
      setFetchingGl(false);
    }
  };

  // Run Diagnosis
  const handleDiagnose = async () => {
    if (!dockerfileContent.trim()) {
      toast.show('Please provide application Dockerfile content to analyze', { severity: 'warning' });
      return;
    }
    setDiagnosing(true);
    setDiagnosisResult(null);
    try {
      const resp = await diagnoseHardenedApp({
        base_image: selectedBase,
        dockerfile_content: dockerfileContent,
        build_error_logs: buildLogs.trim() || undefined,
        gitlab_project: inputTab === 1 ? glProject : undefined,
        gitlab_ref: inputTab === 1 ? glRef : undefined,
      });
      setDiagnosisResult(resp.data);
      toast.show('Compatibility diagnosis complete! Visual diff & reduction matrix generated.', { severity: 'success' });
    } catch (err) {
      toast.show(err.response?.data?.detail || 'Failed to diagnose Dockerfile', { severity: 'error' });
    } finally {
      setDiagnosing(false);
    }
  };

  // Copy code helper
  const handleCopyCode = (text, label) => {
    navigator.clipboard.writeText(text);
    toast.show(`${label} copied to clipboard!`, { severity: 'success' });
  };

  // Download Dockerfile helper
  const handleDownloadDockerfile = (text, filename = 'Dockerfile') => {
    const element = document.createElement('a');
    const file = new Blob([text], { type: 'text/plain' });
    element.href = URL.createObjectURL(file);
    element.download = filename;
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
    toast.show(`Downloaded ${filename}`, { severity: 'success' });
  };

  // Send Chat message
  const handleSendChat = async (messageText = null) => {
    const textToSend = messageText || chatInput;
    if (!textToSend.trim()) return;

    const userMsg = { role: 'user', content: textToSend };
    setChatMessages(prev => [...prev, userMsg]);
    if (!messageText) setChatInput('');
    setSendingChat(true);

    try {
      const resp = await chatWithAdvisor({
        session_id: chatSessionId,
        user_message: textToSend,
        base_image: selectedBase,
        dockerfile_content: dockerfileContent,
      });
      const assistantMsg = {
        role: 'assistant',
        content: resp.data?.reply || 'No response received.',
      };
      setChatMessages(prev => [...prev, assistantMsg]);
    } catch (err) {
      setChatMessages(prev => [
        ...prev,
        {
          role: 'assistant',
          content: `Error communicating with advisor: ${err.response?.data?.detail || err.message}`,
        }
      ]);
    } finally {
      setSendingChat(false);
    }
  };

  const selectedImageMeta = useMemo(() => {
    return images.find(i => i.name === selectedBase) || null;
  }, [images, selectedBase]);

  return (
    <Box sx={{ maxWidth: 1400, mx: 'auto', pb: 6 }}>
      <PageHeader
        title="App Migration Advisor"
        subtitle="Diagnose application Dockerfiles, resolve missing commands, entrypoints & permissions, and generate production-grade multi-stage builds on top of immutable hardened base images."
      />

      {/* Mandatory Enterprise Security Directive Banner */}
      <Alert
        severity="info"
        icon={<SecurityIcon />}
        sx={{
          mb: 3,
          borderRadius: 2,
          border: '1px solid',
          borderColor: 'info.main',
          '& .MuiAlert-message': { width: '100%' },
        }}
      >
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 1 }}>
          <Box>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, letterSpacing: 0.5 }}>
              Enterprise Zero-Trust Security Directive
            </Typography>
            <Typography variant="body2" sx={{ color: 'text.secondary', mt: 0.25 }}>
              Hardened base images are strictly minimal, audited, and immutable. Tools like package managers, curl, and compilers are stripped by design to eliminate CVEs. All adaptations MUST occur on the application side.
            </Typography>
          </Box>
          <Chip
            size="small"
            label="Base Image is Immutable"
            color="info"
            variant="filled"
            sx={{ fontWeight: 600 }}
          />
        </Box>
      </Alert>

      {/* Main Tab Controls */}
      <Paper sx={{ mb: 3, borderRadius: 2 }}>
        <Tabs
          value={mainTab}
          onChange={(_, val) => setMainTab(val)}
          sx={{ px: 2, borderBottom: 1, borderColor: 'divider' }}
        >
          <Tab icon={<AutoFixHighIcon />} iconPosition="start" label="Dockerfile Diagnostic & Generator" />
          <Tab
            icon={
              <Badge badgeContent={chatMessages.length > 1 ? chatMessages.length - 1 : 0} color="primary">
                <ChatIcon />
              </Badge>
            }
            iconPosition="start"
            label="Interactive AI Advisor"
          />
        </Tabs>

        {mainTab === 0 ? (
          <Box sx={{ p: 3 }}>
            <Grid container spacing={3}>
              {/* Left Column: Target Base & Inputs */}
              <Grid item xs={12} lg={5}>
                <Card variant="outlined" sx={{ borderRadius: 2, height: '100%' }}>
                  <CardHeader
                    title="1. Select Target Hardened Base Image"
                    subheader="Choose the enterprise hardened runtime your app will run on"
                    titleTypographyProps={{ variant: 'h6', fontWeight: 600 }}
                  />
                  <CardContent sx={{ pt: 0 }}>
                    <FormControl fullWidth size="small" sx={{ mb: 2 }}>
                      <InputLabel id="select-base-label">Hardened Base Image</InputLabel>
                      <Select
                        labelId="select-base-label"
                        value={selectedBase}
                        label="Hardened Base Image"
                        onChange={(e) => setSelectedBase(e.target.value)}
                        disabled={loadingImages}
                      >
                        {images.map((img) => (
                          <MenuItem key={img.name} value={img.name}>
                            <Box sx={{ display: 'flex', justifyContent: 'space-between', width: '100%', alignItems: 'center' }}>
                              <Typography variant="body2" sx={{ fontWeight: 600, fontFamily: MONO_FONT }}>
                                {img.name}
                              </Typography>
                              <Typography variant="caption" color="text.secondary">
                                {img.type}
                              </Typography>
                            </Box>
                          </MenuItem>
                        ))}
                      </Select>
                    </FormControl>

                    {selectedImageMeta && (
                      <Paper variant="outlined" sx={{ p: 1.5, mb: 3, backgroundColor: 'action.hover', borderRadius: 1.5 }}>
                        <Typography variant="caption" sx={{ fontWeight: 700, color: 'text.secondary', display: 'block' }}>
                          PULL URL:
                        </Typography>
                        <Typography variant="body2" sx={{ fontFamily: MONO_FONT, fontSize: '0.78rem', mb: 1, wordBreak: 'break-all' }}>
                          {selectedImageMeta.pull_url}
                        </Typography>

                        {selectedImageMeta.changes?.available_commands && (
                          <Box sx={{ mb: 1 }}>
                            <Typography variant="caption" sx={{ fontWeight: 700, color: 'text.secondary', display: 'block', mb: 0.5 }}>
                              AVAILABLE IN RUNTIME:
                            </Typography>
                            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                              {selectedImageMeta.changes.available_commands.map((cmd) => (
                                <Chip key={cmd} label={cmd} size="small" color="success" variant="outlined" sx={{ height: 20, fontSize: '0.7rem' }} />
                              ))}
                            </Box>
                          </Box>
                        )}

                        {selectedImageMeta.changes?.removed_notable && (
                          <Box>
                            <Typography variant="caption" sx={{ fontWeight: 700, color: 'text.secondary', display: 'block', mb: 0.5 }}>
                              STRIPPED TOOLS (NOT INSTALLABLE):
                            </Typography>
                            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                              {Object.entries(selectedImageMeta.changes.removed_notable).flatMap(([cat, list]) =>
                                (Array.isArray(list) ? list : []).slice(0, 4).map((t) => (
                                  <Chip key={`${cat}-${t}`} label={t} size="small" color="error" variant="outlined" sx={{ height: 20, fontSize: '0.7rem' }} />
                                ))
                              )}
                            </Box>
                          </Box>
                        )}
                      </Paper>
                    )}

                    <Divider sx={{ my: 2 }} />

                    <Typography variant="h6" sx={{ fontWeight: 600, mb: 1.5 }}>
                      2. Application Dockerfile Source
                    </Typography>

                    <Tabs
                      value={inputTab}
                      onChange={(_, v) => setInputTab(v)}
                      sx={{ minHeight: 36, mb: 2 }}
                    >
                      <Tab label="Paste Dockerfile" sx={{ minHeight: 36, py: 0.5, fontSize: '0.85rem' }} />
                      <Tab label="Fetch from GitLab" sx={{ minHeight: 36, py: 0.5, fontSize: '0.85rem' }} />
                    </Tabs>

                    {inputTab === 0 ? (
                      <Box>
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                          <Typography variant="caption" color="text.secondary">
                            Paste your current Dockerfile below:
                          </Typography>
                          <Button
                            size="small"
                            variant="text"
                            onClick={() => setDockerfileContent(SAMPLE_BROKEN_DOCKERFILE)}
                            sx={{ fontSize: '0.75rem', py: 0 }}
                          >
                            Load Broken Sample
                          </Button>
                        </Box>
                        <TextField
                          multiline
                          rows={12}
                          fullWidth
                          value={dockerfileContent}
                          onChange={(e) => setDockerfileContent(e.target.value)}
                          placeholder="FROM ...\nRUN ...\nCOPY ...\nCMD ..."
                          sx={{
                            fontFamily: MONO_FONT,
                            '& textarea': { fontFamily: MONO_FONT, fontSize: '0.82rem', lineHeight: 1.4 },
                          }}
                        />
                      </Box>
                    ) : (
                      <Box sx={{ p: 1 }}>
                        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                          Connect to your application's GitLab repository to pull the Dockerfile directly.
                        </Typography>
                        <TextField
                          fullWidth
                          size="small"
                          label="GitLab Project ID or Path"
                          placeholder="e.g. 14729 or devops/my-app"
                          value={glProject}
                          onChange={(e) => setGlProject(e.target.value)}
                          sx={{ mb: 1.5 }}
                        />
                        <Grid container spacing={1.5} sx={{ mb: 2 }}>
                          <Grid item xs={6}>
                            <TextField
                              fullWidth
                              size="small"
                              label="Branch / Ref"
                              placeholder="e.g. development or main"
                              value={glRef}
                              onChange={(e) => setGlRef(e.target.value)}
                            />
                          </Grid>
                          <Grid item xs={6}>
                            <TextField
                              fullWidth
                              size="small"
                              label="File Path"
                              placeholder="Dockerfile"
                              value={glPath}
                              onChange={(e) => setGlPath(e.target.value)}
                            />
                          </Grid>
                        </Grid>
                        <Button
                          fullWidth
                          variant="outlined"
                          startIcon={fetchingGl ? <CircularProgress size={16} /> : <CloudDownloadIcon />}
                          onClick={handleFetchFromGitLab}
                          disabled={fetchingGl}
                        >
                          {fetchingGl ? 'Fetching from GitLab...' : 'Fetch Dockerfile'}
                        </Button>
                      </Box>
                    )}

                    <Box sx={{ mt: 2 }}>
                      <Button
                        size="small"
                        color="inherit"
                        onClick={() => setShowLogs(!showLogs)}
                        endIcon={showLogs ? <ExpandLessIcon /> : <ExpandMoreIcon />}
                        sx={{ textTransform: 'none', px: 0 }}
                      >
                        {showLogs ? 'Hide Build Error Logs' : '+ Add Build or Startup Error Logs (Optional)'}
                      </Button>
                      <Collapse in={showLogs}>
                        <TextField
                          multiline
                          rows={4}
                          fullWidth
                          size="small"
                          value={buildLogs}
                          onChange={(e) => setBuildLogs(e.target.value)}
                          placeholder="Paste errors (e.g. microdnf: command not found, Permission denied: /app/logs, curl: not found)..."
                          sx={{
                            mt: 1,
                            '& textarea': { fontFamily: MONO_FONT, fontSize: '0.78rem' },
                          }}
                        />
                      </Collapse>
                    </Box>

                    <Button
                      fullWidth
                      variant="contained"
                      color="primary"
                      size="large"
                      startIcon={diagnosing ? <CircularProgress size={20} color="inherit" /> : <AutoFixHighIcon />}
                      onClick={handleDiagnose}
                      disabled={diagnosing}
                      sx={{ mt: 3, py: 1.2, fontWeight: 700 }}
                    >
                      {diagnosing ? 'Diagnosing & Generating Solution...' : 'Diagnose & Generate Fixed Dockerfile'}
                    </Button>
                  </CardContent>
                </Card>
              </Grid>

              {/* Right Column: Results Panel */}
              <Grid item xs={12} lg={7}>
                {!diagnosisResult && !diagnosing && (
                  <Card variant="outlined" sx={{ borderRadius: 2, height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', p: 4, minHeight: 480 }}>
                    <Box sx={{ textAlign: 'center', maxWidth: 450 }}>
                      <AutoFixHighIcon sx={{ fontSize: 52, color: 'text.disabled', mb: 2 }} />
                      <Typography variant="h6" color="text.secondary" gutterBottom>
                        Ready to Diagnose
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        Click "Diagnose & Generate Fixed Dockerfile" to run static and AI analysis against the hardened base image. You will receive an interactive visual side-by-side diff, a comprehensive CVE & attack surface reduction matrix, and a production-grade multi-stage Dockerfile.
                      </Typography>
                    </Box>
                  </Card>
                )}

                {diagnosing && (
                  <Card variant="outlined" sx={{ borderRadius: 2, height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', p: 4, minHeight: 480 }}>
                    <Box sx={{ textAlign: 'center' }}>
                      <CircularProgress size={48} sx={{ mb: 2 }} />
                      <Typography variant="h6" gutterBottom>
                        Analyzing Application Dockerfile...
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        Evaluating missing binaries, user permissions, entrypoint signal handling, computing CVE reduction delta, and generating side-by-side visual diffs.
                      </Typography>
                    </Box>
                  </Card>
                )}

                {diagnosisResult && (
                  <Stack spacing={2.5}>
                    {/* Executive Summary Card */}
                    <Card variant="outlined" sx={{ borderRadius: 2 }}>
                      <CardHeader
                        title="Diagnosis Summary"
                        action={
                          <Stack direction="row" spacing={1}>
                            <Chip size="small" color="error" label={`${diagnosisResult.issue_counts?.error || 0} Errors`} />
                            <Chip size="small" color="warning" label={`${diagnosisResult.issue_counts?.warning || 0} Warnings`} />
                          </Stack>
                        }
                        titleTypographyProps={{ variant: 'h6', fontWeight: 600 }}
                      />
                      <CardContent sx={{ pt: 0 }}>
                        <Typography variant="body2" sx={{ mb: 1.5 }}>
                          {diagnosisResult.executive_summary}
                        </Typography>

                        <Paper variant="outlined" sx={{ p: 1.5, backgroundColor: 'action.hover', borderRadius: 1.5 }}>
                          <Typography variant="caption" sx={{ fontWeight: 700, color: 'info.main', display: 'flex', alignItems: 'center', gap: 0.5 }}>
                            <VerifiedUserIcon fontSize="inherit" /> WHY THE BASE IMAGE CANNOT BE CHANGED:
                          </Typography>
                          <Typography variant="body2" sx={{ fontSize: '0.82rem', mt: 0.5, color: 'text.secondary' }}>
                            {diagnosisResult.why_base_cannot_change}
                          </Typography>
                        </Paper>
                      </CardContent>
                    </Card>

                    {/* CVE & Attack Surface Reduction Matrix */}
                    <CVEReductionMatrix matrix={diagnosisResult.reduction_matrix} />

                    {/* Detected Issues List */}
                    {diagnosisResult.detected_issues?.length > 0 && (
                      <Card variant="outlined" sx={{ borderRadius: 2 }}>
                        <CardHeader
                          title={`Detected Issues (${diagnosisResult.detected_issues.length})`}
                          titleTypographyProps={{ variant: 'subtitle1', fontWeight: 600 }}
                        />
                        <CardContent sx={{ pt: 0, maxHeight: 240, overflowY: 'auto' }}>
                          <Stack spacing={1.5}>
                            {diagnosisResult.detected_issues.map((issue, i) => (
                              <Paper key={i} variant="outlined" sx={{ p: 1.5, borderRadius: 1.5 }}>
                                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 0.5 }}>
                                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                    {issue.severity === 'error' ? (
                                      <ErrorOutlineIcon color="error" fontSize="small" />
                                    ) : issue.severity === 'warning' ? (
                                      <WarningAmberIcon color="warning" fontSize="small" />
                                    ) : (
                                      <InfoOutlinedIcon color="info" fontSize="small" />
                                    )}
                                    <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                                      {issue.title}
                                    </Typography>
                                  </Box>
                                  {issue.line_number && (
                                    <Chip size="small" variant="outlined" label={`Line ${issue.line_number}`} sx={{ fontFamily: MONO_FONT, fontSize: '0.7rem' }} />
                                  )}
                                </Box>
                                <Typography variant="body2" color="text.secondary" sx={{ fontSize: '0.8rem', mb: 0.5 }}>
                                  {issue.description}
                                </Typography>
                                <Typography variant="caption" sx={{ fontWeight: 600, color: 'primary.main', display: 'block' }}>
                                  Remediation: {issue.remediation}
                                </Typography>
                              </Paper>
                            ))}
                          </Stack>
                        </CardContent>
                      </Card>
                    )}

                    {/* Visual Side-by-Side Diff Viewer */}
                    <VisualDiffViewer
                      diffData={diagnosisResult.diff_data}
                      originalText={dockerfileContent}
                      remediatedText={diagnosisResult.remediated_dockerfile}
                      onCopy={handleCopyCode}
                      onDownload={handleDownloadDockerfile}
                    />

                    {/* Step by Step Action Plan */}
                    {diagnosisResult.step_by_step_instructions?.length > 0 && (
                      <Card variant="outlined" sx={{ borderRadius: 2 }}>
                        <CardHeader
                          title="Implementation Steps"
                          titleTypographyProps={{ variant: 'subtitle1', fontWeight: 600 }}
                        />
                        <CardContent sx={{ pt: 0 }}>
                          <Stack component="ol" spacing={1} sx={{ m: 0, pl: 2.5 }}>
                            {diagnosisResult.step_by_step_instructions.map((step, idx) => (
                              <Typography key={idx} component="li" variant="body2">
                                {step}
                              </Typography>
                            ))}
                          </Stack>
                        </CardContent>
                      </Card>
                    )}
                  </Stack>
                )}
              </Grid>
            </Grid>
          </Box>
        ) : (
          /* Tab 2: Interactive AI Chat Assistant */
          <Box sx={{ p: 3 }}>
            <Paper variant="outlined" sx={{ borderRadius: 2, display: 'flex', flexDirection: 'column', height: 600 }}>
              {/* Chat Thread */}
              <Box sx={{ flexGrow: 1, p: 2.5, overflowY: 'auto' }}>
                <Stack spacing={2}>
                  {chatMessages.map((msg, i) => (
                    <Box
                      key={i}
                      sx={{
                        display: 'flex',
                        justifyContent: msg.role === 'user' ? 'flex-end' : 'flex-start',
                      }}
                    >
                      <Paper
                        variant="outlined"
                        sx={{
                          p: 2,
                          maxWidth: '85%',
                          borderRadius: 2,
                          backgroundColor: msg.role === 'user' ? 'primary.main' : 'background.paper',
                          color: msg.role === 'user' ? 'primary.contrastText' : 'text.primary',
                          borderColor: msg.role === 'user' ? 'primary.main' : 'divider',
                        }}
                      >
                        <Typography
                          variant="caption"
                          sx={{
                            fontWeight: 700,
                            display: 'block',
                            mb: 0.5,
                            textTransform: 'uppercase',
                            opacity: 0.8,
                          }}
                        >
                          {msg.role === 'user' ? 'You' : 'Apex Migration Advisor'}
                        </Typography>
                        <Typography
                          variant="body2"
                          sx={{
                            whiteSpace: 'pre-wrap',
                            fontFamily: msg.content.includes('FROM ') ? MONO_FONT : 'inherit',
                            fontSize: '0.88rem',
                            lineHeight: 1.5,
                          }}
                        >
                          {msg.content}
                        </Typography>
                      </Paper>
                    </Box>
                  ))}
                  {sendingChat && (
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, color: 'text.secondary' }}>
                      <CircularProgress size={18} />
                      <Typography variant="body2">Advisor is thinking...</Typography>
                    </Box>
                  )}
                </Stack>
              </Box>

              <Divider />

              {/* Quick Prompt Chips */}
              <Box sx={{ p: 1.5, display: 'flex', gap: 1, overflowX: 'auto', backgroundColor: 'action.hover' }}>
                {PROMPT_CHIPS.map((p, idx) => (
                  <Chip
                    key={idx}
                    label={p}
                    size="small"
                    onClick={() => handleSendChat(p)}
                    disabled={sendingChat}
                    sx={{ fontSize: '0.75rem', cursor: 'pointer' }}
                  />
                ))}
              </Box>

              {/* Input Area */}
              <Box sx={{ p: 2, display: 'flex', gap: 1 }}>
                <TextField
                  fullWidth
                  size="small"
                  placeholder="Ask any question about your Dockerfile, build errors, non-root users, or multi-stage builds..."
                  value={chatInput}
                  onChange={(e) => setChatInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && !e.shiftKey) {
                      e.preventDefault();
                      handleSendChat();
                    }
                  }}
                  disabled={sendingChat}
                />
                <Button
                  variant="contained"
                  color="primary"
                  onClick={() => handleSendChat()}
                  disabled={sendingChat || !chatInput.trim()}
                  endIcon={<SendIcon />}
                >
                  Send
                </Button>
              </Box>
            </Paper>
          </Box>
        )}
      </Paper>
    </Box>
  );
}
