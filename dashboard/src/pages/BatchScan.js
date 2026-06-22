import React, { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Paper,
  Typography,
  TextField,
  Button,
  Alert,
  CircularProgress,
  Chip,
  IconButton,
  LinearProgress,
  alpha,
} from '@mui/material';
import PageHeader from '../components/PageHeader';
import AddIcon from '@mui/icons-material/Add';
import DeleteIcon from '@mui/icons-material/Delete';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import { startBatchScan, getBatchStatus } from '../api';
import SeverityChip from '../components/SeverityChip';
import { useToast } from '../components/Feedback';
import { MONO_FONT } from '../theme/tokens';

// Stable per-row id so rows aren't keyed by array index (which breaks when
// rows are added/removed mid-edit).
let _rowSeq = 0;
const newRow = () => ({ id: `img-${++_rowSeq}`, value: '' });

function BatchScan() {
  const navigate = useNavigate();
  const toast = useToast();
  const [images, setImages] = useState([newRow()]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [batchResult, setBatchResult] = useState(null);
  const [polling, setPolling] = useState(false);

  // Track mount + the pending poll timer so the recursive poll loop is
  // cancelled when the component unmounts (no setState-after-unmount).
  const isMountedRef = useRef(true);
  const pollTimerRef = useRef(null);
  useEffect(() => {
    isMountedRef.current = true;
    return () => {
      isMountedRef.current = false;
      if (pollTimerRef.current) clearTimeout(pollTimerRef.current);
    };
  }, []);

  const handleAddImage = () => {
    if (images.length < 50) {
      setImages([...images, newRow()]);
    }
  };

  const handleRemoveImage = (id) => {
    setImages(images.filter((img) => img.id !== id));
  };

  const handleImageChange = (id, value) => {
    setImages(images.map((img) => (img.id === id ? { ...img, value } : img)));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const validImages = images.map((img) => img.value.trim()).filter(Boolean);
    if (validImages.length === 0) {
      setError('Please enter at least one image');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const response = await startBatchScan(validImages);
      setBatchResult(response.data);
      setPolling(true);
      pollBatchStatus(response.data.batch_id);
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
      setLoading(false);
    }
  };

  const pollBatchStatus = async (batchId) => {
    try {
      const response = await getBatchStatus(batchId);
      if (!isMountedRef.current) return;
      setBatchResult(response.data);
      if (response.data.status === 'in_progress') {
        pollTimerRef.current = setTimeout(() => pollBatchStatus(batchId), 5000);
      } else {
        setPolling(false);
        setLoading(false);
      }
    } catch (err) {
      if (!isMountedRef.current) return;
      setError(err.message);
      toast('Batch status update failed: ' + (err.response?.data?.detail || err.message), 'error');
      setPolling(false);
      setLoading(false);
    }
  };

  return (
    <Box>
      <PageHeader
        title="Batch Scan"
        description="Queue multiple images for scanning in a single run"
      />

      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          Scan Multiple Images
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Enter multiple Docker images to scan in batch. Maximum 50 images per
          batch.
        </Typography>

        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        <form onSubmit={handleSubmit}>
          {images.map((image, index) => (
            <Box
              key={image.id}
              sx={{ display: 'flex', gap: 1, mb: 2, alignItems: 'center' }}
            >
              <TextField
                fullWidth
                label={`Image ${index + 1}`}
                placeholder="e.g., nginx:latest"
                value={image.value}
                onChange={(e) => handleImageChange(image.id, e.target.value)}
                disabled={loading}
                size="small"
              />
              {images.length > 1 && (
                <IconButton
                  onClick={() => handleRemoveImage(image.id)}
                  disabled={loading}
                  color="error"
                  aria-label={`Remove image ${index + 1}`}
                >
                  <DeleteIcon />
                </IconButton>
              )}
            </Box>
          ))}

          <Box sx={{ display: 'flex', gap: 2, mt: 2 }}>
            <Button
              variant="outlined"
              startIcon={<AddIcon />}
              onClick={handleAddImage}
              disabled={loading || images.length >= 50}
            >
              Add Image
            </Button>
            <Button
              type="submit"
              variant="contained"
              startIcon={
                loading ? <CircularProgress size={20} /> : <PlayArrowIcon />
              }
              disabled={loading}
            >
              {loading ? 'Scanning...' : 'Start Batch Scan'}
            </Button>
          </Box>
        </form>
      </Paper>

      {batchResult && (
        <Paper sx={{ p: 3 }}>
          <Typography variant="h6" gutterBottom>
            Batch Results
          </Typography>
          <Box sx={{ mb: 2 }}>
            <Typography>
              <strong>Batch ID:</strong> {batchResult.batch_id}
            </Typography>
            <Typography>
              <strong>Status:</strong>{' '}
              <Chip
                size="small"
                label={batchResult.status}
                color={
                  batchResult.status === 'completed'
                    ? 'success'
                    : batchResult.status === 'failed'
                    ? 'error'
                    : 'warning'
                }
              />
            </Typography>
            <Typography>
              <strong>Progress:</strong> {batchResult.completed || 0} /{' '}
              {batchResult.total_images} completed
            </Typography>
            {polling && batchResult.total_images > 0 && (
              <LinearProgress
                variant="determinate"
                value={Math.min(
                  ((batchResult.completed || 0) / batchResult.total_images) * 100,
                  100
                )}
                sx={{ mt: 1, height: 8, borderRadius: 1 }}
              />
            )}
          </Box>

          {batchResult.scans && (
            <Box>
              <Typography variant="subtitle1" sx={{ mb: 1 }}>
                Individual Scans:
              </Typography>
              {batchResult.scans.map((scan) => (
                <Box
                  key={scan.scan_id}
                  sx={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    p: 1,
                    mb: 1,
                    backgroundColor: (theme) =>
                      alpha(
                        scan.status === 'completed'
                          ? theme.palette.success.main
                          : scan.status === 'failed'
                          ? theme.palette.error.main
                          : theme.palette.warning.main,
                        0.12
                      ),
                    borderRadius: 1,
                  }}
                >
                  <Box sx={{ minWidth: 0 }}>
                    <Typography
                      variant="body2"
                      sx={{
                        fontWeight: 700,
                        maxWidth: 360,
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                      }}
                      title={scan.image_name}
                    >
                      {scan.image_name}
                    </Typography>
                    <Typography
                      variant="caption"
                      color="text.secondary"
                      sx={{ fontFamily: MONO_FONT }}
                    >
                      {scan.scan_id}
                    </Typography>
                  </Box>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    {scan.status === 'completed' && (
                      <>
                        <SeverityChip severity="Critical" count={scan.critical || 0} />
                        <SeverityChip severity="High" count={scan.high || 0} />
                      </>
                    )}
                    <Button
                      size="small"
                      variant="outlined"
                      onClick={() => navigate(`/scan/${scan.scan_id}`)}
                      disabled={scan.status === 'in_progress'}
                    >
                      View
                    </Button>
                  </Box>
                </Box>
              ))}
            </Box>
          )}
        </Paper>
      )}
    </Box>
  );
}

export default BatchScan;
