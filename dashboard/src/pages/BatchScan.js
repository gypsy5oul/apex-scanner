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
  Chip,
  IconButton,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import DeleteIcon from '@mui/icons-material/Delete';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import { startBatchScan, getBatchStatus } from '../api';

function BatchScan() {
  const navigate = useNavigate();
  const [images, setImages] = useState(['']);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [batchResult, setBatchResult] = useState(null);
  const [polling, setPolling] = useState(false);

  const handleAddImage = () => {
    if (images.length < 50) {
      setImages([...images, '']);
    }
  };

  const handleRemoveImage = (index) => {
    setImages(images.filter((_, i) => i !== index));
  };

  const handleImageChange = (index, value) => {
    const newImages = [...images];
    newImages[index] = value;
    setImages(newImages);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const validImages = images.filter((img) => img.trim());
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
      setBatchResult(response.data);
      if (response.data.status === 'in_progress') {
        setTimeout(() => pollBatchStatus(batchId), 5000);
      } else {
        setPolling(false);
        setLoading(false);
      }
    } catch (err) {
      setError(err.message);
      setPolling(false);
      setLoading(false);
    }
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Batch Scan
      </Typography>

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
              key={index}
              sx={{ display: 'flex', gap: 1, mb: 2, alignItems: 'center' }}
            >
              <TextField
                fullWidth
                label={`Image ${index + 1}`}
                placeholder="e.g., nginx:latest"
                value={image}
                onChange={(e) => handleImageChange(index, e.target.value)}
                disabled={loading}
                size="small"
              />
              {images.length > 1 && (
                <IconButton
                  onClick={() => handleRemoveImage(index)}
                  disabled={loading}
                  color="error"
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
                    backgroundColor:
                      scan.status === 'completed'
                        ? '#e8f5e9'
                        : scan.status === 'failed'
                        ? '#ffebee'
                        : '#fff3e0',
                    borderRadius: 1,
                  }}
                >
                  <Box>
                    <Typography variant="body2">
                      <strong>{scan.image_name}</strong>
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {scan.scan_id}
                    </Typography>
                  </Box>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    {scan.status === 'completed' && (
                      <>
                        <Chip
                          size="small"
                          label={`C:${scan.critical}`}
                          color="error"
                        />
                        <Chip
                          size="small"
                          label={`H:${scan.high}`}
                          color="warning"
                        />
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
