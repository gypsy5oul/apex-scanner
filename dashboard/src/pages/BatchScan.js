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
  IconButton,
} from '@mui/material';
import PageHeader from '../components/PageHeader';
import AddIcon from '@mui/icons-material/Add';
import DeleteIcon from '@mui/icons-material/Delete';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import { startBatchScan } from '../api';

// Stable per-row id so rows aren't keyed by array index (which breaks when
// rows are added/removed mid-edit).
let _rowSeq = 0;
const newRow = () => ({ id: `img-${++_rowSeq}`, value: '' });

function BatchScan() {
  const navigate = useNavigate();
  const [images, setImages] = useState([newRow()]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

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
      // Submit and hand off to the batch results page (live progress lives there).
      const response = await startBatchScan(validImages);
      navigate(`/batches/${response.data.batch_id}`);
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
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
          batch. You'll be taken to the batch results page to watch progress.
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
              {loading ? 'Starting...' : 'Start Batch Scan'}
            </Button>
          </Box>
        </form>
      </Paper>
    </Box>
  );
}

export default BatchScan;
