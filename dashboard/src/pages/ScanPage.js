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
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
} from '@mui/material';
import SearchIcon from '@mui/icons-material/Search';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import { startScan } from '../api';

const exampleImages = [
  'nginx:latest',
  'alpine:3.18',
  'python:3.11-slim',
  'node:20-alpine',
  'ubuntu:22.04',
];

function ScanPage() {
  const navigate = useNavigate();
  const [imageName, setImageName] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);

  const handleScan = async (e) => {
    e.preventDefault();
    if (!imageName.trim()) {
      setError('Please enter an image name');
      return;
    }

    setLoading(true);
    setError(null);
    setSuccess(null);

    try {
      const response = await startScan(imageName.trim());
      setSuccess(`Scan initiated! Scan ID: ${response.data.scan_id}`);
      setTimeout(() => {
        navigate(`/scan/${response.data.scan_id}`);
      }, 1500);
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleExampleClick = (image) => {
    setImageName(image);
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        New Scan
      </Typography>

      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          Scan Docker Image
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Enter a Docker image name to scan for vulnerabilities using Grype,
          Trivy, and generate SBOM with Syft.
        </Typography>

        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        {success && (
          <Alert severity="success" sx={{ mb: 2 }}>
            {success}
          </Alert>
        )}

        <form onSubmit={handleScan}>
          <Box sx={{ display: 'flex', gap: 2, alignItems: 'flex-start' }}>
            <TextField
              fullWidth
              label="Docker Image Name"
              placeholder="e.g., nginx:latest, python:3.11"
              value={imageName}
              onChange={(e) => setImageName(e.target.value)}
              disabled={loading}
              helperText="Format: [registry/]repository[:tag][@digest]"
            />
            <Button
              type="submit"
              variant="contained"
              size="large"
              disabled={loading}
              startIcon={loading ? <CircularProgress size={20} /> : <SearchIcon />}
              sx={{ minWidth: 150, height: 56 }}
            >
              {loading ? 'Scanning...' : 'Scan'}
            </Button>
          </Box>
        </form>
      </Paper>

      <Paper sx={{ p: 3 }}>
        <Typography variant="h6" gutterBottom>
          Example Images
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Click on an image below to use it
        </Typography>
        <List>
          {exampleImages.map((image) => (
            <ListItem
              key={image}
              button
              onClick={() => handleExampleClick(image)}
              sx={{
                '&:hover': { backgroundColor: 'action.hover' },
                borderRadius: 1,
              }}
            >
              <ListItemIcon>
                <CheckCircleIcon color="primary" />
              </ListItemIcon>
              <ListItemText
                primary={image}
                secondary="Click to select"
              />
            </ListItem>
          ))}
        </List>
      </Paper>
    </Box>
  );
}

export default ScanPage;
