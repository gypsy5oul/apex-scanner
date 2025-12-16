import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Card,
  CardContent,
  CardActionArea,
  Typography,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Alert,
  CircularProgress,
  Grid,
  Divider,
  IconButton,
  Tooltip,
} from '@mui/material';
import {
  Add,
  Layers,
  CompareArrows,
  PlayArrow,
  Delete,
  Edit,
} from '@mui/icons-material';
import {
  getBaseImages,
  registerBaseImage,
  compareBaseImages,
  scanAllBaseImages,
  deleteBaseImage,
  updateBaseImage,
} from '../api';

function BaseImages() {
  const navigate = useNavigate();
  const [baseImages, setBaseImages] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editDialogOpen, setEditDialogOpen] = useState(false);
  const [compareDialogOpen, setCompareDialogOpen] = useState(false);
  const [compareResult, setCompareResult] = useState(null);
  const [newImage, setNewImage] = useState({
    image_name: '',
    image_tag: '',
    description: '',
  });
  const [editImage, setEditImage] = useState({
    image_name: '',
    image_tag: '',
    description: '',
  });
  const [compareForm, setCompareForm] = useState({
    image1: '',
    tag1: '',
    image2: '',
    tag2: '',
  });

  const fetchBaseImages = async () => {
    setLoading(true);
    try {
      const res = await getBaseImages();
      setBaseImages(res.data.base_images || []);
    } catch (err) {
      setError('Failed to fetch base images');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchBaseImages();
  }, []);

  const handleRegister = async () => {
    try {
      await registerBaseImage(newImage);
      setSuccess('Base image registered successfully');
      setDialogOpen(false);
      setNewImage({ image_name: '', image_tag: '', description: '' });
      fetchBaseImages();
    } catch (err) {
      setError('Failed to register base image');
    }
  };

  const handleCompare = async () => {
    try {
      const res = await compareBaseImages(
        compareForm.image1,
        compareForm.tag1,
        compareForm.image2,
        compareForm.tag2
      );
      setCompareResult(res.data);
    } catch (err) {
      setError('Failed to compare images');
    }
  };

  const handleScanAll = async () => {
    try {
      await scanAllBaseImages();
      setSuccess('Scan triggered for all base images. Check the dashboard for progress.');
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to trigger base image scan');
    }
  };

  const handleDelete = async (imageName, imageTag, e) => {
    e.stopPropagation();
    if (!window.confirm(`Delete base image "${imageName}:${imageTag}"?`)) return;
    try {
      await deleteBaseImage(imageName, imageTag);
      setSuccess('Base image removed from tracking');
      fetchBaseImages();
    } catch (err) {
      setError('Failed to delete base image');
    }
  };

  const handleEditClick = (image, e) => {
    e.stopPropagation();
    setEditImage({
      image_name: image.image_name,
      image_tag: image.image_tag,
      description: image.description || '',
    });
    setEditDialogOpen(true);
  };

  const handleUpdate = async () => {
    try {
      await updateBaseImage(editImage.image_name, editImage.image_tag, {
        description: editImage.description,
      });
      setSuccess('Base image updated successfully');
      setEditDialogOpen(false);
      fetchBaseImages();
    } catch (err) {
      setError('Failed to update base image');
    }
  };

  const handleCardClick = (image) => {
    const encodedName = encodeURIComponent(image.image_name);
    const encodedTag = encodeURIComponent(image.image_tag);
    navigate(`/base-images/${encodedName}/${encodedTag}`);
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Box>
          <Typography variant="h4" fontWeight="bold">
            Base Image Tracking
          </Typography>
          <Typography color="textSecondary">
            Track and compare vulnerabilities in base images
          </Typography>
        </Box>
        <Box display="flex" gap={2}>
          {baseImages.length > 0 && (
            <Button
              variant="contained"
              color="success"
              startIcon={<PlayArrow />}
              onClick={handleScanAll}
            >
              Scan All Now
            </Button>
          )}
          <Button
            variant="outlined"
            startIcon={<CompareArrows />}
            onClick={() => setCompareDialogOpen(true)}
          >
            Compare Images
          </Button>
          <Button
            variant="contained"
            startIcon={<Add />}
            onClick={() => setDialogOpen(true)}
          >
            Register Base Image
          </Button>
        </Box>
      </Box>

      {error && (
        <Alert severity="error" onClose={() => setError(null)} sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}
      {success && (
        <Alert severity="success" onClose={() => setSuccess(null)} sx={{ mb: 2 }}>
          {success}
        </Alert>
      )}

      {baseImages.length === 0 ? (
        <Card>
          <CardContent>
            <Box textAlign="center" py={4}>
              <Layers sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
              <Typography variant="h6" gutterBottom>
                No Base Images Registered
              </Typography>
              <Typography color="textSecondary" mb={3}>
                Register your base images to track their vulnerabilities over time
              </Typography>
              <Button
                variant="contained"
                startIcon={<Add />}
                onClick={() => setDialogOpen(true)}
              >
                Register Base Image
              </Button>
            </Box>
          </CardContent>
        </Card>
      ) : (
        <Grid container spacing={3}>
          {baseImages.map((image, index) => (
            <Grid item xs={12} md={6} lg={4} key={index}>
              <Card sx={{ cursor: 'pointer', '&:hover': { boxShadow: 6 } }} onClick={() => handleCardClick(image)}>
                <CardContent>
                  <Box display="flex" justifyContent="space-between" alignItems="flex-start">
                    <Typography variant="h6" fontWeight="bold" gutterBottom>
                      {image.full_name || `${image.image_name}:${image.image_tag}`}
                    </Typography>
                    <Box>
                      <Tooltip title="Edit description">
                        <IconButton
                          size="small"
                          color="primary"
                          onClick={(e) => handleEditClick(image, e)}
                        >
                          <Edit fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Remove from tracking">
                        <IconButton
                          size="small"
                          color="error"
                          onClick={(e) => handleDelete(image.image_name, image.image_tag, e)}
                        >
                          <Delete fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    </Box>
                  </Box>
                  {image.description && (
                    <Typography variant="body2" color="textSecondary" mb={2}>
                      {image.description}
                    </Typography>
                  )}
                  <Divider sx={{ my: 2 }} />

                  {/* Fixable Vulnerabilities */}
                  <Typography variant="caption" color="success.main" fontWeight="bold" display="block" mb={1}>
                    FIXABLE (patches available)
                  </Typography>
                  <Grid container spacing={1} mb={2}>
                    <Grid item xs={3}>
                      <Typography variant="caption" color="textSecondary">
                        Critical
                      </Typography>
                      <Typography variant="h6" color="error">
                        {image.current_vulns?.fixable_critical || 0}
                      </Typography>
                    </Grid>
                    <Grid item xs={3}>
                      <Typography variant="caption" color="textSecondary">
                        High
                      </Typography>
                      <Typography variant="h6" color="warning.main">
                        {image.current_vulns?.fixable_high || 0}
                      </Typography>
                    </Grid>
                    <Grid item xs={3}>
                      <Typography variant="caption" color="textSecondary">
                        Medium
                      </Typography>
                      <Typography variant="h6">
                        {image.current_vulns?.fixable_medium || 0}
                      </Typography>
                    </Grid>
                    <Grid item xs={3}>
                      <Typography variant="caption" color="textSecondary">
                        Low
                      </Typography>
                      <Typography variant="h6" color="success.main">
                        {image.current_vulns?.fixable_low || 0}
                      </Typography>
                    </Grid>
                  </Grid>

                  {/* Non-Fixable Vulnerabilities */}
                  <Typography variant="caption" color="text.secondary" fontWeight="bold" display="block" mb={1}>
                    NO FIX AVAILABLE
                  </Typography>
                  <Grid container spacing={1}>
                    <Grid item xs={3}>
                      <Typography variant="caption" color="textSecondary">
                        Critical
                      </Typography>
                      <Typography variant="h6" color="error">
                        {(image.current_vulns?.critical || 0) - (image.current_vulns?.fixable_critical || 0)}
                      </Typography>
                    </Grid>
                    <Grid item xs={3}>
                      <Typography variant="caption" color="textSecondary">
                        High
                      </Typography>
                      <Typography variant="h6" color="warning.main">
                        {(image.current_vulns?.high || 0) - (image.current_vulns?.fixable_high || 0)}
                      </Typography>
                    </Grid>
                    <Grid item xs={3}>
                      <Typography variant="caption" color="textSecondary">
                        Medium
                      </Typography>
                      <Typography variant="h6">
                        {(image.current_vulns?.medium || 0) - (image.current_vulns?.fixable_medium || 0)}
                      </Typography>
                    </Grid>
                    <Grid item xs={3}>
                      <Typography variant="caption" color="textSecondary">
                        Low
                      </Typography>
                      <Typography variant="h6" color="success.main">
                        {(image.current_vulns?.low || 0) - (image.current_vulns?.fixable_low || 0)}
                      </Typography>
                    </Grid>
                  </Grid>
                  <Divider sx={{ my: 2 }} />
                  <Box display="flex" justifyContent="space-between" alignItems="center">
                    <Chip
                      label={`${image.scan_count || 0} scans`}
                      size="small"
                      variant="outlined"
                    />
                    {image.last_scanned && (
                      <Typography variant="caption" color="textSecondary">
                        Last: {new Date(image.last_scanned).toLocaleDateString()}
                      </Typography>
                    )}
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      )}

      {/* Register Dialog */}
      <Dialog open={dialogOpen} onClose={() => setDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Register Base Image</DialogTitle>
        <DialogContent>
          <Grid container spacing={2} sx={{ mt: 1 }}>
            <Grid item xs={8}>
              <TextField
                fullWidth
                label="Image Name"
                value={newImage.image_name}
                onChange={(e) =>
                  setNewImage({ ...newImage, image_name: e.target.value })
                }
                placeholder="ubuntu"
              />
            </Grid>
            <Grid item xs={4}>
              <TextField
                fullWidth
                label="Tag"
                value={newImage.image_tag}
                onChange={(e) =>
                  setNewImage({ ...newImage, image_tag: e.target.value })
                }
                placeholder="22.04"
              />
            </Grid>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Description"
                value={newImage.description}
                onChange={(e) =>
                  setNewImage({ ...newImage, description: e.target.value })
                }
                placeholder="Production base image for Python services"
              />
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDialogOpen(false)}>Cancel</Button>
          <Button variant="contained" onClick={handleRegister}>
            Register
          </Button>
        </DialogActions>
      </Dialog>

      {/* Compare Dialog */}
      <Dialog
        open={compareDialogOpen}
        onClose={() => {
          setCompareDialogOpen(false);
          setCompareResult(null);
        }}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>Compare Base Images</DialogTitle>
        <DialogContent>
          <Grid container spacing={2} sx={{ mt: 1 }}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" gutterBottom>
                Image 1
              </Typography>
              <TextField
                fullWidth
                label="Image Name"
                value={compareForm.image1}
                onChange={(e) =>
                  setCompareForm({ ...compareForm, image1: e.target.value })
                }
                sx={{ mb: 2 }}
              />
              <TextField
                fullWidth
                label="Tag"
                value={compareForm.tag1}
                onChange={(e) =>
                  setCompareForm({ ...compareForm, tag1: e.target.value })
                }
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" gutterBottom>
                Image 2
              </Typography>
              <TextField
                fullWidth
                label="Image Name"
                value={compareForm.image2}
                onChange={(e) =>
                  setCompareForm({ ...compareForm, image2: e.target.value })
                }
                sx={{ mb: 2 }}
              />
              <TextField
                fullWidth
                label="Tag"
                value={compareForm.tag2}
                onChange={(e) =>
                  setCompareForm({ ...compareForm, tag2: e.target.value })
                }
              />
            </Grid>
          </Grid>

          {compareResult && (
            <Box mt={3}>
              <Divider sx={{ mb: 2 }} />
              <Typography variant="h6" gutterBottom>
                Comparison Results
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Card variant="outlined">
                    <CardContent>
                      <Typography variant="subtitle2" color="textSecondary">
                        {compareResult.image1?.name}
                      </Typography>
                      <Box mt={1}>
                        <Chip
                          label={`Critical: ${compareResult.image1?.vulnerabilities?.critical || 0}`}
                          color="error"
                          size="small"
                          sx={{ mr: 1 }}
                        />
                        <Chip
                          label={`High: ${compareResult.image1?.vulnerabilities?.high || 0}`}
                          color="warning"
                          size="small"
                        />
                      </Box>
                    </CardContent>
                  </Card>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Card variant="outlined">
                    <CardContent>
                      <Typography variant="subtitle2" color="textSecondary">
                        {compareResult.image2?.name}
                      </Typography>
                      <Box mt={1}>
                        <Chip
                          label={`Critical: ${compareResult.image2?.vulnerabilities?.critical || 0}`}
                          color="error"
                          size="small"
                          sx={{ mr: 1 }}
                        />
                        <Chip
                          label={`High: ${compareResult.image2?.vulnerabilities?.high || 0}`}
                          color="warning"
                          size="small"
                        />
                      </Box>
                    </CardContent>
                  </Card>
                </Grid>
              </Grid>
              {compareResult.comparison && (
                <Alert
                  severity={compareResult.comparison.recommendation === 'image2' ? 'success' : 'info'}
                  sx={{ mt: 2 }}
                >
                  Recommendation: <strong>{compareResult.comparison.recommendation}</strong> has
                  fewer critical/high vulnerabilities
                </Alert>
              )}
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button
            onClick={() => {
              setCompareDialogOpen(false);
              setCompareResult(null);
            }}
          >
            Close
          </Button>
          <Button variant="contained" onClick={handleCompare}>
            Compare
          </Button>
        </DialogActions>
      </Dialog>

      {/* Edit Dialog */}
      <Dialog open={editDialogOpen} onClose={() => setEditDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Edit Base Image</DialogTitle>
        <DialogContent>
          <Box sx={{ mt: 1 }}>
            <Typography variant="subtitle2" color="textSecondary" gutterBottom>
              Image: {editImage.image_name}:{editImage.image_tag}
            </Typography>
            <TextField
              fullWidth
              label="Description"
              value={editImage.description}
              onChange={(e) =>
                setEditImage({ ...editImage, description: e.target.value })
              }
              placeholder="Production base image for Python services"
              multiline
              rows={2}
              sx={{ mt: 2 }}
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditDialogOpen(false)}>Cancel</Button>
          <Button variant="contained" onClick={handleUpdate}>
            Save Changes
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

export default BaseImages;
