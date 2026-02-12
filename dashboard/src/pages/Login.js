import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import {
  Box,
  Paper,
  Typography,
  TextField,
  Button,
  Alert,
  CircularProgress,
  InputAdornment,
  IconButton,
} from '@mui/material';
import ChangeHistoryIcon from '@mui/icons-material/ChangeHistory';
import VisibilityIcon from '@mui/icons-material/Visibility';
import VisibilityOffIcon from '@mui/icons-material/VisibilityOff';
import PersonIcon from '@mui/icons-material/Person';
import LockIcon from '@mui/icons-material/Lock';
import { useAuth } from '../context/AuthContext';

function Login() {
  const navigate = useNavigate();
  const location = useLocation();
  const { login } = useAuth();

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Get the page user was trying to access
  const from = location.state?.from?.pathname || '/';

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    const result = await login(username, password);

    if (result.success) {
      navigate(from, { replace: true });
    } else {
      setError(result.error);
    }

    setLoading(false);
  };

  return (
    <Box
      sx={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: (theme) =>
          `linear-gradient(135deg, ${theme.palette.grey[900]} 0%, ${theme.palette.grey[800]} 100%)`,
        p: 2,
      }}
    >
      <Paper
        elevation={6}
        sx={{
          p: 4,
          maxWidth: 420,
          width: '100%',
          borderRadius: 3,
        }}
      >
        {/* Logo */}
        <Box sx={{ textAlign: 'center', mb: 4 }}>
          <Box
            sx={{
              width: 72,
              height: 72,
              display: 'inline-flex',
              alignItems: 'center',
              justifyContent: 'center',
              background: (theme) =>
                `linear-gradient(135deg, ${theme.palette.primary.main} 0%, ${theme.palette.secondary.main} 100%)`,
              borderRadius: 3,
              boxShadow: '0 8px 24px rgba(25, 118, 210, 0.3)',
              mb: 2,
            }}
          >
            <ChangeHistoryIcon
              sx={{
                fontSize: 44,
                color: '#fff',
              }}
            />
          </Box>
          <Typography
            variant="h4"
            sx={{
              fontWeight: 700,
              background: (theme) =>
                `linear-gradient(135deg, ${theme.palette.primary.main} 0%, ${theme.palette.secondary.main} 100%)`,
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
            }}
          >
            Apex Scanner
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
            Sign in to continue
          </Typography>
        </Box>

        {/* Error Alert */}
        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        {/* Login Form */}
        <form onSubmit={handleSubmit}>
          <TextField
            fullWidth
            label="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            disabled={loading}
            autoFocus
            sx={{ mb: 2 }}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <PersonIcon color="action" />
                </InputAdornment>
              ),
            }}
          />

          <TextField
            fullWidth
            label="Password"
            type={showPassword ? 'text' : 'password'}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            disabled={loading}
            sx={{ mb: 3 }}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <LockIcon color="action" />
                </InputAdornment>
              ),
              endAdornment: (
                <InputAdornment position="end">
                  <IconButton
                    onClick={() => setShowPassword(!showPassword)}
                    edge="end"
                  >
                    {showPassword ? <VisibilityOffIcon /> : <VisibilityIcon />}
                  </IconButton>
                </InputAdornment>
              ),
            }}
          />

          <Button
            fullWidth
            type="submit"
            variant="contained"
            size="large"
            disabled={loading || !username || !password}
            sx={{
              py: 1.5,
              fontWeight: 600,
              fontSize: '1rem',
            }}
          >
            {loading ? <CircularProgress size={24} /> : 'Sign In'}
          </Button>
        </form>

        <Typography
          variant="caption"
          color="text.disabled"
          sx={{ display: 'block', textAlign: 'center', mt: 3 }}
        >
          Apex Scanner v3.0 &mdash; Enterprise Vulnerability Detection
        </Typography>
      </Paper>
    </Box>
  );
}

export default Login;
