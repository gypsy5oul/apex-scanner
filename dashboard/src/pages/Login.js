import React, { useState, useEffect, useRef } from 'react';
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
  Divider,
  Link,
} from '@mui/material';
import VisibilityIcon from '@mui/icons-material/Visibility';
import VisibilityOffIcon from '@mui/icons-material/VisibilityOff';
import PersonIcon from '@mui/icons-material/Person';
import LockIcon from '@mui/icons-material/Lock';
import VpnKeyIcon from '@mui/icons-material/VpnKey';
import { useAuth } from '../context/AuthContext';
import { getAuthConfig, getSsoLoginUrl } from '../api';

function Login() {
  const navigate = useNavigate();
  const location = useLocation();
  const { login } = useAuth();

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // SSO state: whether OIDC is available, and whether the user opted into the
  // local-account form. SSO is the default; local is a secondary path.
  const [ssoEnabled, setSsoEnabled] = useState(false);
  const [showLocal, setShowLocal] = useState(false);
  const [redirecting, setRedirecting] = useState(false);

  const usernameRef = useRef(null);

  // Get the page user was trying to access
  const from = location.state?.from?.pathname || '/';

  useEffect(() => {
    // Surface an SSO failure bounced back from the callback.
    if (new URLSearchParams(location.search).has('sso_error')) {
      setError('Single sign-on failed. Try again or use a local account.');
    }
    getAuthConfig()
      .then((res) => setSsoEnabled(!!res.data?.oidc_enabled))
      .catch(() => setSsoEnabled(false));
  }, [location.search]);

  const startSso = () => {
    setRedirecting(true);
    window.location.href = getSsoLoginUrl();
  };

  // Local form mounts late (after auth config resolves), so autoFocus on the
  // username field won't fire — move focus explicitly when it appears.
  const localVisible = !ssoEnabled || showLocal;
  useEffect(() => {
    if (localVisible) {
      usernameRef.current?.focus();
    }
  }, [localVisible]);

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
            component="img"
            src="/brand/apex-logomark.svg"
            alt="Apex Scanner"
            sx={{ width: 56, height: 56, objectFit: 'contain', display: 'inline-block', mb: 1.5 }}
          />
          <Typography
            sx={{
              fontFamily: '"Space Grotesk", "Inter", sans-serif',
              fontWeight: 700,
              fontSize: '1.6rem',
              letterSpacing: '-0.02em',
              color: 'text.primary',
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

        {/* SSO — primary */}
        {ssoEnabled && (
          <>
            <Button
              fullWidth
              variant="contained"
              size="large"
              startIcon={redirecting ? <CircularProgress size={20} color="inherit" /> : <VpnKeyIcon />}
              onClick={startSso}
              disabled={redirecting}
              aria-busy={redirecting}
              sx={{ py: 1.5, fontWeight: 600, fontSize: '1rem' }}
            >
              {redirecting ? 'Redirecting…' : 'Sign in with 6D SSO'}
            </Button>
            {!showLocal && (
              <Box sx={{ textAlign: 'center', mt: 2 }}>
                <Link
                  component="button"
                  type="button"
                  variant="body2"
                  underline="hover"
                  onClick={() => setShowLocal(true)}
                  sx={{ color: 'text.secondary' }}
                >
                  Use a local account
                </Link>
              </Box>
            )}
            {localVisible && <Divider sx={{ my: 3 }}>or sign in locally</Divider>}
          </>
        )}

        {/* Local login form (secondary unless SSO is unavailable) */}
        {localVisible && (
        <form onSubmit={handleSubmit}>
          <TextField
            fullWidth
            label="Username"
            name="username"
            autoComplete="username"
            inputRef={usernameRef}
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
            name="password"
            autoComplete="current-password"
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
                    aria-label={showPassword ? 'Hide password' : 'Show password'}
                    tabIndex={-1}
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
            aria-busy={loading}
            startIcon={loading ? <CircularProgress size={20} color="inherit" /> : null}
            sx={{
              py: 1.5,
              fontWeight: 600,
              fontSize: '1rem',
            }}
          >
            {loading ? 'Signing in…' : 'Sign In'}
          </Button>
        </form>
        )}

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
