import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { Box, CircularProgress } from '@mui/material';
import { useAuth } from '../context/AuthContext';

function ProtectedRoute({ children, requiredRole = null }) {
  const { isAuthenticated, isAdmin, loading } = useAuth();
  const location = useLocation();

  // Show loading spinner while checking auth
  if (loading) {
    return (
      <Box
        sx={{
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          minHeight: '50vh',
        }}
      >
        <CircularProgress />
      </Box>
    );
  }

  // Redirect to login if not authenticated
  if (!isAuthenticated()) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  // Check role if required
  if (requiredRole === 'admin' && !isAdmin()) {
    return <Navigate to="/" replace />;
  }

  return children;
}

export default ProtectedRoute;
