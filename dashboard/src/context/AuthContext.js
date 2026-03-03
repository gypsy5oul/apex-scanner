import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import axios from 'axios';

const AuthContext = createContext(null);

// Get API URL
const getApiUrl = () => {
  if (window.REACT_APP_API_URL) {
    return window.REACT_APP_API_URL;
  }
  if (process.env.REACT_APP_API_URL) {
    return process.env.REACT_APP_API_URL;
  }
  const host = window.location.hostname;
  return `http://${host}:7070`;
};

const API_BASE_URL = getApiUrl();

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  // Check if user is authenticated on mount by calling /auth/status
  // The httpOnly cookie is sent automatically by the browser
  const checkAuthStatus = useCallback(async () => {
    try {
      const response = await axios.get(`${API_BASE_URL}/api/v2/auth/status`, {
        withCredentials: true,
      });
      if (response.data.authenticated) {
        setUser({
          username: response.data.username,
          role: response.data.role || 'admin',
        });
      } else {
        setUser(null);
      }
    } catch (error) {
      setUser(null);
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    checkAuthStatus();
  }, [checkAuthStatus]);

  const login = async (username, password) => {
    try {
      const response = await axios.post(
        `${API_BASE_URL}/api/v2/auth/login`,
        { username, password },
        { withCredentials: true }
      );

      // The httpOnly cookie is set by the server response.
      // We only use the response body for user info (not the token).
      const { username: user, role } = response.data;
      setUser({ username: user, role: role });

      return { success: true };
    } catch (error) {
      return {
        success: false,
        error: error.response?.data?.detail || 'Login failed',
      };
    }
  };

  const logout = async () => {
    try {
      // Call backend to clear the httpOnly cookie
      await axios.post(`${API_BASE_URL}/api/v2/auth/logout`, {}, {
        withCredentials: true,
      });
    } catch (error) {
      // Even if the request fails, clear local state
    }
    setUser(null);
  };

  const isAuthenticated = () => {
    return !!user;
  };

  const isAdmin = () => {
    return !!user && user.role === 'admin';
  };

  const value = {
    user,
    loading,
    login,
    logout,
    isAuthenticated,
    isAdmin,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export default AuthContext;
