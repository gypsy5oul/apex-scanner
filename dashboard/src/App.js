import React from 'react';
import { Routes, Route, useLocation, Navigate } from 'react-router-dom';
import { Box, CircularProgress } from '@mui/material';
import { useAuth } from './context/AuthContext';
import Navbar from './components/Navbar';
import Sidebar from './components/Sidebar';
import AuroraBackground from './components/AuroraBackground';
import ProtectedRoute from './components/ProtectedRoute';
import { FeedbackProvider } from './components/Feedback';
import { AuthProvider } from './context/AuthContext';
import Dashboard from './pages/Dashboard';
import ScanPage from './pages/ScanPage';
import ScanResults from './pages/ScanResults';
import BatchScan from './pages/BatchScan';
import History from './pages/History';
import Compare from './pages/Compare';
import Search from './pages/Search';
import Trends from './pages/Trends';
import Login from './pages/Login';
import Schedules from './pages/Schedules';
import BaseImages from './pages/BaseImages';
import BaseImageDetail from './pages/BaseImageDetail';
import SystemStatus from './pages/SystemStatus';
import WorkerMonitor from './pages/WorkerMonitor';
import IacScan from './pages/IacScan';
import Policies from './pages/Policies';
import Compliance from './pages/Compliance';
import DependencyGraph from './pages/DependencyGraph';
import VexManagement from './pages/VexManagement';

const drawerWidth = 280;

// Main layout with sidebar
function MainLayout({ children }) {
  const [mobileOpen, setMobileOpen] = React.useState(false);

  const handleDrawerToggle = () => {
    setMobileOpen(!mobileOpen);
  };

  return (
    <Box sx={{ display: 'flex', minHeight: '100vh' }}>
      <Navbar onMenuClick={handleDrawerToggle} />
      <Sidebar
        mobileOpen={mobileOpen}
        onClose={handleDrawerToggle}
        drawerWidth={drawerWidth}
      />
      <Box
        component="main"
        sx={{
          flexGrow: 1,
          p: 3,
          width: { xs: '100%', sm: `calc(100% - ${drawerWidth}px)` },
          mt: '64px',
          minHeight: 'calc(100vh - 64px)',
          backgroundColor: 'transparent',
        }}
      >
        {children}
      </Box>
    </Box>
  );
}

function AppRoutes() {
  const location = useLocation();
  const { isAuthenticated, loading } = useAuth();

  // Login page has no sidebar
  if (location.pathname === '/login') {
    return (
      <Routes>
        <Route path="/login" element={<Login />} />
      </Routes>
    );
  }

  // While the session cookie is being verified, don't flash the app shell.
  if (loading) {
    return (
      <Box sx={{ display: 'flex', minHeight: '100vh', alignItems: 'center', justifyContent: 'center' }}>
        <CircularProgress />
      </Box>
    );
  }

  // Gate: unauthenticated users go straight to /login (no app shell, no second
  // login entry point). Remember where they were headed.
  if (!isAuthenticated()) {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }

  return (
    <MainLayout>
      <Routes>
        {/* User Routes — accessible to all authenticated users */}
        <Route path="/" element={<Dashboard />} />
        <Route path="/scan" element={<ScanPage />} />
        <Route path="/scan/:scanId" element={<ScanResults />} />
        <Route path="/batch" element={<BatchScan />} />
        <Route path="/history" element={<History />} />
        <Route path="/iac-scan" element={<IacScan />} />

        {/* Admin-Only Routes — analysis & management */}
        <Route path="/compare" element={
          <ProtectedRoute requiredRole="admin"><Compare /></ProtectedRoute>
        } />
        <Route path="/search" element={
          <ProtectedRoute requiredRole="admin"><Search /></ProtectedRoute>
        } />
        <Route path="/trends" element={
          <ProtectedRoute requiredRole="admin"><Trends /></ProtectedRoute>
        } />
        <Route path="/policies" element={
          <ProtectedRoute requiredRole="admin"><Policies /></ProtectedRoute>
        } />
        <Route path="/schedules" element={
          <ProtectedRoute requiredRole="admin"><Schedules /></ProtectedRoute>
        } />
        <Route path="/base-images" element={
          <ProtectedRoute requiredRole="admin"><BaseImages /></ProtectedRoute>
        } />
        <Route path="/base-images/:imageName/:tag" element={
          <ProtectedRoute requiredRole="admin"><BaseImageDetail /></ProtectedRoute>
        } />
        <Route path="/compliance" element={
          <ProtectedRoute requiredRole="admin"><Compliance /></ProtectedRoute>
        } />
        <Route path="/dependency-graph" element={
          <ProtectedRoute requiredRole="admin"><DependencyGraph /></ProtectedRoute>
        } />
        <Route path="/vex" element={
          <ProtectedRoute requiredRole="admin"><VexManagement /></ProtectedRoute>
        } />
        <Route path="/workers" element={
          <ProtectedRoute requiredRole="admin"><WorkerMonitor /></ProtectedRoute>
        } />
        <Route path="/system" element={
          <ProtectedRoute requiredRole="admin"><SystemStatus /></ProtectedRoute>
        } />
      </Routes>
    </MainLayout>
  );
}

function App() {
  return (
    <AuthProvider>
      <FeedbackProvider>
        <AuroraBackground />
        <AppRoutes />
      </FeedbackProvider>
    </AuthProvider>
  );
}

export default App;
