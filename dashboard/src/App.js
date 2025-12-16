import React from 'react';
import { Routes, Route, useLocation } from 'react-router-dom';
import { Box } from '@mui/material';
import Navbar from './components/Navbar';
import Sidebar from './components/Sidebar';
import ProtectedRoute from './components/ProtectedRoute';
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
          backgroundColor: 'background.default',
        }}
      >
        {children}
      </Box>
    </Box>
  );
}

function AppRoutes() {
  const location = useLocation();

  // Login page has no sidebar
  if (location.pathname === '/login') {
    return (
      <Routes>
        <Route path="/login" element={<Login />} />
      </Routes>
    );
  }

  return (
    <MainLayout>
      <Routes>
        {/* Public Routes */}
        <Route path="/" element={<Dashboard />} />
        <Route path="/scan" element={<ScanPage />} />
        <Route path="/scan/:scanId" element={<ScanResults />} />
        <Route path="/batch" element={<BatchScan />} />
        <Route path="/history" element={<History />} />
        <Route path="/compare" element={<Compare />} />
        <Route path="/search" element={<Search />} />
        <Route path="/trends" element={<Trends />} />

        {/* Protected Admin Routes */}
        <Route path="/schedules" element={
          <ProtectedRoute><Schedules /></ProtectedRoute>
        } />
        <Route path="/base-images" element={
          <ProtectedRoute><BaseImages /></ProtectedRoute>
        } />
        <Route path="/base-images/:imageName/:tag" element={
          <ProtectedRoute><BaseImageDetail /></ProtectedRoute>
        } />
        <Route path="/workers" element={
          <ProtectedRoute><WorkerMonitor /></ProtectedRoute>
        } />
        <Route path="/system" element={
          <ProtectedRoute><SystemStatus /></ProtectedRoute>
        } />
      </Routes>
    </MainLayout>
  );
}

function App() {
  return (
    <AuthProvider>
      <AppRoutes />
    </AuthProvider>
  );
}

export default App;
