import React from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import {
  Drawer,
  List,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Toolbar,
  Divider,
  Box,
  Typography,
  alpha,
  Button,
} from '@mui/material';
import DashboardIcon from '@mui/icons-material/Dashboard';
import ScannerIcon from '@mui/icons-material/DocumentScanner';
import BatchIcon from '@mui/icons-material/ViewList';
import HistoryIcon from '@mui/icons-material/History';
import CompareIcon from '@mui/icons-material/Compare';
import BugReportIcon from '@mui/icons-material/BugReport';
import TrendingUpIcon from '@mui/icons-material/TrendingUp';
import ScheduleIcon from '@mui/icons-material/Schedule';
import LayersIcon from '@mui/icons-material/Layers';
import ChangeHistoryIcon from '@mui/icons-material/ChangeHistory';
import SettingsIcon from '@mui/icons-material/Settings';
import GroupWorkIcon from '@mui/icons-material/GroupWork';
import LoginIcon from '@mui/icons-material/Login';
import LogoutIcon from '@mui/icons-material/Logout';
import AdminPanelSettingsIcon from '@mui/icons-material/AdminPanelSettings';
import { useAuth } from '../context/AuthContext';

const mainMenuItems = [
  { text: 'Dashboard', icon: <DashboardIcon />, path: '/' },
  { text: 'New Scan', icon: <ScannerIcon />, path: '/scan' },
  { text: 'Batch Scan', icon: <BatchIcon />, path: '/batch' },
  { text: 'Scan History', icon: <HistoryIcon />, path: '/history' },
];

const analysisMenuItems = [
  { text: 'Compare Scans', icon: <CompareIcon />, path: '/compare' },
  { text: 'Search CVEs', icon: <BugReportIcon />, path: '/search' },
  { text: 'Trends', icon: <TrendingUpIcon />, path: '/trends' },
];

const enterpriseMenuItems = [
  { text: 'Scheduled Scans', icon: <ScheduleIcon />, path: '/schedules' },
  { text: 'Base Images', icon: <LayersIcon />, path: '/base-images' },
  { text: 'Workers', icon: <GroupWorkIcon />, path: '/workers' },
  { text: 'System Status', icon: <SettingsIcon />, path: '/system' },
];

function Sidebar({ mobileOpen, onClose, drawerWidth }) {
  const navigate = useNavigate();
  const location = useLocation();
  const { isAuthenticated, user, logout } = useAuth();

  const MenuSection = ({ title, items }) => (
    <>
      <Box sx={{ px: 3, py: 1.5 }}>
        <Typography
          variant="overline"
          sx={{
            fontWeight: 600,
            color: 'text.secondary',
            letterSpacing: 1.2,
            fontSize: '0.65rem',
          }}
        >
          {title}
        </Typography>
      </Box>
      <List sx={{ px: 1 }}>
        {items.map((item) => {
          const isSelected = location.pathname === item.path;
          return (
            <ListItem key={item.text} disablePadding sx={{ mb: 0.5 }}>
              <ListItemButton
                selected={isSelected}
                onClick={() => {
                  navigate(item.path);
                  if (mobileOpen) onClose();
                }}
                sx={{
                  borderRadius: 2,
                  mx: 1,
                  '&.Mui-selected': {
                    backgroundColor: (theme) =>
                      alpha(theme.palette.primary.main, 0.12),
                    '&:hover': {
                      backgroundColor: (theme) =>
                        alpha(theme.palette.primary.main, 0.18),
                    },
                    '& .MuiListItemIcon-root': {
                      color: 'primary.main',
                    },
                    '& .MuiListItemText-primary': {
                      fontWeight: 600,
                      color: 'primary.main',
                    },
                  },
                  '&:hover': {
                    backgroundColor: (theme) =>
                      alpha(theme.palette.primary.main, 0.08),
                  },
                }}
              >
                <ListItemIcon
                  sx={{
                    minWidth: 40,
                    color: isSelected ? 'primary.main' : 'text.secondary',
                  }}
                >
                  {item.icon}
                </ListItemIcon>
                <ListItemText
                  primary={item.text}
                  primaryTypographyProps={{
                    fontSize: '0.875rem',
                    fontWeight: isSelected ? 600 : 500,
                  }}
                />
              </ListItemButton>
            </ListItem>
          );
        })}
      </List>
    </>
  );

  const drawer = (
    <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      {/* Spacer for fixed AppBar */}
      <Toolbar />

      {/* Logo Section */}
      <Box sx={{ px: 2, py: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
          <Box
            sx={{
              width: 40,
              height: 40,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              background: (theme) =>
                `linear-gradient(135deg, ${theme.palette.primary.main} 0%, ${theme.palette.secondary.main} 100%)`,
              borderRadius: 2,
              boxShadow: '0 4px 12px rgba(25, 118, 210, 0.3)',
            }}
          >
            <ChangeHistoryIcon
              sx={{
                fontSize: 28,
                color: '#fff',
              }}
            />
          </Box>
          <Box>
            <Typography
              variant="h6"
              sx={{
                fontWeight: 700,
                lineHeight: 1.2,
                background: (theme) =>
                  `linear-gradient(135deg, ${theme.palette.primary.main} 0%, ${theme.palette.secondary.main} 100%)`,
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent',
              }}
            >
              Apex Scanner
            </Typography>
            <Typography
              variant="caption"
              sx={{ color: 'text.secondary', fontSize: '0.65rem' }}
            >
              Peak Vulnerability Detection
            </Typography>
          </Box>
        </Box>
      </Box>
      <Divider />

      <Box sx={{ flexGrow: 1, overflow: 'auto', py: 1 }}>
        <MenuSection title="Scanning" items={mainMenuItems} />
        <Divider sx={{ my: 1.5, mx: 2 }} />
        <MenuSection title="Analysis" items={analysisMenuItems} />

        {/* Enterprise Section - Only show when authenticated */}
        {isAuthenticated() && (
          <>
            <Divider sx={{ my: 1.5, mx: 2 }} />
            <MenuSection title="Admin" items={enterpriseMenuItems} />
          </>
        )}
      </Box>

      <Divider />
      <Box sx={{ p: 2 }}>
        {/* Auth Status Box */}
        <Box
          sx={{
            p: 2,
            borderRadius: 2,
            bgcolor: (theme) => alpha(
              isAuthenticated() ? theme.palette.success.main : theme.palette.grey[500],
              0.08
            ),
            mb: 2,
          }}
        >
          {isAuthenticated() ? (
            <>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                <AdminPanelSettingsIcon sx={{ fontSize: 18, color: 'success.main' }} />
                <Typography variant="caption" color="success.main" fontWeight={600}>
                  Admin Mode
                </Typography>
              </Box>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                Logged in as {user?.username}
              </Typography>
              <Button
                size="small"
                variant="outlined"
                color="inherit"
                startIcon={<LogoutIcon />}
                onClick={logout}
                fullWidth
                sx={{ textTransform: 'none' }}
              >
                Logout
              </Button>
            </>
          ) : (
            <>
              <Typography variant="caption" color="text.secondary" display="block" sx={{ mb: 1 }}>
                Admin features hidden
              </Typography>
              <Button
                size="small"
                variant="contained"
                color="primary"
                startIcon={<LoginIcon />}
                onClick={() => navigate('/login')}
                fullWidth
                sx={{ textTransform: 'none' }}
              >
                Admin Login
              </Button>
            </>
          )}
        </Box>

        {/* Scanners Status */}
        <Box
          sx={{
            p: 2,
            borderRadius: 2,
            bgcolor: (theme) => alpha(theme.palette.primary.main, 0.08),
          }}
        >
          <Typography variant="caption" color="text.secondary" display="block">
            Scanners Active
          </Typography>
          <Box sx={{ display: 'flex', gap: 1, mt: 1 }}>
            <Box
              sx={{
                width: 8,
                height: 8,
                borderRadius: '50%',
                bgcolor: 'success.main',
                mt: 0.5,
              }}
            />
            <Typography variant="body2" fontWeight={500}>
              Grype, Trivy, Syft
            </Typography>
          </Box>
        </Box>
      </Box>
    </Box>
  );

  return (
    <Box
      component="nav"
      sx={{ width: { sm: drawerWidth }, flexShrink: { sm: 0 } }}
    >
      <Drawer
        variant="temporary"
        open={mobileOpen}
        onClose={onClose}
        ModalProps={{ keepMounted: true }}
        sx={{
          display: { xs: 'block', sm: 'none' },
          '& .MuiDrawer-paper': {
            boxSizing: 'border-box',
            width: drawerWidth,
            borderRight: '1px solid',
            borderColor: 'divider',
          },
        }}
      >
        {drawer}
      </Drawer>
      <Drawer
        variant="permanent"
        sx={{
          display: { xs: 'none', sm: 'block' },
          '& .MuiDrawer-paper': {
            boxSizing: 'border-box',
            width: drawerWidth,
            borderRight: '1px solid',
            borderColor: 'divider',
          },
        }}
        open
      >
        {drawer}
      </Drawer>
    </Box>
  );
}

export default Sidebar;
