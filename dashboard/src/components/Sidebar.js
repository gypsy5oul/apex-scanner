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
import SettingsIcon from '@mui/icons-material/Settings';
import GroupWorkIcon from '@mui/icons-material/GroupWork';
import SecurityIcon from '@mui/icons-material/Security';
import PolicyIcon from '@mui/icons-material/Policy';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import AccountTreeIcon from '@mui/icons-material/AccountTree';
import GavelIcon from '@mui/icons-material/Gavel';
import ApexLogo from './ApexLogo';
import { useAuth } from '../context/AuthContext';

const mainMenuItems = [
  { text: 'Dashboard', icon: <DashboardIcon />, path: '/' },
  { text: 'New Scan', icon: <ScannerIcon />, path: '/scan' },
  { text: 'IaC Scan', icon: <SecurityIcon />, path: '/iac-scan' },
  { text: 'Batch Scan', icon: <BatchIcon />, path: '/batch' },
  { text: 'Scan History', icon: <HistoryIcon />, path: '/history' },
];

const analysisMenuItems = [
  { text: 'Compare Scans', icon: <CompareIcon />, path: '/compare' },
  { text: 'Search CVEs', icon: <BugReportIcon />, path: '/search' },
  { text: 'Trends', icon: <TrendingUpIcon />, path: '/trends' },
  { text: 'Policies', icon: <PolicyIcon />, path: '/policies' },
  { text: 'Compliance', icon: <GavelIcon />, path: '/compliance' },
  { text: 'Dependencies', icon: <AccountTreeIcon />, path: '/dependency-graph' },
  { text: 'VEX', icon: <VerifiedUserIcon />, path: '/vex' },
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
  const { isAdmin } = useAuth();

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
                  position: 'relative',
                  transition: (theme) =>
                    `background-color 0.2s ${theme.custom?.easing || 'ease'}`,
                  '&.Mui-selected': {
                    background: (theme) =>
                      `linear-gradient(100deg, ${alpha(theme.palette.primary.main, 0.20)}, ${alpha(theme.palette.secondary.main, 0.12)})`,
                    '&:hover': {
                      background: (theme) =>
                        `linear-gradient(100deg, ${alpha(theme.palette.primary.main, 0.26)}, ${alpha(theme.palette.secondary.main, 0.16)})`,
                    },
                    // Glowing accent bar on the left edge.
                    '&::before': {
                      content: '""',
                      position: 'absolute',
                      left: 2,
                      top: '22%',
                      height: '56%',
                      width: 3,
                      borderRadius: 3,
                      backgroundColor: 'info.main',
                      boxShadow: (theme) => `0 0 12px ${theme.palette.info.main}`,
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
        <ApexLogo size={34} tagline />
      </Box>
      <Divider />

      <Box sx={{ flexGrow: 1, overflow: 'auto', py: 1 }}>
        <MenuSection title="Scanning" items={mainMenuItems} />

        {/* Analysis Section - Admin only */}
        {isAdmin() && (
          <>
            <Divider sx={{ my: 1.5, mx: 2 }} />
            <MenuSection title="Analysis" items={analysisMenuItems} />
          </>
        )}

        {/* Enterprise Section - Admin only */}
        {isAdmin() && (
          <>
            <Divider sx={{ my: 1.5, mx: 2 }} />
            <MenuSection title="Admin" items={enterpriseMenuItems} />
          </>
        )}
      </Box>

      <Divider />
      <Box sx={{ p: 2 }}>
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
