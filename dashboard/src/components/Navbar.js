import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  AppBar,
  Toolbar,
  Typography,
  IconButton,
  Box,
  Chip,
  Tooltip,
  Avatar,
  Menu,
  MenuItem,
  Divider,
  ListItemIcon,
  alpha,
} from '@mui/material';
import MenuIcon from '@mui/icons-material/Menu';
import Brightness4Icon from '@mui/icons-material/Brightness4';
import Brightness7Icon from '@mui/icons-material/Brightness7';
import NotificationsIcon from '@mui/icons-material/Notifications';
import LogoutIcon from '@mui/icons-material/Logout';
import AdminPanelSettingsIcon from '@mui/icons-material/AdminPanelSettings';
import { useTheme } from '../context/ThemeContext';
import { useAuth } from '../context/AuthContext';

function Navbar({ onMenuClick }) {
  const navigate = useNavigate();
  const { mode, toggleTheme } = useTheme();
  const { user, isAdmin, logout } = useAuth();

  const [anchorEl, setAnchorEl] = useState(null);
  const menuOpen = Boolean(anchorEl);

  const handleLogout = async () => {
    setAnchorEl(null);
    // logout() clears the session cookie; for SSO it may redirect the browser
    // to Keycloak to end the SSO session (single logout).
    await logout();
    navigate('/login');
  };

  const scannerChipSx = {
    bgcolor: (theme) => alpha(theme.palette.success.main, 0.1),
    color: 'success.main',
    fontWeight: 600,
    fontSize: '0.7rem',
    height: 24,
  };
  const iconBtnSx = {
    color: 'text.primary',
    bgcolor: (theme) => alpha(theme.palette.primary.main, 0.08),
    '&:hover': { bgcolor: (theme) => alpha(theme.palette.primary.main, 0.15) },
  };

  return (
    <AppBar
      position="fixed"
      elevation={0}
      sx={{ zIndex: (theme) => theme.zIndex.drawer + 1 }}
    >
      <Toolbar>
        <IconButton
          edge="start"
          onClick={onMenuClick}
          sx={{ mr: 2, display: { sm: 'none' }, color: 'text.primary' }}
        >
          <MenuIcon />
        </IconButton>

        <Box sx={{ flexGrow: 1 }} />

        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          {/* Scanner Status Chips */}
          <Box sx={{ display: { xs: 'none', md: 'flex' }, gap: 0.5, mr: 2 }}>
            <Chip label="Grype" size="small" sx={scannerChipSx} />
            <Chip label="Trivy" size="small" sx={scannerChipSx} />
            <Chip label="Syft" size="small" sx={scannerChipSx} />
          </Box>

          {/* Dark Mode Toggle */}
          <Tooltip title={mode === 'dark' ? 'Light mode' : 'Dark mode'}>
            <IconButton
              onClick={toggleTheme}
              aria-label={mode === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
              sx={iconBtnSx}
            >
              {mode === 'dark' ? <Brightness7Icon /> : <Brightness4Icon />}
            </IconButton>
          </Tooltip>

          {/* Notifications */}
          <Tooltip title="Notifications">
            <IconButton aria-label="Notifications" sx={iconBtnSx}>
              <NotificationsIcon />
            </IconButton>
          </Tooltip>

          {/* Account menu */}
          <Tooltip title="Account">
            <IconButton
              onClick={(e) => setAnchorEl(e.currentTarget)}
              size="small"
              sx={{ ml: 1 }}
              aria-label="Account menu"
              aria-haspopup="true"
              aria-expanded={menuOpen ? 'true' : undefined}
            >
              <Avatar
                sx={{
                  width: 36,
                  height: 36,
                  bgcolor: isAdmin() ? 'primary.main' : 'info.main',
                  fontWeight: 600,
                }}
              >
                {user?.username ? user.username.charAt(0).toUpperCase() : '?'}
              </Avatar>
            </IconButton>
          </Tooltip>
          <Menu
            anchorEl={anchorEl}
            open={menuOpen}
            onClose={() => setAnchorEl(null)}
            anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
            transformOrigin={{ vertical: 'top', horizontal: 'right' }}
            slotProps={{ paper: { sx: { mt: 1, minWidth: 210 } } }}
          >
            <Box sx={{ px: 2, py: 1 }}>
              <Typography variant="subtitle2" fontWeight={700} noWrap>
                {user?.username || 'Guest'}
              </Typography>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mt: 0.25 }}>
                <AdminPanelSettingsIcon
                  sx={{ fontSize: 14, color: isAdmin() ? 'primary.main' : 'text.secondary' }}
                />
                <Typography variant="caption" color="text.secondary">
                  {isAdmin() ? 'Administrator' : 'Scan User'}
                </Typography>
              </Box>
            </Box>
            <Divider />
            <MenuItem onClick={handleLogout}>
              <ListItemIcon>
                <LogoutIcon fontSize="small" />
              </ListItemIcon>
              Logout
            </MenuItem>
          </Menu>
        </Box>
      </Toolbar>
    </AppBar>
  );
}

export default Navbar;
