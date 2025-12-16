import React from 'react';
import {
  AppBar,
  Toolbar,
  Typography,
  IconButton,
  Box,
  Chip,
  Tooltip,
  Badge,
  Avatar,
  alpha,
} from '@mui/material';
import MenuIcon from '@mui/icons-material/Menu';
import Brightness4Icon from '@mui/icons-material/Brightness4';
import Brightness7Icon from '@mui/icons-material/Brightness7';
import NotificationsIcon from '@mui/icons-material/Notifications';
import { useTheme as useMuiTheme } from '@mui/material/styles';
import { useTheme } from '../context/ThemeContext';

function Navbar({ onMenuClick }) {
  const muiTheme = useMuiTheme();
  const { mode, toggleTheme } = useTheme();

  return (
    <AppBar
      position="fixed"
      elevation={0}
      sx={{
        zIndex: (theme) => theme.zIndex.drawer + 1,
        backdropFilter: 'blur(8px)',
        backgroundColor: (theme) =>
          alpha(theme.palette.background.paper, 0.9),
        borderBottom: '1px solid',
        borderColor: 'divider',
      }}
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
            <Chip
              label="Grype"
              size="small"
              sx={{
                bgcolor: (theme) => alpha(theme.palette.success.main, 0.1),
                color: 'success.main',
                fontWeight: 600,
                fontSize: '0.7rem',
                height: 24,
              }}
            />
            <Chip
              label="Trivy"
              size="small"
              sx={{
                bgcolor: (theme) => alpha(theme.palette.success.main, 0.1),
                color: 'success.main',
                fontWeight: 600,
                fontSize: '0.7rem',
                height: 24,
              }}
            />
            <Chip
              label="Syft"
              size="small"
              sx={{
                bgcolor: (theme) => alpha(theme.palette.success.main, 0.1),
                color: 'success.main',
                fontWeight: 600,
                fontSize: '0.7rem',
                height: 24,
              }}
            />
          </Box>

          {/* Dark Mode Toggle */}
          <Tooltip title={mode === 'dark' ? 'Light mode' : 'Dark mode'}>
            <IconButton
              onClick={toggleTheme}
              sx={{
                color: 'text.primary',
                bgcolor: (theme) => alpha(theme.palette.primary.main, 0.08),
                '&:hover': {
                  bgcolor: (theme) => alpha(theme.palette.primary.main, 0.15),
                },
              }}
            >
              {mode === 'dark' ? <Brightness7Icon /> : <Brightness4Icon />}
            </IconButton>
          </Tooltip>

          {/* Notifications */}
          <Tooltip title="Notifications">
            <IconButton
              sx={{
                color: 'text.primary',
                bgcolor: (theme) => alpha(theme.palette.primary.main, 0.08),
                '&:hover': {
                  bgcolor: (theme) => alpha(theme.palette.primary.main, 0.15),
                },
              }}
            >
              <Badge badgeContent={3} color="error">
                <NotificationsIcon />
              </Badge>
            </IconButton>
          </Tooltip>

          {/* User Avatar */}
          <Tooltip title="Apex Admin">
            <Avatar
              sx={{
                ml: 1,
                width: 36,
                height: 36,
                bgcolor: 'primary.main',
                cursor: 'pointer',
                fontWeight: 600,
              }}
            >
              A
            </Avatar>
          </Tooltip>
        </Box>
      </Toolbar>
    </AppBar>
  );
}

export default Navbar;
