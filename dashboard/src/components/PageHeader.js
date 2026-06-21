import React from 'react';
import { Box, Typography } from '@mui/material';

// The single page frame: a Space Grotesk title (brand display face, via the
// h4 theme variant), an optional one-line description, and a right-aligned
// actions slot. Used on every page so the shell is predictable — that
// consistency is what reads as enterprise-grade.
export default function PageHeader({ title, description, actions, sx }) {
  return (
    <Box
      sx={{
        display: 'flex',
        flexWrap: 'wrap',
        gap: 2,
        alignItems: 'flex-start',
        justifyContent: 'space-between',
        mb: 3,
        ...sx,
      }}
    >
      <Box sx={{ minWidth: 0 }}>
        <Typography variant="h4">{title}</Typography>
        {description && (
          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
            {description}
          </Typography>
        )}
      </Box>
      {actions && (
        <Box sx={{ display: 'flex', gap: 1.5, flexWrap: 'wrap', alignItems: 'center' }}>
          {actions}
        </Box>
      )}
    </Box>
  );
}
