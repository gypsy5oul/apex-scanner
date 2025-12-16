import React from 'react';
import { Chip } from '@mui/material';

const severityColors = {
  critical: { bg: '#d32f2f', color: '#fff' },
  high: { bg: '#f57c00', color: '#fff' },
  medium: { bg: '#fbc02d', color: '#000' },
  low: { bg: '#388e3c', color: '#fff' },
  negligible: { bg: '#9e9e9e', color: '#fff' },
  unknown: { bg: '#757575', color: '#fff' },
};

function SeverityChip({ severity, count }) {
  const sev = severity?.toLowerCase() || 'unknown';
  const colors = severityColors[sev] || severityColors.unknown;

  return (
    <Chip
      label={count !== undefined ? `${severity}: ${count}` : severity}
      size="small"
      sx={{
        backgroundColor: colors.bg,
        color: colors.color,
        fontWeight: 'bold',
      }}
    />
  );
}

export default SeverityChip;
