import React from 'react';
import { Chip } from '@mui/material';
import { getSeverity } from '../theme/tokens';

// Severity badge — the product's primary visual signal.
// Colors come from the central token scale (AA-contrast, dark-mode aware).
// Renders the severity name as text (never color-only) so it remains
// readable for color-blind users and screen readers.
function SeverityChip({ severity, count, size = 'small', variant = 'filled' }) {
  const token = getSeverity(severity);
  const label =
    count !== undefined ? `${token.label}: ${count}` : token.label;

  const filledSx = {
    backgroundColor: token.solid,
    color: token.onSolid,
    fontWeight: 700,
    letterSpacing: '0.01em',
    '& .MuiChip-label': { fontVariantNumeric: 'tabular-nums' },
  };

  return (
    <Chip
      label={label}
      size={size}
      variant={variant === 'outlined' ? 'outlined' : 'filled'}
      aria-label={
        count !== undefined
          ? `${token.label} severity, ${count}`
          : `${token.label} severity`
      }
      sx={
        variant === 'outlined'
          ? { borderColor: token.solid, color: token.solid, fontWeight: 700 }
          : filledSx
      }
    />
  );
}

export default SeverityChip;
