import React from 'react';
import { Box, Typography } from '@mui/material';

// Brand wordmark font (loaded in index.html); falls back to Inter.
const WORDMARK_FONT = '"Space Grotesk", "Inter", sans-serif';

// The Apex logo lockup: the gradient "A" apex mark (served from /public/brand,
// pure SVG shapes so it's crisp and theme-independent) + the wordmark.
export default function ApexLogo({ size = 40, wordmark = true, tagline = false, sx }) {
  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.25, ...sx }}>
      <Box
        component="img"
        src="/brand/apex-logomark.svg"
        alt="Apex Scanner"
        sx={{
          width: size,
          height: size,
          maxWidth: size,
          objectFit: 'contain',
          display: 'block',
          flexShrink: 0,
        }}
      />
      {wordmark && (
        <Box sx={{ lineHeight: 1.05, minWidth: 0 }}>
          <Typography
            component="span"
            noWrap
            sx={{
              display: 'block',
              fontFamily: WORDMARK_FONT,
              fontWeight: 700,
              fontSize: Math.round(size * 0.42),
              letterSpacing: '-0.02em',
              color: 'text.primary',
            }}
          >
            Apex Scanner
          </Typography>
          {tagline && (
            <Typography
              component="span"
              noWrap
              sx={{
                display: 'block',
                fontFamily: (theme) => theme.custom?.monoFont,
                fontSize: '0.58rem',
                letterSpacing: '0.16em',
                color: 'text.secondary',
                mt: 0.25,
              }}
            >
              PEAK VULNERABILITY DETECTION
            </Typography>
          )}
        </Box>
      )}
    </Box>
  );
}
