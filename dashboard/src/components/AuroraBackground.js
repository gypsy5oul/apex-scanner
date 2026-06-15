import React from 'react';
import { Box } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import { keyframes } from '@emotion/react';
import { aurora, EASING } from '../theme/tokens';

// Fixed, full-screen animated backdrop behind the whole app. Mode-aware
// (vivid light aurora vs deep dark blobs). Purely decorative — aria-hidden,
// pointer-events none — and animation is dropped under reduced-motion.
const drifts = [
  keyframes`to { transform: translate(120px, 80px) scale(1.15) }`,
  keyframes`to { transform: translate(-100px, 60px) scale(1.10) }`,
  keyframes`to { transform: translate(80px, -90px) scale(1.20) }`,
];

const POS = [
  { left: '-120px', top: '-80px', size: 520, dur: '22s' },
  { right: '-120px', top: '20%', size: 460, dur: '26s' },
  { left: '30%', bottom: '-160px', size: 420, dur: '30s' },
];

export default function AuroraBackground() {
  const theme = useTheme();
  const a = aurora[theme.palette.mode] || aurora.light;
  const fade = theme.palette.mode === 'light' ? '62%' : '65%';

  return (
    <Box
      aria-hidden
      sx={{
        position: 'fixed',
        inset: 0,
        zIndex: -1,
        overflow: 'hidden',
        pointerEvents: 'none',
        background: a.base,
      }}
    >
      {a.blobs.map((color, i) => {
        const p = POS[i];
        return (
          <Box
            key={i}
            sx={{
              position: 'absolute',
              left: p.left,
              right: p.right,
              top: p.top,
              bottom: p.bottom,
              width: p.size,
              height: p.size,
              borderRadius: '50%',
              background: `radial-gradient(circle, ${color}, transparent ${fade})`,
              filter: `blur(${a.blobBlur}px)`,
              opacity: a.blobOpacity,
              willChange: 'transform',
              animation: `${drifts[i]} ${p.dur} ${EASING} infinite alternate`,
              '@media (prefers-reduced-motion: reduce)': { animation: 'none' },
            }}
          />
        );
      })}
    </Box>
  );
}
