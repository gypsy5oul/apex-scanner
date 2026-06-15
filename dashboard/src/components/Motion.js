import React, { useEffect, useRef, useState } from 'react';
import { Box } from '@mui/material';
import { keyframes } from '@emotion/react';
import { EASING } from '../theme/tokens';

// Motion primitives. Both honor prefers-reduced-motion: Reveal renders fully
// visible with no animation, CountUp jumps straight to the final value.

const prefersReduced = () =>
  typeof window !== 'undefined' &&
  window.matchMedia &&
  window.matchMedia('(prefers-reduced-motion: reduce)').matches;

const rise = keyframes`
  from { opacity: 0; transform: translateY(18px); }
  to   { opacity: 1; transform: none; }
`;

// Staggered entrance. Pass `delay` (seconds) to sequence siblings.
export function Reveal({ children, delay = 0, sx, ...rest }) {
  const reduce = prefersReduced();
  return (
    <Box
      {...rest}
      sx={{
        ...(reduce
          ? {}
          : {
              opacity: 0,
              animation: `${rise} 0.7s ${EASING} forwards`,
              animationDelay: `${delay}s`,
            }),
        ...sx,
      }}
    >
      {children}
    </Box>
  );
}

// Animated number count-up (ease-out cubic). `format` overrides toLocaleString.
export function CountUp({ value = 0, duration = 1100, format, sx }) {
  const safe = Number.isFinite(+value) ? +value : 0;
  const [n, setN] = useState(() => (prefersReduced() ? safe : 0));
  const ref = useRef(safe);
  ref.current = safe;

  useEffect(() => {
    if (prefersReduced()) {
      setN(safe);
      return undefined;
    }
    let raf;
    const t0 = performance.now();
    const tick = (t) => {
      const p = Math.min(1, (t - t0) / duration);
      const e = 1 - Math.pow(1 - p, 3);
      setN(Math.round(ref.current * e));
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [safe, duration]);

  const out = format ? format(n) : n.toLocaleString();
  return (
    <Box component="span" sx={{ fontVariantNumeric: 'tabular-nums', ...sx }}>
      {out}
    </Box>
  );
}
