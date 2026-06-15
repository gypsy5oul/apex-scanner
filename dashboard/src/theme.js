import { createTheme } from '@mui/material/styles';
import { UI_FONT, MONO_FONT, slate, severityTokens, getGlass, EASING } from './theme/tokens';

// ---------------------------------------------------------------------------
// Apex Scanner theme.
//
// One factory builds both light and dark variants so typography, shape,
// spacing and component overrides never drift apart. Enterprise direction:
// "Data-Dense Dashboard" — refined blue, restrained corners, borders over
// heavy shadows, monospace + tabular figures for data, visible focus rings.
// ---------------------------------------------------------------------------

// Mode-aware accent for the `severity` palette slot (bars/dots/charts).
const severityPalette = (mode) =>
  Object.fromEntries(
    Object.entries(severityTokens).map(([k, v]) => [
      k,
      mode === 'dark' ? v.accentDark : v.accentLight,
    ])
  );

const paletteFor = (mode) =>
  mode === 'light'
    ? {
        mode: 'light',
        primary: { main: '#2563EB', light: '#60A5FA', dark: '#1E40AF', contrastText: '#FFFFFF' },
        secondary: { main: '#4F46E5', light: '#818CF8', dark: '#3730A3', contrastText: '#FFFFFF' },
        error: { main: '#DC2626', light: '#F87171', dark: '#B91C1C' },
        warning: { main: '#D97706', light: '#FBBF24', dark: '#B45309' },
        info: { main: '#0284C7', light: '#38BDF8', dark: '#075985' },
        success: { main: '#16A34A', light: '#4ADE80', dark: '#15803D' },
        severity: severityPalette('light'),
        background: { default: slate[50], paper: '#FFFFFF' },
        text: { primary: slate[900], secondary: slate[500], disabled: slate[400] },
        divider: slate[200],
        grey: slate,
      }
    : {
        mode: 'dark',
        primary: { main: '#60A5FA', light: '#93C5FD', dark: '#2563EB', contrastText: '#0B1220' },
        secondary: { main: '#818CF8', light: '#A5B4FC', dark: '#4F46E5', contrastText: '#0B1220' },
        error: { main: '#F87171', light: '#FCA5A5', dark: '#DC2626' },
        warning: { main: '#FBBF24', light: '#FCD34D', dark: '#D97706' },
        info: { main: '#38BDF8', light: '#7DD3FC', dark: '#0284C7' },
        success: { main: '#4ADE80', light: '#86EFAC', dark: '#16A34A' },
        severity: severityPalette('dark'),
        background: { default: slate[950], paper: '#131C2B' },
        text: { primary: '#E5EAF2', secondary: slate[400], disabled: slate[600] },
        divider: 'rgba(148,163,184,0.16)',
        grey: slate,
      };

// Subtle, slate-tinted elevation scale (no colored glow).
const buildShadows = (mode) => {
  const c = mode === 'light' ? '15, 23, 42' : '0, 0, 0';
  const s = (y, blur, a) => `0px ${y}px ${blur}px rgba(${c}, ${a})`;
  return [
    'none',
    s(1, 2, mode === 'light' ? 0.06 : 0.4),
    s(2, 4, mode === 'light' ? 0.08 : 0.45),
    s(4, 8, mode === 'light' ? 0.08 : 0.5),
    s(8, 16, mode === 'light' ? 0.1 : 0.55),
    s(12, 24, mode === 'light' ? 0.12 : 0.6),
    ...Array(19).fill(s(16, 32, mode === 'light' ? 0.14 : 0.6)),
  ];
};

const typography = {
  fontFamily: UI_FONT,
  // Headings: tighter, denser — dashboard not marketing site.
  h1: { fontSize: '2rem', fontWeight: 700, letterSpacing: '-0.02em', lineHeight: 1.2 },
  h2: { fontSize: '1.625rem', fontWeight: 700, letterSpacing: '-0.02em', lineHeight: 1.25 },
  h3: { fontSize: '1.375rem', fontWeight: 600, letterSpacing: '-0.01em', lineHeight: 1.3 },
  h4: { fontSize: '1.15rem', fontWeight: 600, letterSpacing: '-0.01em', lineHeight: 1.35 },
  h5: { fontSize: '1rem', fontWeight: 600, lineHeight: 1.4 },
  h6: { fontSize: '0.9375rem', fontWeight: 600, lineHeight: 1.4 },
  subtitle1: { fontSize: '0.9375rem', fontWeight: 600 },
  subtitle2: { fontSize: '0.8125rem', fontWeight: 600 },
  body1: { fontSize: '0.9375rem', lineHeight: 1.55 },
  body2: { fontSize: '0.8125rem', lineHeight: 1.55 },
  caption: { fontSize: '0.75rem', lineHeight: 1.4 },
  overline: { fontSize: '0.6875rem', fontWeight: 600, letterSpacing: '0.08em' },
  button: { textTransform: 'none', fontWeight: 600, letterSpacing: 0 },
};

const componentsFor = (mode) => {
  const isLight = mode === 'light';
  const borderColor = isLight ? slate[200] : 'rgba(148,163,184,0.16)';
  const headBg = isLight ? slate[50] : 'rgba(148,163,184,0.06)';
  const g = getGlass(mode);
  // Chrome (app bar / drawer) is a touch more opaque than cards so its
  // content stays legible over whatever scrolls behind it.
  const chromeBg = isLight ? 'rgba(255,255,255,0.70)' : 'rgba(11,18,32,0.72)';
  return {
    MuiCssBaseline: {
      styleOverrides: {
        // Visible, on-brand keyboard focus ring everywhere (a11y).
        '*:focus-visible': {
          outline: `2px solid ${isLight ? '#2563EB' : '#60A5FA'}`,
          outlineOffset: '2px',
        },
        // Body is transparent so the fixed <AuroraBackground/> shows through;
        // html keeps a solid fallback color. Tabular figures by default.
        html: { backgroundColor: isLight ? slate[50] : slate[950] },
        body: { fontVariantNumeric: 'tabular-nums', backgroundColor: 'transparent' },
        // Quiet, themed scrollbars.
        '*::-webkit-scrollbar': { width: 10, height: 10 },
        '*::-webkit-scrollbar-thumb': {
          backgroundColor: isLight ? slate[300] : slate[700],
          borderRadius: 8,
          border: `2px solid ${isLight ? slate[50] : slate[950]}`,
        },
        '*::-webkit-scrollbar-track': { backgroundColor: 'transparent' },
        '@media (prefers-reduced-motion: reduce)': {
          '*': { animationDuration: '0.01ms !important', transitionDuration: '0.01ms !important' },
        },
      },
    },
    MuiButton: {
      defaultProps: { disableElevation: true },
      styleOverrides: {
        root: { borderRadius: 8, padding: '8px 16px', fontWeight: 600 },
        sizeSmall: { padding: '4px 12px' },
        containedPrimary: { '&:hover': { backgroundColor: isLight ? '#1D4ED8' : '#3B82F6' } },
      },
    },
    MuiCard: {
      defaultProps: { elevation: 0 },
      styleOverrides: {
        // Glass surface — translucent + frosted, with a top-edge sheen and
        // a tinted depth shadow. Used for KPI/stat/panel cards (not tables).
        root: {
          borderRadius: 16,
          border: `1px solid ${g.border}`,
          background: g.bg,
          backdropFilter: g.blur,
          WebkitBackdropFilter: g.blur,
          backgroundImage: 'none',
          boxShadow: `${g.sheen}, ${g.shadow}`,
          transition: `transform 0.35s ${EASING}, border-color 0.35s ${EASING}, box-shadow 0.35s ${EASING}`,
          '&:hover': {
            transform: 'translateY(-4px)',
            borderColor: g.borderStrong,
            boxShadow: g.hoverShadow,
          },
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: { backgroundImage: 'none' },
        outlined: { borderColor },
        elevation1: {
          boxShadow: isLight ? '0px 1px 3px rgba(15,23,42,0.08)' : '0px 1px 3px rgba(0,0,0,0.5)',
        },
      },
    },
    MuiChip: {
      styleOverrides: {
        root: { borderRadius: 6, fontWeight: 600 },
        sizeSmall: { height: 22, fontSize: '0.7rem' },
        label: { fontVariantNumeric: 'tabular-nums' },
      },
    },
    MuiTableHead: {
      styleOverrides: {
        root: {
          '& .MuiTableCell-head': {
            fontWeight: 600,
            fontSize: '0.75rem',
            letterSpacing: '0.04em',
            textTransform: 'uppercase',
            color: isLight ? slate[500] : slate[400],
            backgroundColor: headBg,
            whiteSpace: 'nowrap',
          },
        },
      },
    },
    MuiTableCell: {
      styleOverrides: {
        root: { borderColor, fontVariantNumeric: 'tabular-nums', padding: '10px 16px' },
      },
    },
    MuiTableRow: {
      styleOverrides: {
        hover: { '&:hover': { backgroundColor: isLight ? slate[50] : 'rgba(148,163,184,0.06)' } },
      },
    },
    MuiTooltip: {
      styleOverrides: {
        tooltip: {
          backgroundColor: isLight ? slate[800] : slate[700],
          fontSize: '0.75rem',
          fontWeight: 500,
          padding: '6px 10px',
          borderRadius: 6,
        },
      },
    },
    MuiDrawer: {
      styleOverrides: {
        paper: {
          borderRight: `1px solid ${g.border}`,
          backgroundColor: chromeBg,
          backdropFilter: g.blur,
          WebkitBackdropFilter: g.blur,
          backgroundImage: 'none',
          boxShadow: 'none',
        },
      },
    },
    MuiAppBar: {
      styleOverrides: {
        root: {
          backgroundColor: chromeBg,
          backdropFilter: g.blur,
          WebkitBackdropFilter: g.blur,
          color: isLight ? slate[900] : '#E5EAF2',
          borderBottom: `1px solid ${g.border}`,
          boxShadow: 'none',
        },
      },
    },
    MuiLinearProgress: { styleOverrides: { root: { borderRadius: 4, height: 8 } } },
    MuiAlert: { styleOverrides: { root: { borderRadius: 8 } } },
    MuiListItemButton: { styleOverrides: { root: { borderRadius: 8 } } },
  };
};

export const createAppTheme = (mode = 'light') =>
  createTheme({
    palette: paletteFor(mode),
    typography,
    shape: { borderRadius: 8 },
    shadows: buildShadows(mode),
    components: componentsFor(mode),
    // Expose the monospace stack + shared easing for components/sx callbacks.
    custom: { monoFont: MONO_FONT, easing: EASING },
  });

export const lightTheme = createAppTheme('light');
export const darkTheme = createAppTheme('dark');

const themes = { lightTheme, darkTheme };
export default themes;
