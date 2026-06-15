// ---------------------------------------------------------------------------
// Design tokens — single source of truth for the Apex Scanner UI.
//
// Anything color/severity related MUST come from here so the look stays
// consistent across every page and adapts correctly to light/dark mode.
// Do NOT hardcode severity hex values in components.
// ---------------------------------------------------------------------------

// Monospace stack for data: CVE IDs, versions, digests, package names, numbers.
export const MONO_FONT =
  '"JetBrains Mono", "Fira Code", ui-monospace, "SF Mono", "Cascadia Code", "Roboto Mono", Menlo, Consolas, monospace';

// UI font stack.
export const UI_FONT =
  '"Inter", "Roboto", -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif';

// Slate neutral ramp — used for surfaces, borders, muted text.
export const slate = {
  50: '#F8FAFC',
  100: '#F1F5F9',
  200: '#E2E8F0',
  300: '#CBD5E1',
  400: '#94A3B8',
  500: '#64748B',
  600: '#475569',
  700: '#334155',
  800: '#1E293B',
  900: '#0F172A',
  950: '#0B1220',
};

// ---------------------------------------------------------------------------
// Severity scale.
//
// `solid`/`onSolid`   -> high-emphasis filled chips (AA contrast guaranteed)
// `accentLight/Dark`  -> bars, dots, chart segments (mode-aware brightness)
// `softBg*`/`softFg*` -> low-emphasis tonal surfaces (alerts, row tints)
//
// Ordering is canonical worst-first; use SEVERITY_ORDER to sort/iterate.
// ---------------------------------------------------------------------------
export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'negligible', 'unknown'];

export const severityTokens = {
  critical: {
    label: 'Critical',
    solid: '#C2181B', onSolid: '#FFFFFF',
    accentLight: '#D32F2F', accentDark: '#F87171',
    softBgLight: '#FEECEB', softFgLight: '#B71C1C',
    softBgDark: 'rgba(248,113,113,0.16)', softFgDark: '#FCA5A5',
  },
  high: {
    label: 'High',
    solid: '#C2410C', onSolid: '#FFFFFF',
    accentLight: '#EA580C', accentDark: '#FB923C',
    softBgLight: '#FFF1E8', softFgLight: '#9A3412',
    softBgDark: 'rgba(251,146,60,0.16)', softFgDark: '#FDBA74',
  },
  medium: {
    label: 'Medium',
    solid: '#B45309', onSolid: '#FFFFFF',
    accentLight: '#D97706', accentDark: '#FBBF24',
    softBgLight: '#FEF6E7', softFgLight: '#92400E',
    softBgDark: 'rgba(251,191,36,0.16)', softFgDark: '#FCD34D',
  },
  low: {
    label: 'Low',
    solid: '#15803D', onSolid: '#FFFFFF',
    accentLight: '#16A34A', accentDark: '#4ADE80',
    softBgLight: '#E8F6EC', softFgLight: '#166534',
    softBgDark: 'rgba(74,222,128,0.16)', softFgDark: '#86EFAC',
  },
  negligible: {
    label: 'Negligible',
    solid: '#475569', onSolid: '#FFFFFF',
    accentLight: '#64748B', accentDark: '#94A3B8',
    softBgLight: '#EEF2F6', softFgLight: '#334155',
    softBgDark: 'rgba(148,163,184,0.16)', softFgDark: '#CBD5E1',
  },
  unknown: {
    label: 'Unknown',
    solid: '#64748B', onSolid: '#FFFFFF',
    accentLight: '#94A3B8', accentDark: '#94A3B8',
    softBgLight: '#EEF2F6', softFgLight: '#334155',
    softBgDark: 'rgba(148,163,184,0.16)', softFgDark: '#CBD5E1',
  },
};

// Normalize any severity string to a token (falls back to `unknown`).
export const getSeverity = (severity) =>
  severityTokens[String(severity || '').toLowerCase()] || severityTokens.unknown;

// Mode-aware accent for bars/dots/chart segments.
export const severityAccent = (severity, mode = 'light') => {
  const t = getSeverity(severity);
  return mode === 'dark' ? t.accentDark : t.accentLight;
};

// Mode-aware tonal pair for low-emphasis surfaces.
export const severitySoft = (severity, mode = 'light') => {
  const t = getSeverity(severity);
  return mode === 'dark'
    ? { bg: t.softBgDark, fg: t.softFgDark }
    : { bg: t.softBgLight, fg: t.softFgLight };
};

// Ordered array of {key, ...token} — handy for legends and segmented bars.
export const severityList = SEVERITY_ORDER.map((key) => ({ key, ...severityTokens[key] }));
