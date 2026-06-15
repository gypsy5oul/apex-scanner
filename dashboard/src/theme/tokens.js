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
// Motion + glass tokens (the "aurora glass" concept).
//
// Glass is applied ONLY to chrome (app bar, sidebar) and Cards — never to the
// Paper surfaces that wrap dense/scrolling tables, where backdrop-filter both
// janks and hurts readability. Motion is always gated on prefers-reduced-motion.
// ---------------------------------------------------------------------------

// Shared easing — the expressive "spring-like" curve from the concept.
export const EASING = 'cubic-bezier(0.16, 1, 0.3, 1)';

export const glassTokens = {
  dark: {
    bg: 'rgba(255,255,255,0.055)',
    bgStrong: 'rgba(255,255,255,0.09)',
    border: 'rgba(255,255,255,0.10)',
    borderStrong: 'rgba(255,255,255,0.18)',
    blur: 'blur(22px) saturate(140%)',
    shadow: '0 10px 40px rgba(0,0,0,0.45)',
    sheen: 'inset 0 1px 0 rgba(255,255,255,0.08)',
    hoverShadow: '0 18px 50px rgba(0,0,0,0.55)',
  },
  light: {
    bg: 'rgba(255,255,255,0.60)',
    bgStrong: 'rgba(255,255,255,0.78)',
    border: 'rgba(255,255,255,0.75)',
    borderStrong: 'rgba(59,130,246,0.40)',
    blur: 'blur(26px) saturate(185%)',
    shadow:
      'inset 0 1px 0 rgba(255,255,255,0.95), 0 0 0 1px rgba(15,23,42,0.04), 0 26px 54px -28px rgba(37,99,235,0.40), 0 10px 26px -18px rgba(15,23,42,0.14)',
    sheen: 'inset 0 1px 0 rgba(255,255,255,0.95)',
    hoverShadow:
      'inset 0 1px 0 rgba(255,255,255,0.95), 0 0 0 1px rgba(59,130,246,0.18), 0 34px 64px -26px rgba(37,99,235,0.52)',
  },
};

export const getGlass = (mode = 'light') => glassTokens[mode] || glassTokens.light;

// Full-screen aurora backdrop per mode (consumed by <AuroraBackground/>).
export const aurora = {
  dark: {
    base:
      'radial-gradient(1200px 800px at 80% -10%, rgba(59,130,246,0.12), transparent 60%),' +
      'radial-gradient(1000px 700px at -10% 110%, rgba(99,102,241,0.12), transparent 60%),' +
      'linear-gradient(160deg, #0B1220, #070B14)',
    blobs: ['#2563EB', '#7C3AED', '#06B6D4'],
    blobOpacity: 0.45,
    blobBlur: 80,
  },
  light: {
    base:
      'radial-gradient(820px 560px at 8% -6%, rgba(99,102,241,0.30), transparent 56%),' +
      'radial-gradient(780px 540px at 96% -4%, rgba(56,189,248,0.28), transparent 56%),' +
      'radial-gradient(900px 680px at 48% 116%, rgba(168,85,247,0.22), transparent 58%),' +
      'radial-gradient(680px 520px at 102% 104%, rgba(244,114,182,0.16), transparent 56%),' +
      'linear-gradient(165deg, #FDFEFF, #ECF1FA)',
    blobs: ['#3B82F6', '#A855F7', '#22D3EE'],
    blobOpacity: 0.34,
    blobBlur: 72,
  },
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
