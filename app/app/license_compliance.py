"""
License compliance analysis for container scan results.

The Syft SBOM already extracts license strings from every package. This module
normalises those strings (which arrive as a mix of SPDX IDs, Fedora-style
names, and compound expressions like "MIT AND GPL-2.0-or-later"), classifies
each into a category, and applies a default policy that flags the licenses
most enterprises forbid in shipped binaries:

  - network_copyleft  (AGPL, SSPL)             → FAIL: forces SaaS source disclosure
  - source_available  (BSL, Elastic, Commons)  → WARN: commercial-use restrictions
  - strong_copyleft   (GPL, EPL, OSL)          → WARN: viral on binary distribution
  - proprietary       ("All Rights Reserved")  → WARN: legal review needed
  - unknown / empty                            → INFO: requires manual classification
  - weak_copyleft     (LGPL, MPL, CDDL)        → INFO: linking rules apply
  - permissive        (MIT, BSD, Apache, ISC)  → PASS

The classifier intentionally takes the WORST category across a compound
expression — "MIT AND GPL-2.0" is treated as GPL, because that's the effective
constraint on the combined work.

This is a static-data classifier; it does NOT call any external service.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from typing import Dict, List, Set, Tuple


# ---------------------------------------------------------------------------
# Category model
# ---------------------------------------------------------------------------

# Ordered most-restrictive → least-restrictive. When a package carries a
# compound expression, the smallest index wins (= the most-restrictive
# category bubbles up).
CATEGORY_ORDER = [
    "network_copyleft",
    "source_available",
    "strong_copyleft",
    "proprietary",
    "unknown",
    "weak_copyleft",
    "permissive",
]

# Policy severity for each category. "fail" means the scan as a whole should
# surface a red banner; "warn" is yellow; "info" is just a count.
DEFAULT_POLICY: Dict[str, str] = {
    "network_copyleft": "fail",
    "source_available": "warn",
    "proprietary":      "warn",
    "strong_copyleft":  "warn",
    "unknown":          "info",
    "weak_copyleft":    "info",
    "permissive":       "pass",
}

# Short human-readable blurb shown next to the count on the report.
CATEGORY_DESCRIPTIONS: Dict[str, str] = {
    "network_copyleft": "AGPL / SSPL — forces source disclosure even for SaaS use",
    "source_available": "BSL / Elastic / Commons Clause — commercial-use restrictions",
    "strong_copyleft":  "GPL / EPL — viral on binary distribution",
    "proprietary":      "Closed / commercial — requires legal review",
    "unknown":          "License not declared or not recognized — review needed",
    "weak_copyleft":    "LGPL / MPL / CDDL — linking rules apply",
    "permissive":       "MIT / BSD / Apache / ISC — no obligations beyond attribution",
}


# ---------------------------------------------------------------------------
# License → category mapping
# ---------------------------------------------------------------------------

# Lowercased license tokens. Matching is exact after normalisation; for
# fuzzy matches (e.g. "GPLv2+ or LGPLv3+") we split into tokens first.
_NETWORK_COPYLEFT = {
    "agpl-1.0", "agpl-1.0-only", "agpl-1.0-or-later",
    "agpl-3.0", "agpl-3.0-only", "agpl-3.0-or-later",
    "agpl",  "agplv3", "agplv3+",
    "sspl-1.0", "sspl",  # MongoDB SSPL is also network-restrictive
}

_SOURCE_AVAILABLE = {
    # Business Source License (Sentry, MariaDB MaxScale, CockroachDB, etc.)
    "bsl-1.1", "bsl-1.0-or-later", "business source license", "bsl",
    # Elastic License (Elasticsearch, Kibana since 2021)
    "elastic-2.0", "elasticv2", "elastic license",
    # Confluent
    "confluent community license",
    # Commons Clause (often added on top of another OSS license)
    "commons clause",
    # Server Side Public License (already in network_copyleft but list here too
    # because some manifests label it as source-available).
}

_STRONG_COPYLEFT = {
    "gpl-1.0",  "gpl-1.0-only",  "gpl-1.0-or-later",
    "gpl-2.0",  "gpl-2.0-only",  "gpl-2.0-or-later",
    "gpl-3.0",  "gpl-3.0-only",  "gpl-3.0-or-later",
    "gpl", "gplv1", "gplv1+",
    "gplv2", "gplv2+", "gplv2 or later", "gpl version 2",
    "gplv3", "gplv3+", "gplv3 or later",
    "epl-1.0", "epl-2.0", "epl",
    "osl-1.0", "osl-2.0", "osl-3.0",
    "rpsl", "rpsl-1.0",
    "qpl-1.0",
}

_PROPRIETARY = {
    "proprietary", "commercial", "closed",
    "all rights reserved", "all-rights-reserved",
    "nonfree", "non-free",
}

_WEAK_COPYLEFT = {
    "lgpl-2.0", "lgpl-2.0-only", "lgpl-2.0-or-later",
    "lgpl-2.1", "lgpl-2.1-only", "lgpl-2.1-or-later",
    "lgpl-3.0", "lgpl-3.0-only", "lgpl-3.0-or-later",
    "lgpl", "lgplv2", "lgplv2+", "lgplv3", "lgplv3+",
    "mpl-1.0", "mpl-1.1", "mpl-2.0", "mpl", "mplv2.0",
    "cddl-1.0", "cddl-1.1", "cddl",
    "epl-1.0 with file scope",
}

_PERMISSIVE = {
    "mit", "mit-0", "mit license", "expat",
    "bsd", "bsd-2-clause", "bsd-3-clause", "bsd-4-clause",
    "bsd-3-clause-clear", "bsd-2-clause-views",
    "isc",
    "apache-1.1", "apache-2.0", "apache 2.0", "apache license, version 2.0",
    "asl 1.1", "asl 2.0",  # Apache Software License (Fedora-style)
    "zlib", "zlib/libpng", "zlib and boost", "bsl-1.0",  # Boost Software License (different from BSL!)
    "boost",  # standalone — appears alongside zlib in some RPM specs
    "boost software license", "boost software license 1.0",
    "unlicense", "cc0", "cc0-1.0", "cc-by-3.0", "cc-by-4.0",
    "wtfpl",
    "ms-pl", "ms-rl",
    "python-2.0", "python-2.0.1", "psf-2.0",
    "openssl", "ssleay",
    "x11", "mit x11",
    "public domain", "publicdomain",
    "ofl-1.1", "ofl",
    "hpnd",  "hpnd-sell-variant",
    "afl-2.1", "afl-3.0",
    "ncsa", "uiuc",
    "fsful", "fsfullr", "fsfap",
    "gfdl", "gfdl-1.1", "gfdl-1.2", "gfdl-1.3", "gfdl-1.1-or-later", "gfdl-1.3-only", "gfdl-1.1-only",
    "unicode-3.0", "unicode-tou",
}

# Tokens that should be treated as "unknown" rather than triggering a false
# match in _PERMISSIVE/etc. (e.g. "pubkey" was real data we saw in RPMs).
_KNOWN_UNKNOWN = {
    "unknown", "noassertion", "none", "n/a", "na", "license",
    "pubkey", "see-license-file",
}


def _normalise(token: str) -> str:
    """Lowercase, trim, strip parens and trailing '+'."""
    s = token.strip().lower()
    s = s.strip("()[]{} ")
    return s


def classify_one(license_str: str) -> str:
    """Return the most-restrictive category for a single license expression.

    Handles SPDX-style names, Fedora-style names ("GPLv2+", "ASL 2.0"),
    compound expressions joined by AND/OR/WITH, and trailing punctuation.
    """
    if not license_str:
        return "unknown"

    raw = license_str.strip()
    if not raw:
        return "unknown"

    # Split compound expressions. AND/OR/WITH must be **whitespace-bounded**
    # to avoid eating substrings inside identifiers like "LGPL-2.1-or-later"
    # or "GCC-exception-2.0". Per SPDX, operators are uppercase + surrounded
    # by spaces; Fedora-style is lowercase but still space-bounded.
    parts = re.split(r"\s+(?:AND|OR|WITH|and|or|with)\s+|[,;|/]+", raw)
    parts = [_normalise(p) for p in parts if p and p.strip()]
    if not parts:
        return "unknown"

    # Pick the worst recognized category across the parts. We deliberately
    # ignore "unknown" parts when there is at least one known classification:
    # a compound like "LGPL-3.0 WITH GCC-exception-3.1" must stay as
    # weak_copyleft, not get demoted to "unknown" because the exception
    # clause isn't in our table. If every part is unknown, the whole
    # expression is unknown.
    best_idx = len(CATEGORY_ORDER)
    saw_known = False
    for p in parts:
        cat = _classify_token(p)
        if cat != "unknown":
            saw_known = True
            idx = CATEGORY_ORDER.index(cat)
            if idx < best_idx:
                best_idx = idx
    if not saw_known:
        return "unknown"
    return CATEGORY_ORDER[best_idx]


def _classify_token(token: str) -> str:
    """Classify a single normalised token."""
    if not token or token in _KNOWN_UNKNOWN:
        return "unknown"

    # Strip trailing `+`/`or later` markers for set lookup, but check the
    # full token first so e.g. "gpl-2.0-or-later" matches before fallback.
    if token in _NETWORK_COPYLEFT: return "network_copyleft"
    if token in _SOURCE_AVAILABLE: return "source_available"
    if token in _STRONG_COPYLEFT:  return "strong_copyleft"
    if token in _PROPRIETARY:      return "proprietary"
    if token in _WEAK_COPYLEFT:    return "weak_copyleft"
    if token in _PERMISSIVE:       return "permissive"

    stripped = token.rstrip("+").strip()
    if stripped != token:
        # Try again without the "+" suffix.
        if stripped in _NETWORK_COPYLEFT: return "network_copyleft"
        if stripped in _SOURCE_AVAILABLE: return "source_available"
        if stripped in _STRONG_COPYLEFT:  return "strong_copyleft"
        if stripped in _PROPRIETARY:      return "proprietary"
        if stripped in _WEAK_COPYLEFT:    return "weak_copyleft"
        if stripped in _PERMISSIVE:       return "permissive"

    # Fall through to prefix heuristics. These catch unusual variants like
    # "gpl-2.0+ with classpath exception" or "agplv3 (modified)".
    if token.startswith(("agpl", "sspl")):
        return "network_copyleft"
    if token.startswith(("bsl-1.1", "elastic-", "elastic license", "commons clause", "confluent")):
        return "source_available"
    if "agpl" in token:
        return "network_copyleft"
    if "lgpl" in token:
        return "weak_copyleft"
    if token.startswith(("gpl", "gplv", "gnu general public")) or " gpl " in token:
        return "strong_copyleft"
    if token.startswith(("mpl", "cddl", "epl")):
        return "weak_copyleft"
    if any(p in token for p in ("proprietary", "commercial", "all rights")):
        return "proprietary"
    if token.startswith(("mit", "bsd", "apache", "asl", "isc", "zlib", "python")):
        return "permissive"

    return "unknown"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@dataclass
class PackageLicense:
    """One row in the license-compliance table."""
    name: str
    version: str
    type: str
    licenses: List[str]
    category: str  # worst category across all licenses
    severity: str  # fail / warn / info / pass


@dataclass
class ComplianceResult:
    """Per-scan license compliance summary."""
    status: str           # pass / warn / fail
    counts: Dict[str, int]  # category → count
    severity_counts: Dict[str, int]  # severity → count
    violations: List[PackageLicense]  # packages whose category triggers warn or fail
    total_packages: int
    packages_with_known_license: int
    distinct_licenses: int


def evaluate(packages: List[Dict], policy: Dict[str, str] = None) -> ComplianceResult:
    """Run license compliance over a list of SBOM packages.

    Each `package` must have ``name``, ``version``, ``type``, and ``licenses``
    (list of strings) — the same shape the SBOM HTML generator already builds.
    """
    policy = policy or DEFAULT_POLICY
    counts = {c: 0 for c in CATEGORY_ORDER}
    severity_counts = {"fail": 0, "warn": 0, "info": 0, "pass": 0}
    violations: List[PackageLicense] = []
    distinct: Set[str] = set()
    packages_with_known = 0

    for pkg in packages or []:
        license_list = [str(l) for l in (pkg.get("licenses") or []) if l]
        for l in license_list:
            distinct.add(l)

        if not license_list:
            category = "unknown"
        else:
            # Combine all of the package's licenses and pick the worst.
            best_idx = len(CATEGORY_ORDER)
            for l in license_list:
                idx = CATEGORY_ORDER.index(classify_one(l))
                if idx < best_idx:
                    best_idx = idx
            category = CATEGORY_ORDER[best_idx]

        counts[category] = counts.get(category, 0) + 1
        severity = policy.get(category, "info")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        if category != "unknown" or license_list:
            packages_with_known += 1

        if severity in ("warn", "fail"):
            violations.append(PackageLicense(
                name=pkg.get("name", "unknown"),
                version=pkg.get("version", ""),
                type=pkg.get("type", ""),
                licenses=license_list,
                category=category,
                severity=severity,
            ))

    # Overall status: worst of all severity_counts that have non-zero entries.
    if severity_counts["fail"] > 0:
        status = "fail"
    elif severity_counts["warn"] > 0:
        status = "warn"
    else:
        status = "pass"

    # Sort violations: fail first, then warn, then by category restrictiveness.
    severity_order = {"fail": 0, "warn": 1, "info": 2, "pass": 3}
    violations.sort(key=lambda v: (
        severity_order.get(v.severity, 9),
        CATEGORY_ORDER.index(v.category),
        v.name.lower(),
    ))

    return ComplianceResult(
        status=status,
        counts=counts,
        severity_counts=severity_counts,
        violations=violations,
        total_packages=len(packages or []),
        packages_with_known_license=packages_with_known,
        distinct_licenses=len(distinct),
    )


def to_dict(result: ComplianceResult) -> Dict:
    """Convert a ComplianceResult to a JSON-serialisable dict."""
    d = asdict(result)
    return d
