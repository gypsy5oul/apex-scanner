"""
Translate raw scanner stderr (Grype/Trivy/Syft) into short, user-friendly messages.

Scanners dump a wall of text on failure — multiple provider attempts, full URLs,
go stack-style errors. The dashboard renders that verbatim which is overwhelming
and not actionable. We pattern-match the common failure modes and return a short,
actionable summary instead. The original error is preserved separately for support.
"""
from __future__ import annotations

import re
from typing import Dict, Optional, Tuple


# (pattern, friendly_message, category)
# Order matters — first match wins. Put specific patterns above generic ones.
_PATTERNS: Tuple[Tuple[re.Pattern, str, str], ...] = (
    (re.compile(r"MANIFEST_UNKNOWN|manifest unknown|tag does not exist", re.I),
     "Image tag does not exist in the registry.",
     "image_not_found"),

    (re.compile(r"NAME_UNKNOWN|repository name not known", re.I),
     "Image repository does not exist in the registry.",
     "image_not_found"),

    (re.compile(r"no space left on device", re.I),
     "Scanner ran out of disk space. Free space on the host and re-run.",
     "disk_full"),

    (re.compile(r"UNAUTHORIZED|authentication required|401\b|access denied", re.I),
     "Registry authentication required. Configure registry credentials for this scanner.",
     "auth_required"),

    (re.compile(r"TOOMANYREQUESTS|rate limit|too many requests|429\b", re.I),
     "Registry rate limit hit. Wait a few minutes or use an authenticated pull.",
     "rate_limited"),

    (re.compile(r"no such host|name or service not known|dns", re.I),
     "Registry hostname could not be resolved (DNS/network issue).",
     "dns_error"),

    (re.compile(r"connection refused|i/o timeout|context deadline exceeded|timed?\s?out", re.I),
     "Registry network timeout. The registry may be unreachable or slow.",
     "network_timeout"),

    (re.compile(r"x509|certificate|tls handshake", re.I),
     "TLS/certificate error talking to the registry.",
     "tls_error"),

    (re.compile(r"snap file .* does not exist", re.I),  # Grype's first attempt failing — rarely the real cause
     "Image could not be resolved from the registry. Check the image reference is correct.",
     "image_not_found"),

    (re.compile(r"docker daemon|cannot connect to the docker", re.I),
     "Internal scanner error contacting Docker daemon. Re-run the scan.",
     "scanner_internal"),

    (re.compile(r"db (?:upgrade available|stale|missing)|database not (?:found|present)", re.I),
     "Scanner vulnerability database is stale or missing. The next scan will refresh it.",
     "db_stale"),

    (re.compile(r"invalid image|invalid reference|invalid tag", re.I),
     "The image reference is malformed (e.g. missing tag or contains invalid characters).",
     "invalid_reference"),
)


def classify_error(raw_error: Optional[str]) -> Dict[str, str]:
    """
    Return a small dict describing the failure in plain language.

    Returns keys:
      message  — single short sentence for the user
      category — machine-friendly tag (image_not_found, disk_full, etc.)
      raw      — first 500 chars of the original error for support/debugging
    """
    if not raw_error:
        return {
            "message": "Unknown scanner error.",
            "category": "unknown",
            "raw": "",
        }

    text = str(raw_error)
    for pattern, message, category in _PATTERNS:
        if pattern.search(text):
            return {
                "message": message,
                "category": category,
                "raw": text[:500],
            }

    # Fallback: pick the first non-empty line so we at least show something short.
    first_line = next(
        (ln.strip() for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("-")),
        "",
    )
    short = first_line[:160] if first_line else "Scanner failed without a clear reason."
    return {
        "message": short,
        "category": "unknown",
        "raw": text[:500],
    }


def classify_scanner_errors(
    scanner_errors: Dict[str, str],
) -> Dict[str, Dict[str, str]]:
    """Apply ``classify_error`` to a {scanner_name: raw_error_text} dict."""
    return {name: classify_error(err) for name, err in (scanner_errors or {}).items()}


def summarize_scan_failure(scanner_errors: Dict[str, str]) -> str:
    """
    One short sentence summarizing why an *entire* scan failed.

    Picks the most common classified message across all scanners. Generic
    "Unknown" classifications are ignored when picking the dominant cause,
    since one scanner returning ``Unknown error`` shouldn't drown out two
    others that agree on the real reason.
    """
    if not scanner_errors:
        return "Scan failed without scanner errors."

    classified = classify_scanner_errors(scanner_errors)
    # Count messages, weighting non-"unknown" categories higher.
    from collections import Counter
    known = [c["message"] for c in classified.values() if c["category"] != "unknown"]
    if known:
        most_common, _ = Counter(known).most_common(1)[0]
        return most_common
    # Fallback: every scanner returned an unknown error.
    all_msgs = [c["message"] for c in classified.values()]
    if len(set(all_msgs)) == 1:
        return all_msgs[0]
    return f"{len(scanner_errors)} scanners failed — see scanner_errors for details."
