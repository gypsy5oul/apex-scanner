"""Shared normalization helpers for scanner output."""
from typing import Optional


def normalize_cvss(value) -> Optional[float]:
    """Coerce a scanner's CVSS base score to a float in [0, 10], or None.

    Scanners variously emit the score as a float (Grype), a numeric string
    (Trivy, e.g. "9.8"), or the sentinel string "N/A" when unavailable. Storing
    those mixed types caused downstream bugs (the risk engine read "N/A" as 0;
    the report rendered "N/A"|float as "0.0"). Normalize to one type: a real
    float when a usable score exists, otherwise None.
    """
    if value is None:
        return None
    try:
        score = float(value)
    except (ValueError, TypeError):
        return None
    if score <= 0:
        # 0 / negative means "not scored" in practice — treat as unavailable.
        return None
    return round(min(10.0, score), 1)
