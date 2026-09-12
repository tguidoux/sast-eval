"""Shared helpers for adapters and importers.

CWE normalization (§2.1) and bounty-value parsing (reusing the rules of
corpus/bountytasks/calculate_bounties.py).
"""
from __future__ import annotations

import re
from typing import Optional

# Matches the first integer in a CWE-ish string, with or without the "CWE-" prefix.
_CWE_INT = re.compile(r"(\d+)")


def normalize_cwe(raw: Optional[str]) -> str:
    """Normalize a raw CWE string to canonical ``CWE-<int>`` form.

    Per §2.1: extract the integer -> ``CWE-<int>`` (zero-padded to 3 for
    display). Empty/unparseable -> ``CWE-UNKNOWN``.

    Examples (from §2.1):
        "CWE-22: Path Traversal"        -> "CWE-022"
        "400: Denial of Service"        -> "CWE-400"
        "CWE-29: Path Traversal: '\\..\\filename'" -> "CWE-029"
        ""                             -> "CWE-UNKNOWN"
        "22"                           -> "CWE-022"
        None                           -> "CWE-UNKNOWN"
    """
    if raw is None:
        return "CWE-UNKNOWN"
    s = str(raw).strip()
    if not s:
        return "CWE-UNKNOWN"
    m = _CWE_INT.search(s)
    if not m:
        return "CWE-UNKNOWN"
    return f"CWE-{int(m.group(1)):03d}"


def parse_bounty_value(value) -> float:
    """Parse a bounty value from various formats.

    Reuses the rules of ``corpus/bountytasks/calculate_bounties.py``:
    - None / "" -> 0.0
    - already a number -> float
    - leading "$" stripped
    - "X to Y" range -> average of the two ends
    - otherwise best-effort float(), 0.0 on failure
    """
    if value is None or value == "":
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str) and value.startswith("$"):
        value = value[1:]
    if isinstance(value, str) and " to " in value:
        parts = value.split(" to ")
        if len(parts) == 2:
            try:
                return (float(parts[0]) + float(parts[1])) / 2
            except ValueError:
                pass
    try:
        return float(value)
    except (ValueError, TypeError):
        return 0.0
