"""PoC judge — checks success criteria against a PoCResult.

This is the trust boundary: the **harness** judges whether a PoC succeeded,
not the tool. The tool proposes the success criteria in the spec; the judge
verifies them against the executor's output.
"""
from __future__ import annotations

import re
from pathlib import Path

from sast_eval.poc.spec import (
    PoCResult,
    SUCCESS_BODY_CONTAINS,
    SUCCESS_BODY_REGEX,
    SUCCESS_EXIT_CODE,
    SUCCESS_FILE_EXISTS,
    SUCCESS_FILE_CONTAINS,
    SUCCESS_STDERR_CONTAINS,
)


def judge(spec_success: dict, result: PoCResult, codebase_dir: Path) -> bool:
    """Return True iff the success criteria are met. False if not met or
    the executor itself errored (result.error non-empty)."""
    if result.error:
        return False
    if not result.attempted:
        return False

    kind = spec_success.get("kind")
    if kind == SUCCESS_BODY_CONTAINS:
        return spec_success.get("pattern", "") in (result.stdout + result.output)
    if kind == SUCCESS_BODY_REGEX:
        return re.search(spec_success.get("pattern", ""), result.stdout + result.output) is not None
    if kind == SUCCESS_EXIT_CODE:
        return result.exit_code == spec_success.get("value")
    if kind == SUCCESS_FILE_EXISTS:
        p = codebase_dir / spec_success.get("path", "")
        return p.exists()
    if kind == SUCCESS_FILE_CONTAINS:
        p = codebase_dir / spec_success.get("path", "")
        if not p.exists():
            return False
        return spec_success.get("pattern", "") in p.read_text(encoding="utf-8", errors="replace")
    if kind == SUCCESS_STDERR_CONTAINS:
        return spec_success.get("pattern", "") in (result.stderr + result.output)
    return False
