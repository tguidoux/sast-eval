"""PoC runner — ties spec → executor → judge together.

    run_poc(spec, codebase_dir, sandbox) -> PoCResult

Validates the spec, dispatches to the right executor, judges success, and
returns a :class:`PoCResult` with ``passed`` set. This is the single entry
point the harness and CLI use.
"""
from __future__ import annotations

import time
from pathlib import Path

from sast_eval.poc.executors import get_executor
from sast_eval.poc.judge import judge
from sast_eval.poc.sandbox import Sandbox
from sast_eval.poc.spec import PoCResult, PoCSpec, validate_poc


def run_poc(spec: PoCSpec | dict, codebase_dir: str | Path, sandbox: Sandbox) -> PoCResult:
    """Run a PoC spec against a codebase in a sandbox and judge success."""
    if isinstance(spec, dict):
        valid, issues = validate_poc(spec)
        if not valid:
            errs = "; ".join(f"{i.code}: {i.message}" for i in issues if i.severity == "error")
            return PoCResult(attempted=False, error=f"invalid PoC spec: {errs}")
        from sast_eval.poc.spec import from_dict
        spec = from_dict(spec)

    valid, issues = validate_poc(spec)
    if not valid:
        errs = "; ".join(f"{i.code}: {i.message}" for i in issues if i.severity == "error")
        return PoCResult(attempted=False, error=f"invalid PoC spec: {errs}")

    executor_fn = get_executor(spec.executor)
    if executor_fn is None:
        return PoCResult(attempted=False, error=f"no executor registered for {spec.executor!r}")

    codebase_dir = Path(codebase_dir)
    t0 = time.time()
    try:
        result = executor_fn(spec, codebase_dir, sandbox)
    except Exception as e:
        result = PoCResult(attempted=False, error=f"executor raised: {e}", duration_s=time.time() - t0)

    # Judge success (harness decides, not the tool).
    result.passed = judge(spec.success, result, codebase_dir)
    return result
