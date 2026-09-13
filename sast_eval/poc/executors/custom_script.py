"""``custom-script`` executor — run an arbitrary script in the sandbox.

The escape hatch for benchmarks that don't fit the other executors. The
script is provided as a string (``invoke.script``) and run with ``sh -c`` in
the sandbox. The judge still checks the success criteria — the script cannot
self-certify.
"""
from __future__ import annotations

import time
from pathlib import Path

from sast_eval.poc.spec import PoCResult, PoCSpec
from sast_eval.poc.sandbox import Sandbox, expand_template


def run(spec: PoCSpec, codebase_dir: Path, sandbox: Sandbox) -> PoCResult:
    invoke = spec.invoke or {}
    t0 = time.time()

    script = invoke.get("script", "")
    if not script:
        return PoCResult(attempted=False, error="invoke.script is empty", duration_s=time.time() - t0)

    env = invoke.get("env", {}) or {}
    cmd = expand_template(script, {"CODEBASE": str(codebase_dir)})
    r = sandbox.run(cmd, cwd=str(codebase_dir), env=env, timeout_s=float(invoke.get("timeout_s", 60)))
    return PoCResult(
        attempted=True,
        stdout=r.stdout,
        stderr=r.stderr,
        exit_code=r.exit_code,
        output=r.stdout + ("\n" + r.stderr if r.stderr else ""),
        duration_s=time.time() - t0,
    )
