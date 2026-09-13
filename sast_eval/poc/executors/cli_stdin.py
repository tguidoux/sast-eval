"""``cli-stdin`` executor — run a CLI binary with crafted stdin.

Used by CLI-tool benchmarks (bountytasks targets that are command-line tools).
The executor runs the binary with the given args, pipes stdin, and returns
stdout/stderr/exit. The judge checks the success criteria.
"""
from __future__ import annotations

import time
from pathlib import Path

from sast_eval.poc.spec import PoCResult, PoCSpec
from sast_eval.poc.sandbox import Sandbox, expand_template


def run(spec: PoCSpec, codebase_dir: Path, sandbox: Sandbox) -> PoCResult:
    invoke = spec.invoke or {}
    t0 = time.time()

    binary = invoke.get("binary", "")
    if not binary:
        return PoCResult(attempted=False, error="invoke.binary is empty", duration_s=time.time() - t0)

    args = invoke.get("args", []) or []
    stdin_text = invoke.get("stdin", "") or ""
    env = invoke.get("env", {}) or {}

    arg_str = " ".join(str(a) for a in args)
    cmd = f"{binary} {arg_str}".strip()
    cmd = expand_template(cmd, {"CODEBASE": str(codebase_dir)})

    # Pipe stdin via a here-doc so the sandbox's shell handles it.
    full = f"printf %s {repr(stdin_text)} | ({cmd})"
    r = sandbox.run(full, cwd=str(codebase_dir), env=env, timeout_s=float(invoke.get("timeout_s", 30)))
    return PoCResult(
        attempted=True,
        stdout=r.stdout,
        stderr=r.stderr,
        exit_code=r.exit_code,
        output=r.stdout + ("\n" + r.stderr if r.stderr else ""),
        duration_s=time.time() - t0,
    )
