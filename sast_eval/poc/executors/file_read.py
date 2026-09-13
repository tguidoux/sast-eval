"""``file-read`` executor — write a payload, run a binary, check an output file.

Used by path-traversal PoCs where the exploit writes to or reads from the
filesystem (e.g. CyberGym C/C++ targets, file-handling CLI tools). The executor
writes the payload file, runs the binary, and returns. The judge checks
``file-exists`` / ``file-contains`` against the output path.
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
    payload_path = invoke.get("payload_path", "payload.txt")
    payload_content = invoke.get("payload_content", "")
    args = invoke.get("args", []) or []

    # Write the payload file into the sandbox.
    local = codebase_dir / payload_path
    local.parent.mkdir(parents=True, exist_ok=True)
    local.write_text(payload_content, encoding="utf-8")

    if not binary:
        return PoCResult(attempted=False, error="invoke.binary is empty", duration_s=time.time() - t0)

    arg_str = " ".join(str(a) for a in args)
    cmd = f"{binary} {arg_str}".strip()
    cmd = expand_template(cmd, {"CODEBASE": str(codebase_dir), "PAYLOAD": payload_path})

    r = sandbox.run(cmd, cwd=str(codebase_dir), timeout_s=float(invoke.get("timeout_s", 30)))
    return PoCResult(
        attempted=True,
        stdout=r.stdout,
        stderr=r.stderr,
        exit_code=r.exit_code,
        output=r.stdout + ("\n" + r.stderr if r.stderr else ""),
        duration_s=time.time() - t0,
    )
