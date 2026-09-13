"""Sandbox contract — where PoCs (and SAST tools) run.

A sandbox executes untrusted commands in an isolated environment. The harness
is sandbox-agnostic: it only needs :meth:`Sandbox.run` and :meth:`Sandbox.port`.
Concrete implementations can wrap Docker, gVisor, a remote VM, or (for tests)
the local process.

The same sandbox runs both the SAST tool (to produce SARIF) and the PoC (to
validate a finding). This keeps the execution model uniform across benchmarks.
"""
from __future__ import annotations

import os
import shlex
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class RunResult:
    """Result of a single sandboxed command."""

    exit_code: int
    stdout: str
    stderr: str
    duration_s: float


class Sandbox:
    """Abstract sandbox. Subclasses implement :meth:`run` and :meth:`port`.

    The contract is intentionally minimal so any isolation backend can adapt:
    - ``run(cmd, cwd, env, timeout_s)`` → execute a shell command, return RunResult
    - ``port(host_port)`` → a port reachable from outside the sandbox (for http-request)
    - ``put_file(local, remote)`` → copy a file into the sandbox
    - ``teardown()`` → stop/clean up
    """

    def run(
        self,
        command: str,
        *,
        cwd: str | Path = ".",
        env: dict | None = None,
        timeout_s: float = 120.0,
    ) -> RunResult:
        raise NotImplementedError

    def port(self, host_port: int) -> int:
        """Return a port reachable from outside the sandbox for a given in-sandbox port."""
        return host_port

    def put_file(self, local: str | Path, remote: str | Path) -> None:
        raise NotImplementedError

    def teardown(self) -> None:
        pass


class LocalSandbox(Sandbox):
    """A no-isolation sandbox that runs commands on the local host.

    Use only for tests and trusted codebases. Never run untrusted PoCs with
    this backend — use a Docker/gVisor-backed sandbox in production.
    """

    def __init__(self, workdir: str | Path | None = None) -> None:
        self.workdir = Path(workdir) if workdir else Path.cwd()
        self.workdir.mkdir(parents=True, exist_ok=True)
        self._pids: list[int] = []
        self._port_map: dict[int, int] = {}

    def run(
        self,
        command: str,
        *,
        cwd: str | Path = ".",
        env: dict | None = None,
        timeout_s: float = 120.0,
    ) -> RunResult:
        full_env = os.environ.copy()
        if env:
            full_env.update({k: str(v) for k, v in env.items()})
        run_cwd = self.workdir / cwd if not Path(cwd).is_absolute() else Path(cwd)
        run_cwd.mkdir(parents=True, exist_ok=True)
        t0 = time.time()
        try:
            proc = subprocess.run(
                command,
                shell=True,
                cwd=str(run_cwd),
                env=full_env,
                capture_output=True,
                text=True,
                timeout=timeout_s,
            )
            return RunResult(
                exit_code=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                duration_s=time.time() - t0,
            )
        except subprocess.TimeoutExpired as e:
            return RunResult(
                exit_code=-1,
                stdout=e.stdout.decode() if e.stdout else "",
                stderr=(e.stderr.decode() + "\n[timeout]") if e.stderr else "[timeout]",
                duration_s=timeout_s,
            )

    def port(self, host_port: int) -> int:
        # Local sandbox: the port is the same inside and outside.
        self._port_map[host_port] = host_port
        return host_port

    def put_file(self, local: str | Path, remote: str | Path) -> None:
        import shutil
        remote = self.workdir / remote if not Path(remote).is_absolute() else Path(remote)
        remote.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(str(local), str(remote))

    def teardown(self) -> None:
        for pid in self._pids:
            try:
                os.kill(pid, 15)
            except (ProcessLookupError, PermissionError):
                pass
        self._pids.clear()


def expand_template(text: str, env: dict) -> str:
    """Expand ``${VAR}`` placeholders in a command/template string."""
    result = text
    for k, v in env.items():
        result = result.replace(f"${{{k}}}", str(v))
    return result
