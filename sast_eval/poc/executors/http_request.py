"""``http-request`` executor — build, start a server, send an HTTP request.

Used by web-app benchmarks (OWASP BenchmarkJava, any servlet/Spring app).

Flow:
  1. ``setup.build`` — run the build+start command in the sandbox (background).
  2. Wait for ``setup.ready_pattern`` in the server's stdout (or a timeout).
  3. ``invoke`` — send the HTTP request (method, path, params, headers).
  4. Return the response body + status as PoCResult.output.
  5. ``cleanup`` — kill the server.

The executor does NOT judge success — it returns the response; the judge
checks the success criteria.
"""
from __future__ import annotations

import time
import urllib.parse
import urllib.request
from pathlib import Path

from sast_eval.poc.spec import PoCResult, PoCSpec
from sast_eval.poc.sandbox import Sandbox, expand_template


def run(spec: PoCSpec, codebase_dir: Path, sandbox: Sandbox) -> PoCResult:
    setup = spec.setup or {}
    invoke = spec.invoke or {}
    t0 = time.time()

    # Pick a port and let the sandbox map it.
    port = int(setup.get("port", 8888))
    outer_port = sandbox.port(port)

    # Build + start the server in the background.
    build_cmd = setup.get("build", "")
    if not build_cmd:
        return PoCResult(attempted=False, error="setup.build is empty", duration_s=time.time() - t0)

    # We run the server with PORT in the env so the command can use ${PORT}.
    server_env = {"PORT": port, "SERVER_PID": "$!"}
    expanded = expand_template(build_cmd, {"PORT": port, "SERVER_PID": "$!"})
    # Start the server in the background so we can poll it.
    full_cmd = f"{expanded} & echo $! > .server_pid"
    start = sandbox.run(full_cmd, cwd=str(codebase_dir), env={"PORT": str(port)}, timeout_s=setup.get("ready_timeout_s", 120))
    if start.exit_code != 0 and "Started" not in (start.stdout + start.stderr):
        # Background launch may return non-zero immediately; that's OK if the
        # server is actually starting. We rely on ready_pattern below.
        pass

    # Wait for ready.
    ready_pat = setup.get("ready_pattern", "")
    ready_timeout = float(setup.get("ready_timeout_s", 60))
    deadline = time.time() + ready_timeout
    ready = False
    if not ready_pat:
        # No pattern: assume the server is up after a short fixed delay.
        time.sleep(min(2.0, ready_timeout))
        ready = True
    else:
        # Poll the server root until it responds or we time out.
        while time.time() < deadline:
            try:
                req = urllib.request.Request(f"http://127.0.0.1:{outer_port}/", method="GET")
                with urllib.request.urlopen(req, timeout=2) as resp:
                    body = resp.read(2048).decode("utf-8", "replace")
                    if ready_pat in body or ready_pat in (start.stdout + start.stderr):
                        ready = True
                        break
            except Exception:
                time.sleep(1.0)

    if not ready:
        _cleanup(sandbox, spec, codebase_dir)
        return PoCResult(
            attempted=False,
            error=f"server did not become ready within {ready_timeout}s (pattern={ready_pat!r})",
            output=start.stdout + start.stderr,
            duration_s=time.time() - t0,
        )

    # Send the invoke request.
    method = invoke.get("method", "GET").upper()
    path = invoke.get("path", "/")
    params = invoke.get("params", {}) or {}
    headers = invoke.get("headers", {}) or {}
    qs = urllib.parse.urlencode(params) if params else ""
    url = f"http://127.0.0.1:{outer_port}{path}"
    if qs and "?" not in url:
        url += "?" + qs
    elif qs:
        url += "&" + qs

    body = None
    if method in ("POST", "PUT", "PATCH"):
        body = invoke.get("body", "").encode("utf-8") if invoke.get("body") else None
        if body is None and params:
            body = qs.encode("utf-8")
            headers = {**headers, "Content-Type": "application/x-www-form-urlencoded"}

    try:
        req = urllib.request.Request(url, data=body, method=method, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp_body = resp.read().decode("utf-8", "replace")
            status = resp.getcode()
            out = f"HTTP {status}\n{resp_body}"
            result = PoCResult(attempted=True, stdout=resp_body, output=out, exit_code=status, duration_s=time.time() - t0)
    except urllib.error.HTTPError as e:
        resp_body = e.read().decode("utf-8", "replace") if e.fp else ""
        result = PoCResult(
            attempted=True,
            stdout=resp_body,
            output=f"HTTP {e.code}\n{resp_body}",
            exit_code=e.code,
            duration_s=time.time() - t0,
        )
    except Exception as e:
        result = PoCResult(attempted=True, error=f"request failed: {e}", duration_s=time.time() - t0)

    _cleanup(sandbox, spec, codebase_dir)
    return result


def _cleanup(sandbox: Sandbox, spec: PoCSpec, codebase_dir: Path) -> None:
    cleanup = spec.cleanup or ""
    if not cleanup:
        return
    try:
        sandbox.run(cleanup, cwd=str(codebase_dir), timeout_s=10)
    except Exception:
        pass
