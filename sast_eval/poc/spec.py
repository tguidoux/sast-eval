"""PoC (proof-of-concept) contract — Tier 3 exploit validation.

A PoC is a **declarative spec** that describes how to trigger a finding and
how to judge success. It is benchmark-agnostic: it declares an *executor type*
(``http-request``, ``cli-stdin``, ``file-read``, ``grpc-call``, ``custom-script``)
and *success criteria*. The harness runs the executor in a sandbox and judges
the result — the tool never self-certifies.

This module defines the spec schema, the result dataclass, and a reference
fixture. Executors live in :mod:`sast_eval.poc.executors`; the runner that ties
them together lives in :mod:`sast_eval.poc.runner`.

Contract summary (what a tool emits per finding):

    {
      "poc_version": "1.0",
      "task_id": "owasp__BenchmarkTest00001",
      "finding": {"rule_id": "...", "cwe": "CWE-022", "file": "...", "line": 29},
      "executor": "http-request",
      "setup":   {"build": "...", "ready_pattern": "...", "ready_timeout_s": 60},
      "invoke":  {"method": "GET", "path": "/...", "params": {...}},
      "success": {"kind": "response-body-contains", "pattern": "root:"},
      "cleanup": "kill ${SERVER_PID}"
    }

The harness provides:

    run_poc(spec, codebase_dir, sandbox) -> PoCResult

where ``sandbox`` implements :class:`sast_eval.poc.sandbox.Sandbox`.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

# Executor types the harness ships. A spec picks exactly one via ``executor``.
EXECUTOR_HTTP_REQUEST = "http-request"      # web app: build, start server, send HTTP
EXECUTOR_CLI_STDIN = "cli-stdin"            # CLI tool: run binary with crafted stdin
EXECUTOR_FILE_READ = "file-read"           # path traversal: write payload, check output file
EXECUTOR_GRPC_CALL = "grpc-call"            # microservice: send protobuf, check response
EXECUTOR_CUSTOM_SCRIPT = "custom-script"    # anything else: run a script in the sandbox

ALL_EXECUTORS = (
    EXECUTOR_HTTP_REQUEST,
    EXECUTOR_CLI_STDIN,
    EXECUTOR_FILE_READ,
    EXECUTOR_GRPC_CALL,
    EXECUTOR_CUSTOM_SCRIPT,
)

# Success-criterion kinds. The harness judges these — not the tool.
SUCCESS_BODY_CONTAINS = "response-body-contains"      # HTTP/CLI stdout contains a pattern
SUCCESS_BODY_REGEX = "response-body-regex"            # stdout matches a regex
SUCCESS_EXIT_CODE = "exit-code"                        # exit code equals a value
SUCCESS_FILE_EXISTS = "file-exists"                    # a file exists after the run
SUCCESS_FILE_CONTAINS = "file-contains"                # a file contains a pattern
SUCCESS_STDERR_CONTAINS = "stderr-contains"            # stderr contains a pattern (crash)

ALL_SUCCESS_KINDS = (
    SUCCESS_BODY_CONTAINS,
    SUCCESS_BODY_REGEX,
    SUCCESS_EXIT_CODE,
    SUCCESS_FILE_EXISTS,
    SUCCESS_FILE_CONTAINS,
    SUCCESS_STDERR_CONTAINS,
)

POC_VERSION = "1.0"


@dataclass
class PoCIssue:
    """A validation issue with a PoC spec (analogous to SarifIssue)."""

    code: str
    message: str
    severity: str = "warning"  # "error" (spec unusable) or "warning" (fixable)


@dataclass
class PoCResult:
    """Outcome of running a PoC spec in a sandbox."""

    attempted: bool = False
    passed: bool = False
    output: str = ""        # combined stdout/stderr/logs for debugging
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None
    duration_s: float = 0.0
    error: str = ""          # non-empty if the executor itself failed (not the PoC)


@dataclass
class PoCSpec:
    """A proof-of-concept spec for one finding.

    Use :func:`from_dict` to parse/validate; :func:`to_dict` to serialize.
    """

    poc_version: str = POC_VERSION
    task_id: str = ""
    finding: dict = field(default_factory=dict)   # {rule_id, cwe, file, line}
    executor: str = ""
    setup: dict = field(default_factory=dict)
    invoke: dict = field(default_factory=dict)
    success: dict = field(default_factory=dict)
    cleanup: str = ""
    meta: dict = field(default_factory=dict)     # benchmark-specific hints

    def to_dict(self) -> dict:
        return asdict(self)


# --- Validation ----------------------------------------------------------


def validate_poc(spec: dict | PoCSpec) -> tuple[bool, list[PoCIssue]]:
    """Validate a PoC spec dict.

    Returns ``(valid, issues)`` where ``valid`` is True iff the spec is
    structurally usable (executor known, invoke present, success kind known).
    Warnings (missing task_id, missing finding fields) do not make the spec
    invalid — the runner can still attempt it.
    """
    if isinstance(spec, PoCSpec):
        spec = spec.to_dict()
    issues: list[PoCIssue] = []

    if not isinstance(spec, dict):
        return False, [PoCIssue("not-object", "spec must be a JSON object", "error")]

    executor = spec.get("executor")
    if not executor:
        issues.append(PoCIssue("no-executor", "spec is missing 'executor'", "error"))
    elif executor not in ALL_EXECUTORS:
        issues.append(PoCIssue(
            "unknown-executor",
            f"executor {executor!r} not in {ALL_EXECUTORS}",
            "error",
        ))

    invoke = spec.get("invoke")
    if not isinstance(invoke, dict) or not invoke:
        issues.append(PoCIssue("no-invoke", "spec is missing 'invoke' (what to run)", "error"))

    success = spec.get("success")
    if not isinstance(success, dict) or not success:
        issues.append(PoCIssue("no-success", "spec is missing 'success' (how to judge)", "error"))
    else:
        kind = success.get("kind")
        if not kind:
            issues.append(PoCIssue("no-success-kind", "success is missing 'kind'", "error"))
        elif kind not in ALL_SUCCESS_KINDS:
            issues.append(PoCIssue(
                "unknown-success-kind",
                f"success.kind {kind!r} not in {ALL_SUCCESS_KINDS}",
                "error",
            ))
        # pattern required for contains/regex kinds
        if kind in (SUCCESS_BODY_CONTAINS, SUCCESS_BODY_REGEX,
                    SUCCESS_FILE_CONTAINS, SUCCESS_STDERR_CONTAINS):
            if not success.get("pattern"):
                issues.append(PoCIssue(
                    "no-pattern",
                    f"success.kind={kind!r} requires a 'pattern'",
                    "error",
                ))
        if kind == SUCCESS_EXIT_CODE and "value" not in success:
            issues.append(PoCIssue("no-exit-value", "success.kind='exit-code' requires 'value'", "error"))
        if kind in (SUCCESS_FILE_EXISTS, SUCCESS_FILE_CONTAINS) and not success.get("path"):
            issues.append(PoCIssue("no-file-path", f"success.kind={kind!r} requires 'path'", "error"))

    # Warnings (don't invalidate the spec)
    if not spec.get("task_id"):
        issues.append(PoCIssue("no-task-id", "spec is missing 'task_id'", "warning"))
    finding = spec.get("finding", {})
    if not isinstance(finding, dict) or not finding:
        issues.append(PoCIssue("no-finding", "spec is missing 'finding' (which SARIF finding this proves)", "warning"))
    else:
        if not finding.get("cwe"):
            issues.append(PoCIssue("no-finding-cwe", "finding is missing 'cwe'", "warning"))
        if not finding.get("file"):
            issues.append(PoCIssue("no-finding-file", "finding is missing 'file'", "warning"))

    errors = [i for i in issues if i.severity == "error"]
    return len(errors) == 0, issues


def from_dict(spec: dict) -> PoCSpec:
    """Parse a validated dict into a :class:`PoCSpec`. Does not re-validate."""
    return PoCSpec(
        poc_version=spec.get("poc_version", POC_VERSION),
        task_id=spec.get("task_id", ""),
        finding=spec.get("finding", {}) or {},
        executor=spec.get("executor", ""),
        setup=spec.get("setup", {}) or {},
        invoke=spec.get("invoke", {}) or {},
        success=spec.get("success", {}) or {},
        cleanup=spec.get("cleanup", ""),
        meta=spec.get("meta", {}) or {},
    )


def validate_file(path: str | Path) -> tuple[bool, list[PoCIssue], PoCSpec | None]:
    """Validate a PoC spec file on disk. Returns (valid, issues, spec_or_None)."""
    p = Path(path)
    try:
        spec = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        return False, [PoCIssue("invalid-json", f"not valid JSON: {e}", "error")], None
    valid, issues = validate_poc(spec)
    return valid, issues, (from_dict(spec) if valid else None)


# --- Reference fixture --------------------------------------------------

# A reference PoC for OWASP BenchmarkTest00001 (CWE-022 path traversal).
# The harness can run this end-to-end against a packaged OWASP codebase in a
# sandbox. It demonstrates the full contract: build, wait for ready, send a
# traversal payload, judge by response body.
REFERENCE_POC: dict = {
    "poc_version": "1.0",
    "task_id": "owasp__BenchmarkTest00001",
    "finding": {
        "rule_id": "java/path-traversal",
        "cwe": "CWE-022",
        "file": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00001.java",
        "line": 29,
    },
    "executor": "http-request",
    "setup": {
        "build": "mvn -q compile jetty:run -Djetty.port=${PORT}",
        "ready_pattern": "Started Jetty Server",
        "ready_timeout_s": 120,
    },
    "invoke": {
        "method": "GET",
        "path": "/benchmark/BenchmarkTest00001",
        "params": {"filename": "../../../../etc/passwd"},
        "headers": {},
    },
    "success": {
        "kind": "response-body-contains",
        "pattern": "root:",
    },
    "cleanup": "kill ${SERVER_PID}",
    "meta": {"benchmark": "owasp", "language": "java"},
}
