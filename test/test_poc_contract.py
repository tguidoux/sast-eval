"""Tests for the PoC contract: spec validation, judge, runner, CLI.

Run with:
    uv run python test/test_poc_contract.py
or via ``make test``.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from sast_eval.poc import (
    PoCSpec, PoCResult, PoCIssue,
    validate_poc, validate_file as validate_poc_file,
    run_poc, LocalSandbox, REFERENCE_POC,
)
from sast_eval.poc.spec import from_dict
from sast_eval.poc.judge import judge


# --- spec validation ----------------------------------------------------

def test_reference_poc_is_valid():
    valid, issues = validate_poc(REFERENCE_POC)
    assert valid, f"reference PoC must be valid, issues: {issues}"
    errs = [i for i in issues if i.severity == "error"]
    assert errs == [], f"reference PoC must have no errors, got: {errs}"


def test_missing_executor_is_invalid():
    spec = {"task_id": "x", "invoke": {"script": "echo hi"}, "success": {"kind": "exit-code", "value": 0}}
    valid, issues = validate_poc(spec)
    assert not valid
    assert any(i.code == "no-executor" for i in issues)


def test_unknown_executor_is_invalid():
    spec = {"executor": "telepathy", "invoke": {"script": "echo hi"}, "success": {"kind": "exit-code", "value": 0}}
    valid, issues = validate_poc(spec)
    assert not valid
    assert any(i.code == "unknown-executor" for i in issues)


def test_missing_invoke_is_invalid():
    spec = {"executor": "custom-script", "success": {"kind": "exit-code", "value": 0}}
    valid, issues = validate_poc(spec)
    assert not valid
    assert any(i.code == "no-invoke" for i in issues)


def test_missing_success_is_invalid():
    spec = {"executor": "custom-script", "invoke": {"script": "echo hi"}}
    valid, issues = validate_poc(spec)
    assert not valid
    assert any(i.code == "no-success" for i in issues)


def test_contains_without_pattern_is_invalid():
    spec = {"executor": "custom-script", "invoke": {"script": "echo hi"},
            "success": {"kind": "response-body-contains"}}
    valid, issues = validate_poc(spec)
    assert not valid
    assert any(i.code == "no-pattern" for i in issues)


def test_exit_code_without_value_is_invalid():
    spec = {"executor": "custom-script", "invoke": {"script": "echo hi"},
            "success": {"kind": "exit-code"}}
    valid, issues = validate_poc(spec)
    assert not valid
    assert any(i.code == "no-exit-value" for i in issues)


def test_missing_task_id_is_warning_not_error():
    spec = {"executor": "custom-script", "invoke": {"script": "echo hi"},
            "success": {"kind": "exit-code", "value": 0}}
    valid, issues = validate_poc(spec)
    assert valid  # warnings don't invalidate
    assert any(i.code == "no-task-id" and i.severity == "warning" for i in issues)


def test_non_object_is_invalid():
    valid, issues = validate_poc("not a dict")  # type: ignore[arg-type]
    assert not valid
    assert issues[0].code == "not-object"


def test_validate_file_reads_disk():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "x.poc.json"
        p.write_text(json.dumps(REFERENCE_POC), encoding="utf-8")
        valid, issues, spec = validate_poc_file(p)
        assert valid
        assert spec is not None
        assert spec.executor == "http-request"


def test_validate_file_invalid_json():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "bad.poc.json"
        p.write_text("{not json", encoding="utf-8")
        valid, issues, spec = validate_poc_file(p)
        assert not valid
        assert issues[0].code == "invalid-json"
        assert spec is None


# --- judge ---------------------------------------------------------------

def test_judge_body_contains_hit():
    result = PoCResult(attempted=True, stdout="hello root:x:0:0", output="hello root:x:0:0")
    assert judge({"kind": "response-body-contains", "pattern": "root:"}, result, Path(".")) is True


def test_judge_body_contains_miss():
    result = PoCResult(attempted=True, stdout="nothing here", output="nothing here")
    assert judge({"kind": "response-body-contains", "pattern": "root:"}, result, Path(".")) is False


def test_judge_exit_code_match():
    result = PoCResult(attempted=True, exit_code=0)
    assert judge({"kind": "exit-code", "value": 0}, result, Path(".")) is True


def test_judge_exit_code_mismatch():
    result = PoCResult(attempted=True, exit_code=1)
    assert judge({"kind": "exit-code", "value": 0}, result, Path(".")) is False


def test_judge_error_disqualifies():
    result = PoCResult(attempted=True, exit_code=0, error="server crashed")
    assert judge({"kind": "exit-code", "value": 0}, result, Path(".")) is False


def test_judge_not_attempted_fails():
    result = PoCResult(attempted=False)
    assert judge({"kind": "exit-code", "value": 0}, result, Path(".")) is False


def test_judge_file_exists():
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "out.txt").write_text("leaked", encoding="utf-8")
        result = PoCResult(attempted=True, exit_code=0)
        assert judge({"kind": "file-exists", "path": "out.txt"}, result, Path(d)) is True


def test_judge_file_contains():
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "out.txt").write_text("secret: password123", encoding="utf-8")
        result = PoCResult(attempted=True, exit_code=0)
        assert judge({"kind": "file-contains", "path": "out.txt", "pattern": "password123"}, result, Path(d)) is True


# --- runner (custom-script, no network) ---------------------------------

def test_run_poc_custom_script_exit_code_success():
    spec = {
        "executor": "custom-script",
        "task_id": "test__1",
        "finding": {"cwe": "CWE-022", "file": "x.py", "line": 1},
        "invoke": {"script": "echo pwned"},
        "success": {"kind": "exit-code", "value": 0},
    }
    with tempfile.TemporaryDirectory() as d:
        sandbox = LocalSandbox(workdir=Path(d) / ".sb")
        try:
            result = run_poc(spec, d, sandbox)
        finally:
            sandbox.teardown()
    assert result.attempted is True
    assert result.passed is True
    assert result.exit_code == 0
    assert "pwned" in result.stdout


def test_run_poc_custom_script_body_contains_success():
    spec = {
        "executor": "custom-script",
        "task_id": "test__2",
        "finding": {"cwe": "CWE-089", "file": "x.py", "line": 1},
        "invoke": {"script": "echo 'SQLI: admin:admin'"},
        "success": {"kind": "response-body-contains", "pattern": "SQLI: admin"},
    }
    with tempfile.TemporaryDirectory() as d:
        sandbox = LocalSandbox(workdir=Path(d) / ".sb")
        try:
            result = run_poc(spec, d, sandbox)
        finally:
            sandbox.teardown()
    assert result.attempted is True
    assert result.passed is True


def test_run_poc_failure_when_exit_code_mismatch():
    spec = {
        "executor": "custom-script",
        "task_id": "test__3",
        "finding": {"cwe": "CWE-022", "file": "x.py", "line": 1},
        "invoke": {"script": "exit 1"},
        "success": {"kind": "exit-code", "value": 0},
    }
    with tempfile.TemporaryDirectory() as d:
        sandbox = LocalSandbox(workdir=Path(d) / ".sb")
        try:
            result = run_poc(spec, d, sandbox)
        finally:
            sandbox.teardown()
    assert result.attempted is True
    assert result.passed is False
    assert result.exit_code == 1


def test_run_poc_invalid_spec_returns_error():
    spec = {"executor": "telepathy", "invoke": {}, "success": {}}
    with tempfile.TemporaryDirectory() as d:
        sandbox = LocalSandbox(workdir=Path(d) / ".sb")
        try:
            result = run_poc(spec, d, sandbox)
        finally:
            sandbox.teardown()
    assert result.attempted is False
    assert "invalid PoC spec" in result.error


def test_run_poc_file_read_executor():
    """file-read executor writes a payload, runs a binary, judge checks output file."""
    spec = {
        "executor": "file-read",
        "task_id": "test__4",
        "finding": {"cwe": "CWE-022", "file": "x.py", "line": 1},
        "invoke": {
            "binary": "sh -c",
            "args": ["'cp payload.txt out.txt'"],
            "payload_path": "payload.txt",
            "payload_content": "traversed-secret",
        },
        "success": {"kind": "file-contains", "path": "out.txt", "pattern": "traversed-secret"},
    }
    with tempfile.TemporaryDirectory() as d:
        sandbox = LocalSandbox(workdir=Path(d) / ".sb")
        try:
            result = run_poc(spec, d, sandbox)
        finally:
            sandbox.teardown()
    assert result.attempted is True
    assert result.passed is True, f"expected pass, got: {result}"


# --- CLI -----------------------------------------------------------------

def test_cli_validate_poc_reference():
    r = subprocess.run(
        [sys.executable, "-m", "sast_eval.cli", "validate-poc", "--reference"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    assert r.returncode == 0, r.stderr
    doc = json.loads(r.stdout)
    assert doc["executor"] == "http-request"
    assert doc["success"]["kind"] == "response-body-contains"


def test_cli_validate_poc_file():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "x.poc.json"
        p.write_text(json.dumps(REFERENCE_POC), encoding="utf-8")
        r = subprocess.run(
            [sys.executable, "-m", "sast_eval.cli", "validate-poc", str(p)],
            capture_output=True, text=True, cwd=str(REPO_ROOT),
        )
        assert r.returncode == 0, r.stderr
        assert "✓" in r.stdout


def test_cli_run_poc_custom_script():
    spec = {
        "executor": "custom-script",
        "task_id": "cli__1",
        "finding": {"cwe": "CWE-022", "file": "x.py", "line": 1},
        "invoke": {"script": "echo pwned"},
        "success": {"kind": "exit-code", "value": 0},
    }
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "x.poc.json"
        p.write_text(json.dumps(spec), encoding="utf-8")
        cb = Path(d) / "codebase"
        cb.mkdir()
        r = subprocess.run(
            [sys.executable, "-m", "sast_eval.cli", "run-poc", str(p), str(cb)],
            capture_output=True, text=True, cwd=str(REPO_ROOT),
        )
        assert r.returncode == 0, r.stderr
        out = json.loads(r.stdout)
        assert out["attempted"] is True
        assert out["passed"] is True


def _run() -> int:
    tests = [
        test_reference_poc_is_valid,
        test_missing_executor_is_invalid,
        test_unknown_executor_is_invalid,
        test_missing_invoke_is_invalid,
        test_missing_success_is_invalid,
        test_contains_without_pattern_is_invalid,
        test_exit_code_without_value_is_invalid,
        test_missing_task_id_is_warning_not_error,
        test_non_object_is_invalid,
        test_validate_file_reads_disk,
        test_validate_file_invalid_json,
        test_judge_body_contains_hit,
        test_judge_body_contains_miss,
        test_judge_exit_code_match,
        test_judge_exit_code_mismatch,
        test_judge_error_disqualifies,
        test_judge_not_attempted_fails,
        test_judge_file_exists,
        test_judge_file_contains,
        test_run_poc_custom_script_exit_code_success,
        test_run_poc_custom_script_body_contains_success,
        test_run_poc_failure_when_exit_code_mismatch,
        test_run_poc_invalid_spec_returns_error,
        test_run_poc_file_read_executor,
        test_cli_validate_poc_reference,
        test_cli_validate_poc_file,
        test_cli_run_poc_custom_script,
    ]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  ✓ {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  ✗ {t.__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} poc-contract tests passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run())
