"""Integration test: the generic PoC-backed Tier 3 oracle confirms a finding
when a PoC spec is present and passes, and leaves it unconfirmed when it fails.

This exercises the full ladder: matcher → Tier 1 (reachability) → Tier 3 (PoC).
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from sast_eval.exploit.oracle import validate_task
from sast_eval.exploit import oracles  # noqa: F401  (triggers registration)


def _task(poc_dir: Path, task_id: str = "testbench__1") -> dict:
    return {
        "task_id": task_id,
        "benchmark": "testbench",
        "source_root": "",
        "meta": {"poc_dir": str(poc_dir)},
    }


def _matched(file: str = "x.py", line: int = 1, cwe: str = "CWE-022") -> dict:
    return {
        "task_id": "testbench__1",
        "findings": [{"file": file, "line": line, "cwe": cwe, "ruleId": "r1"}],
        "tp": [{"file": file, "line": line, "cwe": cwe, "ruleId": "r1"}],
        "fp": [],
        "fn": [],
    }


def _poc_spec(success_value: int = 0, script: str = "echo pwned") -> dict:
    return {
        "executor": "custom-script",
        "task_id": "testbench__1",
        "finding": {"cwe": "CWE-022", "file": "x.py", "line": 1},
        "invoke": {"script": script},
        "success": {"kind": "exit-code", "value": success_value},
    }


def test_poc_oracle_confirms_on_pass():
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        poc_dir = d / "pocs"
        poc_dir.mkdir()
        (poc_dir / "testbench__1.poc.json").write_text(json.dumps(_poc_spec(0, "echo pwned")), encoding="utf-8")
        # source_root must exist for the sandbox workdir
        src = d / "codebase"
        src.mkdir()
        task = _task(poc_dir)
        task["source_root"] = str(src)
        report = validate_task(task, _matched(), src)
    assert len(report.verdicts) == 1
    v = report.verdicts[0]
    assert v.exploit_attempted is True, f"expected attempted, got {v}"
    assert v.exploit_passed is True, f"expected passed, got {v}"
    assert v.outcome == "confirmed", f"expected confirmed, got {v.outcome}"
    assert v.highest_tier == 3


def test_poc_oracle_unconfirms_on_fail():
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        poc_dir = d / "pocs"
        poc_dir.mkdir()
        # exit 1 but success wants 0 → fail
        (poc_dir / "testbench__1.poc.json").write_text(json.dumps(_poc_spec(0, "exit 1")), encoding="utf-8")
        src = d / "codebase"
        src.mkdir()
        task = _task(poc_dir)
        task["source_root"] = str(src)
        report = validate_task(task, _matched(), src)
    v = report.verdicts[0]
    assert v.exploit_attempted is True
    assert v.exploit_passed is False
    assert v.outcome == "unconfirmed", f"expected unconfirmed, got {v.outcome}"
    assert v.highest_tier == 3


def test_poc_oracle_no_spec_falls_back():
    """No PoC spec → Tier 3 doesn't run → falls back to Tier 1 (static-only)."""
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        poc_dir = d / "pocs"  # empty dir, no spec
        poc_dir.mkdir()
        src = d / "codebase"
        src.mkdir()
        task = _task(poc_dir)
        task["source_root"] = str(src)
        report = validate_task(task, _matched(), src)
    v = report.verdicts[0]
    assert v.exploit_attempted is False
    # No Tier 3 ran → outcome is matched-static-only (reachable + static match)
    assert v.outcome == "matched-static-only", f"expected matched-static-only, got {v.outcome}"


def _run() -> int:
    tests = [
        test_poc_oracle_confirms_on_pass,
        test_poc_oracle_unconfirms_on_fail,
        test_poc_oracle_no_spec_falls_back,
    ]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  ✓ {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  ✗ {t.__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} poc-oracle integration tests passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run())
