"""Tests for the SARIF contract validator.

Validates that the harness's input contract (what a SAST tool must emit) is
correctly enforced, and that the reference fixture passes. Run with:

    uv run python test/test_sarif_contract.py

or via ``make test``.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from sast_eval.sarif_contract import (
    REFERENCE_SARIF,
    validate_sarif,
    validate_file,
)


def test_reference_fixture_is_valid():
    rep = validate_sarif(REFERENCE_SARIF)
    assert rep.valid, "reference fixture must be valid"
    assert rep.finding_count == 2
    assert rep.rule_count == 2
    assert rep.issues == [], f"reference fixture must have no issues, got: {rep.issues}"


def test_missing_runs_is_invalid():
    rep = validate_sarif({"version": "2.1.0"})
    assert rep.valid is False
    assert rep.issues[0].code == "no-runs"


def test_non_object_is_invalid():
    rep = validate_sarif("not a dict")  # type: ignore[arg-type]
    assert rep.valid is False
    assert rep.issues[0].code == "not-object"


def test_finding_without_ruleid_warns():
    doc = {"runs": [{"results": [{"locations": [{"physicalLocation": {"artifactLocation": {"uri": "x.java"}, "region": {"startLine": 1}}}]}]}]}
    rep = validate_sarif(doc)
    assert rep.valid is True  # parseable
    codes = [i.code for i in rep.issues]
    assert "missing-ruleId" in codes


def test_finding_without_uri_warns():
    doc = {"runs": [{"tool": {"driver": {"rules": [{"id": "r1", "properties": {"tags": ["CWE-022"]}}]}},
                     "results": [{"ruleId": "r1", "locations": [{"physicalLocation": {"region": {"startLine": 1}}}]}]}]}
    rep = validate_sarif(doc)
    assert rep.valid is True
    codes = [i.code for i in rep.issues]
    assert "no-uri" in codes


def test_rule_without_cwe_warns():
    doc = {"runs": [{"tool": {"driver": {"rules": [{"id": "r1", "properties": {"tags": ["security"]}}]}},
                     "results": [{"ruleId": "r1", "locations": [{"physicalLocation": {"artifactLocation": {"uri": "x.java"}, "region": {"startLine": 1}}}]}]}]}
    rep = validate_sarif(doc)
    codes = [i.code for i in rep.issues]
    assert "rule-missing-cwe" in codes


def test_undeclared_rule_warns():
    doc = {"runs": [{"results": [{"ruleId": "undeclared",
                                  "locations": [{"physicalLocation": {"artifactLocation": {"uri": "x.java"}, "region": {"startLine": 1}}}]}]}]}
    rep = validate_sarif(doc)
    codes = [i.code for i in rep.issues]
    assert "undeclared-rule" in codes


def test_missing_line_recommended():
    doc = {"runs": [{"tool": {"driver": {"rules": [{"id": "r1", "properties": {"tags": ["CWE-022"]}}]}},
                     "results": [{"ruleId": "r1", "locations": [{"physicalLocation": {"artifactLocation": {"uri": "x.java"}}}]}]}]}
    rep = validate_sarif(doc)
    codes = [i.code for i in rep.issues]
    assert "no-line" in codes


def test_validate_file_reads_disk():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "x.sarif"
        p.write_text(json.dumps(REFERENCE_SARIF), encoding="utf-8")
        rep = validate_file(p)
        assert rep.valid
        assert rep.finding_count == 2


def test_validate_file_invalid_json():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "bad.sarif"
        p.write_text("{not json", encoding="utf-8")
        rep = validate_file(p)
        assert rep.valid is False
        assert rep.issues[0].code == "invalid-json"


def test_cli_reference_flag():
    """`sast-eval validate-sarif --reference` prints the fixture and exits 0."""
    import subprocess
    r = subprocess.run(
        [sys.executable, "-m", "sast_eval.cli", "validate-sarif", "--reference"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    assert r.returncode == 0, r.stderr
    doc = json.loads(r.stdout)
    assert doc["runs"][0]["results"][0]["ruleId"] == "java/path-traversal"


def test_cli_validates_file():
    """`sast-eval validate-sarif <file>` reports findings count."""
    import subprocess
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "x.sarif"
        p.write_text(json.dumps(REFERENCE_SARIF), encoding="utf-8")
        r = subprocess.run(
            [sys.executable, "-m", "sast_eval.cli", "validate-sarif", str(p)],
            capture_output=True, text=True, cwd=str(REPO_ROOT),
        )
        assert r.returncode == 0, r.stderr
        assert "2 findings" in r.stdout
        assert "2 rules" in r.stdout


def _run() -> int:
    tests = [
        test_reference_fixture_is_valid,
        test_missing_runs_is_invalid,
        test_non_object_is_invalid,
        test_finding_without_ruleid_warns,
        test_finding_without_uri_warns,
        test_rule_without_cwe_warns,
        test_undeclared_rule_warns,
        test_missing_line_recommended,
        test_validate_file_reads_disk,
        test_validate_file_invalid_json,
        test_cli_reference_flag,
        test_cli_validates_file,
    ]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  ✓ {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  ✗ {t.__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} sarif-contract tests passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run())
