"""End-to-end test for the sast_eval programmatic API.

Fast, lightweight, no network. Uses the already-prepared OWASP corpus (the
smallest benchmark) and a fake SARIF generator, so it runs in a few seconds.

Run it with:

    uv run python test/test_api.py

or:

    make test

It exercises the full flow: prepare → iterate codebases → download (stream) →
save SARIF → match → score, and asserts the scorecard is produced and the
matched records contain the expected TP/FP classification.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

# Make `sast_eval` importable when running from the repo root.
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from sast_eval import SastEval


def _fake_sarif(codebase, finding_in_vuln_file: bool) -> dict:
    """Build a SARIF doc with one finding, either in the vulnerable file (TP)
    or in a wrong file (FP)."""
    cwe = codebase.ground_truth.get("cwe", "CWE-022")
    vuln_files = codebase.ground_truth.get("vulnerable_files", [])
    target = vuln_files[0] if vuln_files and finding_in_vuln_file else "nonexistent/Fake.java"
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "faketool",
                    "rules": [{"id": "R1", "properties": {"tags": [cwe]}}],
                }
            },
            "results": [{
                "ruleId": "R1",
                "level": "error",
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": target},
                        "region": {"startLine": 10},
                    }
                }],
                "message": {"text": "fake finding"},
            }],
        }],
    }


def main() -> int:
    # Use a throwaway results/reports dir so we don't clobber a real run.
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        sast = SastEval(
            benchmark="owasp",
            limit=2,
            results=str(tmp / "results"),
            reports=str(tmp / "reports"),
        )

        # 1. prepare (idempotent — OWASP is already in the corpus, so this is fast)
        print("[1/5] prepare …")
        rc = sast.prepare()
        assert rc == 0, f"prepare failed (rc={rc})"

        # 2. iterate codebases
        print("[2/5] iterate codebases …")
        codebases = list(sast.codebases())
        assert len(codebases) == 2, f"expected 2 codebases, got {len(codebases)}"
        for cb in codebases:
            assert cb.task_id.startswith("owasp/")
            assert cb.benchmark == "owasp"
            assert cb.bytes > 0
            assert cb.file_count > 0
            assert cb.ground_truth.get("cwe"), f"no cwe in ground truth for {cb.task_id}"

        # 3. download (stream) the first codebase and check the tarball arrives
        print("[3/5] download (stream) …")
        cb0 = codebases[0]
        tar = cb0.download(tmp / "sandbox")
        assert tar.is_file(), f"tarball not downloaded: {tar}"
        assert tar.stat().st_size == cb0.bytes, "streamed size mismatch"
        # extract variant
        extracted = cb0.download(tmp / "sandbox-extract", extract=True)
        assert extracted.is_dir(), f"not extracted: {extracted}"
        assert any(extracted.rglob("*.java")), "no .java files in extracted tree"

        # 4. save SARIF (one TP, one FP) and match
        print("[4/5] save SARIF + match …")
        with sast.results("faketool") as run:
            run.save_sarif(_fake_sarif(codebases[0], finding_in_vuln_file=True), codebases[0].task_id)
            run.save_sarif(_fake_sarif(codebases[1], finding_in_vuln_file=False), codebases[1].task_id)
            matched_dir = run.match()
            assert matched_dir.is_dir(), "matched dir not created"

            # Check the matched records: first should have a TP, second a FP.
            for cb, expect_tp in [(codebases[0], True), (codebases[1], False)]:
                rec_path = matched_dir / f"{cb.task_id.replace('/', '__')}.json"
                assert rec_path.is_file(), f"matched record missing: {rec_path}"
                rec = json.loads(rec_path.read_text())
                counts = rec.get("counts", {})
                if expect_tp:
                    assert counts.get("tp", 0) >= 1, f"expected TP for {cb.task_id}: {counts}"
                else:
                    assert counts.get("fp", 0) >= 1, f"expected FP for {cb.task_id}: {counts}"

            # 5. score
            print("[5/5] score …")
            scorecard = run.score()
            assert scorecard.is_file(), f"scorecard not written: {scorecard}"
            assert scorecard.stat().st_size > 0, "scorecard is empty"
            text = scorecard.read_text()
            assert "faketool" in text, "tool name missing from scorecard"

    print("\n✓ all API tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
