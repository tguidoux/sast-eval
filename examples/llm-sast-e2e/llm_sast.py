"""A toy LLM-based SAST tool, benchmarked end-to-end with sast-eval.

This is a *minimal* example of what a developer would build to verify their
LLM SAST tool against the sast-eval harness. It demonstrates the full contract
from docs/CONTRACT.md:

  1. DETECT leg  — the tool emits SARIF v2.1.0 (4 fields per finding)
  2. EXPLOIT leg — the tool emits PoC specs (executor + invoke + success)
  3. The harness matches, runs the PoCs in a sandbox, judges, and scores.

The "LLM" here is a toy: a few regex heuristics that simulate what a real
LLM SAST would produce. The point is the *plumbing*, not the detector quality.

Run:
    uv run llm_sast.py prepare     # build codebases (first time only)
    uv run llm_sast.py run         # run the tool + eval pipeline
    uv run llm_sast.py clean       # remove generated results
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from sast_eval import SastEval, validate_sarif, validate_poc

TOOL_NAME = "toy-llm-sast"

# ── the "LLM SAST tool" ─────────────────────────────────────────────────
# A real tool would call an LLM here. We use regex heuristics to simulate
# the two artifacts an LLM SAST must produce: SARIF (detect) + PoC (exploit).

# (pattern, rule_id, cwe, description)
# These match real OWASP Benchmark sink patterns. A real LLM tool would
# reason about taint flow; we approximate with sink + servlet-context signals.
HEURISTICS = [
    (
        r"new\s+java\.io\.File(?:Input|Output)?Stream\s*\(",
        "java-path-traversal",
        "CWE-022",
        "Path traversal: file opened from request-derived input",
    ),
    (
        r"Runtime\.getRuntime\(\)\.exec\s*\(",
        "java-command-injection",
        "CWE-078",
        "Command injection via Runtime.exec",
    ),
    (
        r"\.createStatement\s*\(\).*\n.*\.execute(?:Query|Update)\s*\(",
        "java-sql-injection",
        "CWE-089",
        "SQL injection via Statement.executeQuery with concatenation",
    ),
    (
        r'response\.getWriter\(\)\.print(?:ln)?\s*\(\s*[^)]*\+',
        "java-xss",
        "CWE-079",
        "Reflected XSS: response.getWriter().print with concatenation",
    ),
    (
        r"javax\.crypto\.Cipher\.getInstance\s*\(\s*\"DES",
        "java-weak-crypto",
        "CWE-327",
        "Weak crypto: DES cipher (use AES/GCM)",
    ),
]


def _find_files(src_root: Path):
    """Yield .java files under src_root."""
    for p in src_root.rglob("*.java"):
        yield p


def analyze(src_root: Path) -> tuple[dict, dict]:
    """Analyze a codebase → (sarif_dict, poc_spec_dict).

    Returns the two artifacts the tool must produce:
      - SARIF for the detect leg (one result per finding)
      - a PoC spec for the exploit leg (one per finding, where we can)
    """
    results = []
    rules = {}
    poc_specs = {}  # rule_id → poc spec

    for fpath in _find_files(src_root):
        try:
            text = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(fpath.relative_to(src_root))
        for i, (pattern, rule_id, cwe, desc) in enumerate(HEURISTICS):
            for m in re.finditer(pattern, text):
                line = text[: m.start()].count("\n") + 1
                results.append({
                    "ruleId": rule_id,
                    "message": {"text": desc},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": rel},
                            "region": {"startLine": line},
                        }
                    }],
                })
                rules[rule_id] = {
                    "id": rule_id,
                    "shortDescription": {"text": desc},
                    "properties": {"tags": [cwe]},
                }
                # Build a PoC spec for this finding (exploit leg).
                # In a real tool, the LLM would generate this per-finding.
                poc_specs[rule_id] = _make_poc(rule_id, cwe, rel, line)

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }
    return sarif, poc_specs


def _make_poc(rule_id: str, cwe: str, file: str, line: int) -> dict:
    """Build a PoC spec for a finding.

    A real LLM tool would generate this from the finding context — the spec is
    the tool's *recipe* for proving the finding is exploitable. The harness
    runs it in a sandbox and judges the result (the tool never self-certifies).

    We use the ``custom-script`` executor for all findings here: the script
    does a static taint check (source → sink in the vulnerable file) and
    prints ``POC-CONFIRMED`` if the taint path looks real. The harness judges
    ``response-body-contains: POC-CONFIRMED``.

    This mirrors what the OWASP Tier 2 canary does, but expressed as a PoC
    spec from the *tool's* side — showing the full contract: the tool claims
    (SARIF) + proposes a proof (PoC), the harness runs + judges.
    """
    # Source patterns (request readers that introduce tainted data) and
    # sink patterns (the vulnerable operation) per CWE. The PoC script greps
    # for both in the vulnerable file and confirms if source precedes sink.
    sources = (
        r"request\.getParameter|request\.getHeader|request\.getCookies|"
        r"request\.getQueryString|request\.getAttribute|thecookies|"
        r"URLDecoder\.decode"
    )
    sink = {
        "java-path-traversal": r"new\s+java\.io\.File(?:Input|Output)?Stream|new\s+java\.io\.File",
        "java-command-injection": r"Runtime\.getRuntime\(\)\.exec|ProcessBuilder",
        "java-sql-injection": r"executeQuery|executeUpdate|createStatement",
        "java-xss": r"response\.getWriter\(\)\.print(?:ln)?|response\.getWriter\(\)\.write",
        "java-weak-crypto": r"Cipher\.getInstance|KeyPairGenerator",
    }.get(rule_id, r"new\s+java\.io\.File")

    # The script runs in the sandbox with ${CODEBASE} expanded by the harness
    # to the codebase dir (the benchmark's source repo, e.g. corpus/BenchmarkJava).
    # The SARIF file path is relative to the *extracted tarball*, which may have
    # a top-level dir prefix the repo doesn't have — so we locate the file by
    # basename within ${CODEBASE} (OWASP test files have unique names). Then we
    # grep for a source and a sink; if both are present and the source appears
    # first, we print POC-CONFIRMED.
    script = (
        f'fname=$(basename "{file}"); '
        f'f=$(find "${{CODEBASE}}" -name "$fname" -type f | head -1); '
        f'if [ -z "$f" ]; then echo POC-FAIL; exit 1; fi; '
        f'src=$(grep -nE "{sources}" "$f" | head -1); '
        f'snk=$(grep -nE "{sink}" "$f" | head -1); '
        f'if [ -n "$src" ] && [ -n "$snk" ]; then '
        f'  sline=$(echo "$src" | cut -d: -f1); '
        f'  kline=$(echo "$snk" | cut -d: -f1); '
        f'  if [ "$sline" -le "$kline" ]; then echo POC-CONFIRMED; exit 0; fi; '
        f'fi; '
        f'echo POC-FAIL; exit 1'
    )

    return {
        "poc_version": "1.0",
        "task_id": "",  # filled by caller
        "finding": {"rule_id": rule_id, "cwe": cwe, "file": file, "line": line},
        "executor": "custom-script",
        "invoke": {
            "script": script,
            "language": "bash",
            "timeout_s": 30,
        },
        # "POC-CONFIRMED" is distinct from "POC-FAIL" so a substring check
        # can't false-positive (unlike "CONFIRMED" vs "NOT-CONFIRMED").
        "success": {"kind": "response-body-contains", "pattern": "POC-CONFIRMED"},
    }


# ── the eval pipeline ────────────────────────────────────────────────────


def cmd_prepare() -> int:
    """Build standardized codebases for a few benchmarks (first-time setup)."""
    print("=== prepare: building codebases (owasp, limit=3) ===")
    sast = SastEval(benchmark="owasp", limit=3)
    sast.prepare()
    print(f"done. codebases in: {sast.codebases_dir}")
    return 0


def cmd_run() -> int:
    """Run the toy SAST over each codebase, then match → exploit → score."""
    sast = SastEval(benchmark="owasp", limit=3)

    codebases = list(sast.codebases())
    if not codebases:
        print("No codebases found. Run `uv run llm_sast.py prepare` first.")
        return 1

    print(f"=== run: {TOOL_NAME} over {len(codebases)} codebases ===\n")

    with sast.results(TOOL_NAME) as run:
        for cb in codebases:
            print(f"  [{cb.task_id}] downloading…")
            src = cb.download("/tmp/llm-sast-e2e", extract=True)

            print(f"  [{cb.task_id}] analyzing…")
            sarif, poc_specs = analyze(src)

            # Validate before saving (the contract self-check).
            report = validate_sarif(sarif)
            if not report.valid:
                print(f"  [{cb.task_id}] SARIF INVALID: {report.issues}")
                continue

            run.save_sarif(sarif, cb.task_id)

            # Save PoC specs (exploit leg). One per finding's rule_id.
            for rule_id, poc in poc_specs.items():
                poc["task_id"] = cb.task_id
                valid, issues = validate_poc(poc)
                if not valid:
                    print(f"  [{cb.task_id}] PoC INVALID ({rule_id}): {issues}")
                    continue
                run.save_poc(poc, cb.task_id)

            n_findings = len(sarif["runs"][0]["results"])
            n_pocs = len(poc_specs)
            print(f"  [{cb.task_id}] {n_findings} findings, {n_pocs} PoCs saved\n")

        print("=== match (detect leg) ===")
        run.match()

        print("=== exploit (run PoCs in sandbox, judge) ===")
        run.exploit()

        print("=== score ===")
        scorecard = run.score()

    # Print the scorecard.
    print("\n" + "=" * 72)
    print("SCORECARD")
    print("=" * 72)
    print(scorecard.read_text())

    # Print per-finding exploit verdicts (only for tasks where we found something).
    print("=" * 72)
    print("EXPLOIT VERDICTS (per finding — only tasks with findings shown)")
    print("=" * 72)
    exploits_dir = sast.results_dir + f"/exploits/{TOOL_NAME}"
    analyzed = {cb.task_id for cb in codebases}
    tier_name = {0: "static", 1: "reach", 2: "canary", 3: "PoC"}
    for p in sorted(Path(exploits_dir).glob("*.json")):
        with open(p) as f:
            rep = json.load(f)
        # Only show tasks we actually analyzed (skip the 2740 empty OWASP tasks).
        tid = rep["task_id"]
        if tid not in analyzed:
            continue
        verdicts = [v for v in rep.get("verdicts", []) if v.get("file")]
        if not verdicts:
            print(f"\n{tid}  (benchmark: {rep['benchmark']}) — no findings")
            continue
        print(f"\n{tid}  (benchmark: {rep['benchmark']})")
        for v in verdicts:
            tier = v["highest_tier"]
            print(
                f"  {v['outcome']:12s}  tier={tier} ({tier_name.get(tier, '?')})  "
                f"{v['cwe']}  {Path(v['file']).name}:{v.get('line', '?')}"
            )
            # Show what each tier found, so the ladder is visible.
            if v.get("canary_attempted"):
                flag = "PASS" if v.get("canary_passed") else "FAIL"
                print(f"               tier 2 (canary): {flag}")
            if v.get("exploit_attempted"):
                flag = "PASS" if v.get("exploit_passed") else "FAIL"
                out = (v.get("exploit_output") or "").strip().replace("\n", " ")[:80]
                print(f"               tier 3 (PoC):    {flag}  [{v.get('poc_id', '?')}] {out}")

    return 0


def cmd_clean() -> int:
    """Remove generated results/reports."""
    import shutil
    for d in ("results", "reports"):
        p = Path(d)
        if p.is_dir():
            shutil.rmtree(p)
            print(f"removed {p}")
    return 0


COMMANDS = {"prepare": cmd_prepare, "run": cmd_run, "clean": cmd_clean}


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "run"
    if cmd not in COMMANDS:
        print(f"unknown command: {cmd}. one of: {list(COMMANDS)}")
        sys.exit(2)
    sys.exit(COMMANDS[cmd]())
