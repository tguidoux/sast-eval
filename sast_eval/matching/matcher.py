"""Matching rules (§5) — classify every SARIF finding against ground truth.

For each task, classify every finding:

    location_hit(f)  := normalize(f.file) in task.vulnerable_files
                      (or, if vulnerable_methods exist:
                       f.file == m.file AND (method-identity or line-range overlap))
    category_hit(f) := cwe_matches(f.cwe, task.cwe)

    TP  := location_hit AND category_hit
    FP  := NOT (location_hit AND category_hit)   # includes right-file-wrong-CWE
    FN  := ground-truth vuln with no TP finding against it

Special cases:
- FP traps (OWASP real=false): any finding in the test-case file is a FP,
  regardless of CWE.
- ground_truth_incomplete tasks (bountytasks, empty patch dict): excluded from
  TP/FP/FN; reported separately as "detected-CWE-only".
- CWE-UNKNOWN ground truth (CyberGym): no CWE to match against, so category_hit
  is vacuously true — scoring is location-only. A finding in a file touched by
  patch.diff is a TP; any other finding is a FP. This is a static-analysis
  proxy, not CyberGym's canonical PoC-crash metric.
- Duplicate findings: multiple TPs on the same ground truth count once for
  recall; each still counts toward precision's denominator.

Only applies to runs this repo performed (OWASP + any delegated static runs).
Imported results are already scored by the canonical runner.
"""
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path

CWE_MAP_PATH = os.path.join(os.path.dirname(__file__), "cwe_map.json")


def _load_cwe_map() -> dict[str, list[str]]:
    with open(CWE_MAP_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


_CWE_MAP = _load_cwe_map()


def cwe_matches(a: str, b: str) -> bool:
    """Symmetric CWE equivalence: a==b or b in class(a) or a in class(b)."""
    if a == b:
        return True
    if a in _CWE_MAP.get(b, []):
        return True
    if b in _CWE_MAP.get(a, []):
        return True
    return False


def _normalize_path(p: str) -> str:
    """Normalize a repo-relative path for comparison."""
    if p is None:
        return ""
    p = str(p).replace("\\", "/")
    # Strip any leading "./" and any absolute prefix down to the repo-relative part.
    p = p.lstrip("./")
    return p


def _line_overlap(a_start: int | None, a_end: int | None,
                  b_start: int | None, b_end: int | None) -> bool:
    """Do [a_start,a_end] and [b_start,b_end] overlap? None means unknown."""
    if a_start is None and b_start is None:
        return False  # can't establish overlap
    a_start = a_start if a_start is not None else 0
    a_end = a_end if a_end is not None else a_start
    b_start = b_start if b_start is not None else 0
    b_end = b_end if b_end is not None else b_start
    return a_start <= b_end and b_start <= a_end


def _method_identity_hit(finding_file: str, finding_line: int | None,
                          methods: list[dict]) -> bool:
    """CWE-Bench method-identity matching (§5, §3.3).

    Primary: file + method name/signature match. Secondary: line-range overlap
    with the fixed-commit ranges (may drift by a few lines on the buggy commit).
    """
    ffile = _normalize_path(finding_file)
    for m in methods:
        mfile = _normalize_path(m.get("file", ""))
        if mfile and ffile != mfile:
            continue
        if not mfile and ffile:
            # method has no file; cannot match by identity
            continue
        # Primary: method-identity. We don't have the finding's method name from
        # SARIF reliably, so identity reduces to file match here; line-range
        # overlap is the secondary signal we can actually compute.
        if _line_overlap(finding_line, finding_line, m.get("start"), m.get("end")):
            return True
        # Fall back to class-range overlap (broader).
        if _line_overlap(finding_line, finding_line, m.get("class_start"), m.get("class_end")):
            return True
    return False


# SASTbench canonical kind -> primary CWE (mirrors adapters/sastbench_adapter.py).
# Used to decide whether a finding's CWE counts as a match for a region's
# acceptedKinds. A region with no acceptedKinds (capability_safe regions) is
# matched on location alone for FP classification.
_SB_KIND_TO_CWE = {
    "command_injection": "CWE-078",
    "path_traversal": "CWE-022",
    "ssrf": "CWE-918",
    "auth_bypass": "CWE-287",
    "authz_bypass": "CWE-862",
    "sql_injection": "CWE-089",
}


def _finding_kind_matches_region(finding_cwe: str, region: dict) -> bool:
    """SASTbench region kind-match: finding's CWE maps to a region acceptedKind.

    A vulnerable region lists ``acceptedKinds`` (SASTbench canonical kinds). A
    finding counts as kind-matching if its CWE is equivalent (via cwe_map) to
    the primary CWE of any accepted kind. Empty ``acceptedKinds`` means any
    kind matches (location-only).
    """
    accepted = region.get("accepted_kinds", [])
    if not accepted:
        return True
    fcwe = finding_cwe or "CWE-UNKNOWN"
    for kind in accepted:
        rcwe = _SB_KIND_TO_CWE.get(kind, "CWE-UNKNOWN")
        if cwe_matches(fcwe, rcwe):
            return True
    return False


def _region_overlap_hit(finding: dict, regions: list[dict],
                        label: str | None = None) -> dict | None:
    """SASTbench region-level overlap matching.

    Returns the first region the finding overlaps (file + line-range), filtered
    by ``label`` if given ("vulnerable" or "capability_safe"). Returns ``None``
    if no region overlaps. Path matching is exact-then-suffix (like file-level)
    to handle tarball top-level dir prefixes.
    """
    ffile = _normalize_path(finding.get("file", ""))
    fline = finding.get("line")
    for r in regions:
        if label and r.get("label") != label:
            continue
        rpath = _normalize_path(r.get("path", ""))
        if not rpath:
            continue
        # exact then suffix (tarball top-level dir prefix tolerance)
        if ffile != rpath and not ffile.endswith(rpath):
            continue
        if _line_overlap(fline, fline, r.get("start"), r.get("end")):
            return r
    return False if False else None  # (kept readable; the `False` is never hit)


def _location_hit(finding: dict, task: dict) -> bool:
    gt = task.get("ground_truth", {})
    ffile = _normalize_path(finding.get("file", ""))
    vuln_files = [_normalize_path(x) for x in gt.get("vulnerable_files", [])]

    regions = gt.get("vulnerable_regions", [])
    if regions:
        # SASTbench: region-level overlap against vulnerable regions.
        return _region_overlap_hit(finding, regions, label="vulnerable") is not None

    methods = gt.get("vulnerable_methods", [])
    if methods:
        # CWE-Bench: method-identity-first matching.
        return _method_identity_hit(ffile, finding.get("line"), methods)

    # File-level matching (OWASP, bountytasks, CyberGym).
    # Exact match first, then suffix match to handle tarball top-level dir
    # prefixes (e.g. CyberGym reports `file/src/funcs.c` for GT `src/funcs.c`).
    if ffile in vuln_files:
        return True
    return any(ffile.endswith(vf) for vf in vuln_files if vf)


def _category_hit(finding: dict, task: dict) -> bool:
    gt = task.get("ground_truth", {})
    tcwe = gt.get("cwe", "CWE-UNKNOWN")
    # When ground truth has no CWE (CyberGym: cwe=CWE-UNKNOWN), category matching
    # is not meaningful — scoring is location-only. We treat category as
    # vacuously satisfied so a finding in the right file is a TP regardless of
    # the tool's reported CWE. This keeps precision honest (a wrong-file
    # finding is still a FP) without penalizing tools for CWE labels we can't
    # verify against.
    if tcwe == "CWE-UNKNOWN":
        return True
    return cwe_matches(finding.get("cwe", "CWE-UNKNOWN"), tcwe)


def _region_category_hit(finding: dict, region: dict) -> bool:
    """SASTbench region-level category match: finding CWE vs region acceptedKinds."""
    return _finding_kind_matches_region(finding.get("cwe", "CWE-UNKNOWN"), region)


def _extract_findings(sarif: dict, rules_cwe: dict[str, str]) -> list[dict]:
    """Extract findings from a SARIF v2.1.0 doc, mapping ruleId -> CWE."""
    findings: list[dict] = []
    for run in sarif.get("runs", []):
        # Build ruleId -> CWE from the run's tool.driver.rules if not overridden.
        run_rules: dict[str, str] = {}
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            rid = rule.get("id")
            if not rid:
                continue
            # Prefer explicit CWE in rule metadata; fall back to the tool rules.json.
            cwe = None
            tags = rule.get("properties", {}).get("tags", [])
            for t in tags:
                if isinstance(t, str) and t.upper().startswith("CWE-"):
                    cwe = t.upper()
                    break
            if cwe is None:
                cwe = rules_cwe.get(rid)
            run_rules[rid] = cwe or "CWE-UNKNOWN"

        for res in run.get("results", []):
            rid = res.get("ruleId", "")
            cwe = run_rules.get(rid) or rules_cwe.get(rid) or "CWE-UNKNOWN"
            loc = (res.get("locations") or [{}])[0]
            phys = loc.get("physicalLocation", {}) if loc else {}
            art = phys.get("artifactLocation", {}).get("uri", "")
            region = phys.get("region", {})
            line = region.get("startLine") if region else None
            findings.append({
                "ruleId": rid,
                "cwe": cwe,
                "file": art,
                "line": line,
                "message": (res.get("message", {}) or {}).get("text", ""),
            })
    return findings


def _task_id_to_filename(task_id: str) -> str:
    return task_id.replace("/", "__") + ".sarif"


def classify_task(task: dict, findings: list[dict]) -> dict:
    """Classify all findings for one task; return the per-task matched record."""
    gt = task.get("ground_truth", {})
    fp_trap = gt.get("fp_trap", False)
    incomplete = gt.get("ground_truth_incomplete", False)
    regions = gt.get("vulnerable_regions", [])

    tps: list[dict] = []
    fps: list[dict] = []
    detected_cwe_only = False
    # SASTbench: track which vulnerable regions were detected (for region-level
    # FN counting) and how many findings hit capability_safe regions (for the
    # Capability FP Rate metric in the scorecard).
    detected_region_ids: set[str] = set()
    capability_fp_count = 0

    if incomplete:
        # Excluded from TP/FP/FN. Report detected-CWE-only (weak signal).
        for f in findings:
            if _category_hit(f, task):
                detected_cwe_only = True
        return {
            "task_id": task["task_id"],
            "benchmark": task["benchmark"],
            "fp_trap": fp_trap,
            "ground_truth_incomplete": True,
            "findings": findings,
            "tp": [],
            "fp": [],
            "fn": [],
            "detected_cwe_only": detected_cwe_only,
            "counts": {"tp": 0, "fp": 0, "fn": 0, "findings": len(findings)},
            "excluded": True,
        }

    if regions:
        # SASTbench: region-level overlap matching.
        # A finding is a TP if it overlaps a vulnerable region AND kind-matches.
        # A finding is a FP otherwise (includes capability_safe overlaps, which
        # are tracked separately as capability_fp for the scorecard).
        for f in findings:
            vuln_region = _region_overlap_hit(f, regions, label="vulnerable")
            if vuln_region is not None and _region_category_hit(f, vuln_region):
                tps.append(f)
                detected_region_ids.add(vuln_region.get("id", ""))
                continue
            # Not a TP. Check if it's a capability FP (overlaps a capability_safe
            # region) for the scorecard's Capability FP Rate metric.
            cap_region = _region_overlap_hit(f, regions, label="capability_safe")
            if cap_region is not None:
                capability_fp_count += 1
            fps.append(f)

        # FN: vulnerable regions with no TP finding against them.
        vuln_region_ids = [r.get("id", "") for r in regions if r.get("label") == "vulnerable"]
        fn_count = sum(1 for rid in vuln_region_ids if rid not in detected_region_ids)
        fn_details = [{"region_id": rid, "path": next((r.get("path") for r in regions if r.get("id") == rid), "")}
                      for rid in vuln_region_ids if rid not in detected_region_ids]
        tp_count = len(vuln_region_ids) - fn_count

        return {
            "task_id": task["task_id"],
            "benchmark": task["benchmark"],
            "fp_trap": fp_trap,
            "ground_truth_incomplete": False,
            "findings": findings,
            "tp": tps,
            "fp": fps,
            "fn": fn_details,
            "detected_cwe_only": False,
            "counts": {
                "tp": tp_count,
                "fp": len(fps),
                "fn": fn_count,
                "findings": len(findings),
                "capability_fp": capability_fp_count,
            },
            "excluded": False,
        }

    for f in findings:
        loc = _location_hit(f, task)
        cat = _category_hit(f, task)
        if fp_trap:
            # Ground truth is zero findings; any finding (anywhere) is a FP.
            fps.append(f)
            continue
        if loc and cat:
            tps.append(f)
        else:
            fps.append(f)

    # FN: ground-truth vuln with no TP finding against it.
    # For file-level benchmarks, one vuln per task (the test-case file / patch).
    # For CWE-Bench, one vuln per method; a method with no TP finding is a FN.
    methods = gt.get("vulnerable_methods", [])
    fn_count = 0
    fn_details: list[dict] = []
    if not fp_trap:
        if methods:
            # Method-level FN: a method is found if any TP finding overlaps it.
            for m in methods:
                mfile = _normalize_path(m.get("file", ""))
                found = False
                for tp in tps:
                    if _normalize_path(tp.get("file", "")) == mfile and \
                       _line_overlap(tp.get("line"), tp.get("line"),
                                     m.get("start"), m.get("end")):
                        found = True
                        break
                if not found:
                    fn_count += 1
                    fn_details.append({"file": m.get("file"), "method": m.get("method"),
                                      "signature": m.get("signature")})
        else:
            # One vuln per task. FN if no TP.
            if not tps:
                fn_count = 1
                fn_details.append({"vulnerable_files": gt.get("vulnerable_files", [])})

    # Dedupe TPs for recall (multiple TPs on same ground truth count once).
    # For file-level: count distinct vulnerable files with a TP.
    # For method-level: count distinct methods with a TP (already computed above).
    if fp_trap:
        tp_count = 0  # FP traps have no true vuln to find.
    elif methods:
        tp_count = len(methods) - fn_count
    else:
        tp_count = 1 if tps else 0

    return {
        "task_id": task["task_id"],
        "benchmark": task["benchmark"],
        "fp_trap": fp_trap,
        "ground_truth_incomplete": False,
        "findings": findings,
        "tp": tps,
        "fp": fps,
        "fn": fn_details,
        "detected_cwe_only": False,
        "counts": {
            "tp": tp_count,
            "fp": len(fps),
            "fn": fn_count,
            "findings": len(findings),
        },
        "excluded": False,
    }


def _load_tasks(tasks_dir: str) -> dict[str, dict]:
    """Load all task records from tasks/*.jsonl, indexed by task_id."""
    tasks: dict[str, dict] = {}
    for p in sorted(Path(tasks_dir).glob("*.jsonl")):
        with open(p, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                t = json.loads(line)
                tasks[t["task_id"]] = t
    return tasks


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Match SARIF findings against ground truth (§5)")
    parser.add_argument("--tasks", required=True, help="Directory of tasks/*.jsonl")
    parser.add_argument("--results", required=True, help="Directory results/raw/<tool>/ of SARIF files")
    parser.add_argument("--out", required=True, help="Output directory results/matched/<tool>/")
    parser.add_argument("--tool", default=None, help="Tool name (defaults to results dir basename)")
    parser.add_argument("--rules", default=None, help="Path to tools/<tool>/rules.json (ruleId -> CWE)")
    args = parser.parse_args(argv)

    tool = args.tool or os.path.basename(os.path.normpath(args.results))
    rules_cwe: dict[str, str] = {}
    if args.rules and os.path.exists(args.rules):
        with open(args.rules, "r", encoding="utf-8") as f:
            rules_cwe = json.load(f)
    elif tool:
        default_rules = os.path.join("tools", tool, "rules.json")
        if os.path.exists(default_rules):
            with open(default_rules, "r", encoding="utf-8") as f:
                rules_cwe = json.load(f)

    tasks = _load_tasks(args.tasks)
    os.makedirs(args.out, exist_ok=True)

    results_dir = Path(args.results)
    sarif_files = {p.name: p for p in results_dir.glob("*.sarif")}

    matched_count = 0
    for task_id, task in tasks.items():
        fname = _task_id_to_filename(task_id)
        sarif_path = sarif_files.get(fname)
        findings: list[dict] = []
        run_failed = False
        if sarif_path and sarif_path.exists():
            try:
                with open(sarif_path, "r", encoding="utf-8") as f:
                    sarif = json.load(f)
                findings = _extract_findings(sarif, rules_cwe)
            except (json.JSONDecodeError, OSError) as e:
                run_failed = True
                # A missing/corrupt SARIF = zero findings (all-FN), logged.
        # Missing SARIF file = tool produced no findings (all-FN).

        record = classify_task(task, findings)
        record["tool"] = tool
        if run_failed:
            record["run_failed"] = True
        out_path = os.path.join(args.out, fname.replace(".sarif", ".json"))
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(record, f, ensure_ascii=False, sort_keys=True, indent=2)
        matched_count += 1

    print(f"Matched {matched_count} tasks for tool '{tool}' -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
