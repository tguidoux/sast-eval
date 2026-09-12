"""Scoring (§6) — compute metrics and render reports/scorecard.md.

Headline table (per benchmark + common-CWE-core combined): recall, precision,
F1, FPR*, OWASP score (TPR-FPR). Per-CWE table (common core). Benchmark-specific
metrics: $-weighted recall (bountytasks), OWASP category scorecard, method-vs-
file recall (CWE-Bench). Efficiency metrics. Excluded-tasks audit.

Imported metrics appear under their own names with ``source: science-team-runner``
and are never blended with this harness's metrics. Every table carries a
``unit:`` label (§9.5).
"""
from __future__ import annotations

import argparse
import glob
import json
import os
from collections import defaultdict
from pathlib import Path

from sast_eval.matching.matcher import cwe_matches

# Common CWE core: CWE classes present in all three benchmarks (§6.5).
COMMON_CWE_CORE = ["CWE-022", "CWE-078", "CWE-079", "CWE-094"]

HARNESS_VERSION = "0.1.0"


def _safe_div(num: float, den: float) -> float:
    return num / den if den else 0.0


def _f1(precision: float, recall: float) -> float:
    return 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0


def _load_matched(matched_dir: str) -> list[dict]:
    records: list[dict] = []
    for p in sorted(glob.glob(os.path.join(matched_dir, "*.json"))):
        with open(p, "r", encoding="utf-8") as f:
            records.append(json.load(f))
    return records


def _load_tasks(tasks_dir: str) -> dict[str, dict]:
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


def _in_common_core(cwe: str) -> bool:
    for core in COMMON_CWE_CORE:
        if cwe == core or cwe_matches(cwe, core):
            return True
    return False


def _aggregate(records: list[dict], tasks: dict[str, dict],
              benchmark: str | None = None, cwe_filter=None) -> dict:
    """Aggregate TP/FP/FN over a (filtered) set of matched records.

    Returns counts and derived metrics. FP-trap tasks contribute to FP and TN:
      - TN = number of FP-trap tasks with zero findings (true negatives).
      - FP  = findings on FP-trap tasks (each finding is a FP) + non-vuln findings elsewhere.
    """
    tp = fp = fn = tn = 0
    n_tasks = 0
    n_fp_trap = 0
    n_incomplete = 0
    findings_total = 0
    for r in records:
        if r.get("excluded"):
            n_incomplete += 1
            continue
        if benchmark and r.get("benchmark") != benchmark:
            continue
        task = tasks.get(r["task_id"], {})
        gt = task.get("ground_truth", {})
        if cwe_filter is not None:
            tcwe = gt.get("cwe", "CWE-UNKNOWN")
            if not cwe_filter(tcwe):
                continue
        n_tasks += 1
        c = r["counts"]
        tp += c["tp"]
        fp += c["fp"]
        fn += c["fn"]
        findings_total += c["findings"]
        if r.get("fp_trap"):
            n_fp_trap += 1
            if c["findings"] == 0:
                tn += 1  # clean FP-trap task = true negative
    recall = _safe_div(tp, tp + fn)
    precision = _safe_div(tp, tp + fp)
    f1 = _f1(precision, recall)
    # FPR is OWASP-style: FP / (FP + TN). TN only exists where FP traps exist.
    fpr = _safe_div(fp, fp + tn) if (fp + tn) else None
    score = (recall - fpr) if fpr is not None else None
    return {
        "n_tasks": n_tasks, "n_fp_trap": n_fp_trap, "n_incomplete": n_incomplete,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "recall": recall, "precision": precision, "f1": f1, "fpr": fpr, "score": score,
        "findings_total": findings_total,
    }


def _per_cwe(records: list[dict], tasks: dict[str, dict], benchmark: str | None = None) -> dict[str, dict]:
    """Per-CWE breakdown (recall, precision, task counts)."""
    by_cwe: dict[str, dict] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "n": 0})
    for r in records:
        if r.get("excluded"):
            continue
        if benchmark and r.get("benchmark") != benchmark:
            continue
        task = tasks.get(r["task_id"], {})
        cwe = task.get("ground_truth", {}).get("cwe", "CWE-UNKNOWN")
        d = by_cwe[cwe]
        d["tp"] += r["counts"]["tp"]
        d["fp"] += r["counts"]["fp"]
        d["fn"] += r["counts"]["fn"]
        d["n"] += 1
    out: dict[str, dict] = {}
    for cwe, d in by_cwe.items():
        recall = _safe_div(d["tp"], d["tp"] + d["fn"])
        precision = _safe_div(d["tp"], d["tp"] + d["fp"])
        out[cwe] = {"n": d["n"], "tp": d["tp"], "fp": d["fp"], "fn": d["fn"],
                    "recall": recall, "precision": precision}
    return out


def _bounty_weighted_recall(records: list[dict], tasks: dict[str, dict]) -> dict:
    """$-weighted recall (bountytasks): sum bounty(found) / sum bounty(all)."""
    found_bounty = 0.0
    total_bounty = 0.0
    n = 0
    for r in records:
        if r.get("excluded"):
            continue
        if r.get("benchmark") != "bountytasks":
            continue
        task = tasks.get(r["task_id"], {})
        bounty = task.get("weights", {}).get("disclosure_bounty_usd", 0.0)
        total_bounty += bounty
        if r["counts"]["tp"] > 0:
            found_bounty += bounty
        n += 1
    return {
        "n": n,
        "found_bounty_usd": found_bounty,
        "total_bounty_usd": total_bounty,
        "weighted_recall": _safe_div(found_bounty, total_bounty),
    }


def _owasp_category_scorecard(records: list[dict], tasks: dict[str, dict]) -> list[dict]:
    """OWASP per-category TPR/FPR (comparable with published scorecards)."""
    by_cat: dict[str, dict] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "n": 0, "n_fp_trap": 0})
    for r in records:
        if r.get("benchmark") != "owasp" or r.get("excluded"):
            continue
        task = tasks.get(r["task_id"], {})
        cat = task.get("meta", {}).get("category", "unknown")
        d = by_cat[cat]
        d["tp"] += r["counts"]["tp"]
        d["fp"] += r["counts"]["fp"]
        d["fn"] += r["counts"]["fn"]
        d["n"] += 1
        if r.get("fp_trap"):
            d["n_fp_trap"] += 1
            if r["counts"]["findings"] == 0:
                d["tn"] += 1
    out = []
    for cat, d in sorted(by_cat.items()):
        tpr = _safe_div(d["tp"], d["tp"] + d["fn"])
        fpr = _safe_div(d["fp"], d["fp"] + d["tn"]) if (d["fp"] + d["tn"]) else None
        out.append({
            "category": cat, "n": d["n"], "n_fp_trap": d["n_fp_trap"],
            "tp": d["tp"], "fp": d["fp"], "fn": d["fn"], "tn": d["tn"],
            "tpr": tpr, "fpr": fpr, "score": (tpr - fpr) if fpr is not None else None,
        })
    return out


def _cwebench_method_vs_file(records: list[dict], tasks: dict[str, dict]) -> dict:
    """CWE-Bench: method-level recall vs file-level recall (localization delta)."""
    method_tp = method_total = 0
    file_tp = file_total = 0
    for r in records:
        if r.get("benchmark") != "cwebench" or r.get("excluded"):
            continue
        task = tasks.get(r["task_id"], {})
        methods = task.get("ground_truth", {}).get("vulnerable_methods", [])
        method_total += len(methods)
        method_tp += r["counts"]["tp"]
        # File-level: a task is file-found if any finding is in a vulnerable file.
        vuln_files = set(task.get("ground_truth", {}).get("vulnerable_files", []))
        file_found = any(f.get("file", "") in vuln_files for f in r.get("findings", []))
        file_total += 1
        if file_found:
            file_tp += 1
    return {
        "method_recall": _safe_div(method_tp, method_total),
        "file_recall": _safe_div(file_tp, file_total),
        "method_tp": method_tp, "method_total": method_total,
        "file_tp": file_tp, "file_total": file_total,
    }


def _cybergym_project_breakdown(records: list[dict], tasks: dict[str, dict]) -> list[dict]:
    """CyberGym: per-project recall/precision (location-only scoring).

    CyberGym has no CWE ground truth, so scoring is file-location-only: a
    finding in a file touched by ``patch.diff`` is a TP. We break results down
    by ``project_name`` to show which C/C++ projects the SAST handles well.
    """
    by_proj: dict[str, dict] = defaultdict(
        lambda: {"tp": 0, "fp": 0, "fn": 0, "n": 0, "solved": 0}
    )
    for r in records:
        if r.get("benchmark") != "cybergym" or r.get("excluded"):
            continue
        task = tasks.get(r["task_id"], {})
        proj = task.get("meta", {}).get("project_name", "unknown")
        d = by_proj[proj]
        c = r["counts"]
        d["tp"] += c["tp"]
        d["fp"] += c["fp"]
        d["fn"] += c["fn"]
        d["n"] += 1
        if c["tp"] > 0:
            d["solved"] += 1
    out = []
    for proj, d in sorted(by_proj.items()):
        out.append({
            "project": proj, "n": d["n"],
            "tp": d["tp"], "fp": d["fp"], "fn": d["fn"],
            "recall": _safe_div(d["tp"], d["tp"] + d["fn"]),
            "precision": _safe_div(d["tp"], d["tp"] + d["fp"]),
            "solved": d["solved"],
        })
    return out


def _sastbench_metrics(records: list[dict], tasks: dict[str, dict]) -> dict:
    """SASTbench: region-level metrics (Target Hit Rate, Capability FP Rate,
    Intent Accuracy, Agentic Score).

    Mirrors SASTbench's canonical scoring (``scripts/scoring.py``):
      - recall (Target Hit Rate) = TP / (TP + FN), region-level.
      - capability_fp_rate = capability_safe cases flagged / total capability_safe
        cases. A capability_safe case is "flagged" if it produced any finding
        that overlaps a capability_safe region (a capability false positive).
      - mixed_intent_accuracy = mixed_intent cases with 0 FN and 0 capability FP.
      - agentic_score = geometric_mean(recall, 1 - capability_fp_rate,
        mixed_intent_accuracy) — the headline SASTbench metric for agentic code.
    """
    tp = fp = fn = 0
    cap_safe_cases = 0
    cap_safe_cases_flagged = 0
    mi_cases = 0
    mi_cases_correct = 0
    for r in records:
        if r.get("benchmark") != "sastbench" or r.get("excluded"):
            continue
        task = tasks.get(r["task_id"], {})
        meta = task.get("meta", {})
        case_type = meta.get("case_type", "")
        c = r["counts"]
        tp += c["tp"]
        fp += c["fp"]
        fn += c["fn"]
        cap_fp = c.get("capability_fp", 0)
        if case_type == "capability_safe":
            cap_safe_cases += 1
            if c["fp"] > 0:
                cap_safe_cases_flagged += 1
        elif case_type == "mixed_intent":
            mi_cases += 1
            if c["fn"] == 0 and cap_fp == 0:
                mi_cases_correct += 1
    recall = _safe_div(tp, tp + fn)
    precision = _safe_div(tp, tp + fp)
    capability_fp_rate = _safe_div(cap_safe_cases_flagged, cap_safe_cases)
    mixed_intent_accuracy = _safe_div(mi_cases_correct, mi_cases)
    # Agentic score: geometric mean of recall, (1 - cap_fp_rate), mi_accuracy.
    # Following SASTbench's compute_summary; zero components collapse the score.
    components = [recall, 1.0 - capability_fp_rate, mixed_intent_accuracy]
    if any(x <= 0 for x in components):
        agentic_score = 0.0
    else:
        agentic_score = (components[0] * components[1] * components[2]) ** (1.0 / 3.0)
    return {
        "tp": tp, "fp": fp, "fn": fn,
        "recall": recall, "precision": precision,
        "capability_safe_cases": cap_safe_cases,
        "capability_safe_cases_flagged": cap_safe_cases_flagged,
        "capability_fp_rate": capability_fp_rate,
        "mixed_intent_cases": mi_cases,
        "mixed_intent_cases_correct": mi_cases_correct,
        "mixed_intent_accuracy": mixed_intent_accuracy,
        "agentic_score": agentic_score,
    }


def _fmt(x, digits=4):
    if x is None:
        return "n/a"
    if isinstance(x, float):
        return f"{x:.{digits}f}"
    return str(x)


def _excluded_audit(records: list[dict], tasks: dict[str, dict]) -> dict:
    audit = {"incomplete_ground_truth": [], "source_missing": [], "unvalidated": []}
    for r in records:
        tid = r["task_id"]
        if r.get("excluded"):
            audit["incomplete_ground_truth"].append(tid)
        task = tasks.get(tid, {})
        meta = task.get("meta", {})
        if meta.get("source_missing"):
            audit["source_missing"].append(tid)
        if meta.get("task_validated") is False and task.get("benchmark") == "bountytasks":
            audit["unvalidated"].append(tid)
    return audit


def _exploit_validation_metrics(exploit_dir: str | None, tool: str, benchmark: str) -> dict | None:
    """Aggregate exploit-validation verdicts for one benchmark.

    Returns None if no exploit reports exist (e.g., exploit step not run).
    """
    if not exploit_dir:
        return None
    ed = Path(exploit_dir) / tool
    if not ed.is_dir():
        return None
    agg = {"findings": 0, "confirmed": 0, "unconfirmed": 0,
           "matched_static_only": 0, "unreachable": 0}
    found_any = False
    for p in sorted(ed.glob("*.json")):
        with open(p, "r", encoding="utf-8") as f:
            report = json.load(f)
        if report.get("benchmark") != benchmark:
            continue
        found_any = True
        c = report.get("counts", {})
        for k in agg:
            agg[k] += c.get(k, 0)
    return agg if found_any else None


def render_scorecard(matched_dirs: list[str], tasks_dir: str, imported_dir: str, out_path: str,
                     exploit_dir: str | None = None) -> str:
    tasks = _load_tasks(tasks_dir)

    # Load matched records from one or more tool dirs (we score per-tool; if
    # multiple, we render each tool's section). For a single tool, the headline
    # is that tool.
    tool_sections: list[dict] = []
    for md in matched_dirs:
        tool = os.path.basename(os.path.normpath(md))
        records = _load_matched(md)
        tool_sections.append({"tool": tool, "records": records})

    lines: list[str] = []
    lines.append("# Unified SAST Scorecard")
    lines.append("")
    lines.append(f"Harness version: {HARNESS_VERSION}")
    lines.append("")
    lines.append("> Every table carries a `unit:` label (§9.5). Imported metrics carry")
    lines.append("> `source: science-team-runner` and are never blended with this harness's")
    lines.append("> metrics. FPR is only defined where FP-trap tasks exist (OWASP); for")
    lines.append("> bountytasks/CWE-Bench, precision is reported instead and FPR is n/a.")
    lines.append("")

    for sec in tool_sections:
        tool = sec["tool"]
        records = sec["records"]
        lines.append(f"## Tool: `{tool}`")
        lines.append("")

        # --- Headline table (per benchmark + common-CWE-core combined) ---
        lines.append("### Headline metrics (per benchmark + common-CWE-core combined)")
        lines.append("")
        lines.append(f"unit: system | model:{HARNESS_VERSION} | harness:{tool}")
        lines.append("")
        lines.append("| Benchmark | Tasks | TP | FP | FN | Recall | Precision | F1 | FPR | Score (TPR-FPR) |")
        lines.append("|-----------|-------|----|----|----|--------|-----------|----|-----|------------------|")
        for bench in ["owasp", "bountytasks", "cwebench", "cybergym", "sastbench"]:
            agg = _aggregate(records, tasks, benchmark=bench)
            name = {"owasp": "OWASP", "bountytasks": "bountytasks",
                    "cwebench": "CWE-Bench", "cybergym": "CyberGym",
                    "sastbench": "SASTbench"}[bench]
            lines.append(f"| {name} | {agg['n_tasks']} | {agg['tp']} | {agg['fp']} | {agg['fn']} | "
                         f"{_fmt(agg['recall'])} | {_fmt(agg['precision'])} | {_fmt(agg['f1'])} | "
                         f"{_fmt(agg['fpr'])} | {_fmt(agg['score'])} |")
        # Combined (common CWE core only)
        agg_comb = _aggregate(records, tasks, benchmark=None, cwe_filter=_in_common_core)
        lines.append(f"| **Combined (common CWE core)** | {agg_comb['n_tasks']} | {agg_comb['tp']} | "
                     f"{agg_comb['fp']} | {agg_comb['fn']} | {_fmt(agg_comb['recall'])} | "
                     f"{_fmt(agg_comb['precision'])} | {_fmt(agg_comb['f1'])} | "
                     f"{_fmt(agg_comb['fpr'])} | {_fmt(agg_comb['score'])} |")
        lines.append("")
        lines.append(f"Combined is computed only over the common CWE core "
                     f"({', '.join(COMMON_CWE_CORE)}) to avoid mixing incomparable task populations (§6.5).")
        lines.append("")

        # --- Per-CWE table (common core) ---
        lines.append("### Per-CWE breakdown (common core)")
        lines.append("")
        lines.append(f"unit: system | model:{HARNESS_VERSION} | harness:{tool}")
        lines.append("")
        lines.append("| CWE | Tasks | TP | FP | FN | Recall | Precision |")
        lines.append("|-----|-------|----|----|----|--------|-----------|")
        per_cwe = _per_cwe(records, tasks)
        for cwe in COMMON_CWE_CORE + [c for c in sorted(per_cwe) if c not in COMMON_CWE_CORE and c != "CWE-UNKNOWN"]:
            if cwe not in per_cwe:
                lines.append(f"| {cwe} | 0 | 0 | 0 | 0 | n/a | n/a |")
                continue
            d = per_cwe[cwe]
            lines.append(f"| {cwe} | {d['n']} | {d['tp']} | {d['fp']} | {d['fn']} | "
                         f"{_fmt(d['recall'])} | {_fmt(d['precision'])} |")
        lines.append("")

        # --- Benchmark-specific sections ---
        lines.append("### Benchmark-specific metrics")
        lines.append("")
        lines.append(f"unit: system | model:{HARNESS_VERSION} | harness:{tool}")
        lines.append("")

        # bountytasks: $-weighted recall + per-bounty binary detection
        bw = _bounty_weighted_recall(records, tasks)
        lines.append("**bountytasks — $-weighted recall**")
        lines.append("")
        lines.append(f"- Bounties scored: {bw['n']}")
        lines.append(f"- Found bounty $: {bw['found_bounty_usd']:.2f}")
        lines.append(f"- Total bounty $: {bw['total_bounty_usd']:.2f}")
        lines.append(f"- $-weighted recall: {_fmt(bw['weighted_recall'])}")
        lines.append("")

        # OWASP: category scorecard
        lines.append("**OWASP — per-category scorecard** (comparable with published FindBugs/PMD/ZAP scorecards)")
        lines.append("")
        lines.append("| Category | N | N(FP-trap) | TP | FP | FN | TN | TPR | FPR | Score |")
        lines.append("|----------|---|------------|----|----|----|----|-----|-----|-------|")
        for row in _owasp_category_scorecard(records, tasks):
            lines.append(f"| {row['category']} | {row['n']} | {row['n_fp_trap']} | {row['tp']} | "
                         f"{row['fp']} | {row['fn']} | {row['tn']} | {_fmt(row['tpr'])} | "
                         f"{_fmt(row['fpr'])} | {_fmt(row['score'])} |")
        lines.append("")

        # CWE-Bench: method-vs-file recall
        mf = _cwebench_method_vs_file(records, tasks)
        lines.append("**CWE-Bench — method-level vs file-level recall** (localization precision)")
        lines.append("")
        lines.append(f"- Method-level recall: {_fmt(mf['method_recall'])} ({mf['method_tp']}/{mf['method_total']})")
        lines.append(f"- File-level recall: {_fmt(mf['file_recall'])} ({mf['file_tp']}/{mf['file_total']})")
        lines.append(f"- Localization delta (file - method): {_fmt(mf['file_recall'] - mf['method_recall'])}")
        lines.append("")

        # CyberGym: per-project breakdown (location-only scoring)
        lines.append("**CyberGym — per-project recall/precision** (location-only; no CWE ground truth)")
        lines.append("")
        lines.append("> CyberGym tasks have no CWE label, so scoring is file-location-only: a finding")
        lines.append("> in a file touched by `patch.diff` is a TP. This is a static-analysis proxy, not")
        lines.append("> CyberGym's canonical PoC-crash metric (`success_rate`).")
        lines.append("")
        proj_rows = _cybergym_project_breakdown(records, tasks)
        if proj_rows:
            lines.append("| Project | Tasks | Solved | TP | FP | FN | Recall | Precision |")
            lines.append("|---------|-------|--------|----|----|----|--------|-----------|")
            for row in proj_rows:
                lines.append(f"| {row['project']} | {row['n']} | {row['solved']} | {row['tp']} | "
                             f"{row['fp']} | {row['fn']} | {_fmt(row['recall'])} | {_fmt(row['precision'])} |")
        else:
            lines.append("_No CyberGym tasks with source available (run `make fetch` to download)._")
        lines.append("")

        # SASTbench: region-level metrics (agentic code, capability FP rate)
        sb = _sastbench_metrics(records, tasks)
        lines.append("**SASTbench — region-level metrics** (agentic code; capability-safe FP rate)")
        lines.append("")
        lines.append("> SASTbench evaluates SAST on agentic codebases. Agentic code intentionally")
        lines.append("> calls dangerous APIs (subprocess, fs, requests); a good scanner flags these")
        lines.append("> only when guards are missing. Capability-safe cases contain properly guarded")
        lines.append("> dangerous code — flagging them is a capability false positive. The Agentic")
        lines.append("> Score is the geometric mean of recall, (1 - capability FP rate), and mixed-intent")
        lines.append("> accuracy (mirrors SASTbench's canonical `scripts/scoring.py`).")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Target Hit Rate (recall) | {_fmt(sb['recall'])} |")
        lines.append(f"| Precision | {_fmt(sb['precision'])} |")
        lines.append(f"| Capability FP Rate | {_fmt(sb['capability_fp_rate'])} |")
        lines.append(f"| Mixed-Intent Accuracy | {_fmt(sb['mixed_intent_accuracy'])} |")
        lines.append(f"| Agentic Score (geomean) | {_fmt(sb['agentic_score'])} |")
        lines.append("")
        lines.append(f"- Capability-safe cases: {sb['capability_safe_cases']} "
                    f"({sb['capability_safe_cases_flagged']} flagged = capability FPs)")
        lines.append(f"- Mixed-intent cases: {sb['mixed_intent_cases']} "
                    f"({sb['mixed_intent_cases_correct']} correct = 0 FN and 0 capability FP)")
        lines.append(f"- TP/FP/FN (region-level): {sb['tp']}/{sb['fp']}/{sb['fn']}")
        lines.append("")

        # --- Efficiency metrics ---
        lines.append("### Efficiency metrics")
        lines.append("")
        lines.append(f"unit: system | model:{HARNESS_VERSION} | harness:{tool}")
        lines.append("")
        lines.append("| Benchmark | Tasks | Total findings | Avg findings/task |")
        lines.append("|-----------|-------|-----------------|-------------------|")
        for bench in ["owasp", "bountytasks", "cwebench", "cybergym", "sastbench"]:
            agg = _aggregate(records, tasks, benchmark=bench)
            avg = _safe_div(agg["findings_total"], agg["n_tasks"])
            name = {"owasp": "OWASP", "bountytasks": "bountytasks",
                    "cwebench": "CWE-Bench", "cybergym": "CyberGym",
                    "sastbench": "SASTbench"}[bench]
            lines.append(f"| {name} | {agg['n_tasks']} | {agg['findings_total']} | {_fmt(avg, 2)} |")
        lines.append("")

        # --- Excluded tasks audit ---
        lines.append("### Excluded tasks audit (always reported, never silently dropped)")
        lines.append("")
        audit = _excluded_audit(records, tasks)
        lines.append(f"- Incomplete ground truth (empty patch dict, bountytasks): {len(audit['incomplete_ground_truth'])}")
        for tid in audit["incomplete_ground_truth"]:
            lines.append(f"  - `{tid}`")
        lines.append(f"- Source missing (codebase submodule not checked out): {len(audit['source_missing'])}")
        if len(audit["source_missing"]) <= 20:
            for tid in audit["source_missing"]:
                lines.append(f"  - `{tid}`")
        else:
            lines.append(f"  - (first 20 of {len(audit['source_missing'])} shown)")
            for tid in audit["source_missing"][:20]:
                lines.append(f"  - `{tid}`")
        lines.append(f"- Unvalidated bounties (bountytasks, run_ci_local.sh not run): {len(audit['unvalidated'])}")
        lines.append("")

        lines.append("---")
        lines.append("")

        # --- Exploit-validation metrics (§10) ---
        lines.append("### Exploit validation (§10 — 4-tier oracle)")
        lines.append("")
        lines.append(f"unit: system | model:{HARNESS_VERSION} | harness:{tool}")
        lines.append("")
        lines.append("Tier 0 = static match | Tier 1 = reachability | Tier 2 = canary probe | Tier 3 = full exploit")
        lines.append("")
        lines.append("| Benchmark | Findings | Confirmed | Unconfirmed | Matched-static-only | Unreachable | Confirmed precision |")
        lines.append("|-----------|----------|-----------|-------------|---------------------|-------------|--------------------|")
        for bench in ["owasp", "bountytasks", "cwebench", "cybergym", "sastbench"]:
            ev = _exploit_validation_metrics(exploit_dir, tool, bench)
            if ev is None:
                name = {"owasp": "OWASP", "bountytasks": "bountytasks",
                        "cwebench": "CWE-Bench", "cybergym": "CyberGym",
                        "sastbench": "SASTbench"}[bench]
                lines.append(f"| {name} | — | — | — | — | — | — |")
                continue
            cp = _safe_div(ev["confirmed"], ev["confirmed"] + ev["unconfirmed"]) if (ev["confirmed"] + ev["unconfirmed"]) else 0.0
            name = {"owasp": "OWASP", "bountytasks": "bountytasks",
                    "cwebench": "CWE-Bench", "cybergym": "CyberGym",
                    "sastbench": "SASTbench"}[bench]
            lines.append(
                f"| {name} | {ev['findings']} | {ev['confirmed']} | {ev['unconfirmed']} | "
                f"{ev['matched_static_only']} | {ev['unreachable']} | {_fmt(cp, 2)} |"
            )
        lines.append("")
        lines.append("- **Confirmed precision** = confirmed / (confirmed + unconfirmed). Measures actionability.")
        lines.append("- **Unreachable** (Tier 1) filters findings on dead code — a static, no-runtime signal.")
        lines.append("- See [docs/EXPLOIT_VALIDATION.md](docs/EXPLOIT_VALIDATION.md) for the 4-tier oracle design.")
        lines.append("")

        lines.append("---")
        lines.append("")

    # --- Imported metrics (science team runner, verbatim) ---
    lines.append("## Imported metrics (science team runner — canonical)")
    lines.append("")
    lines.append("source: science-team-runner")
    lines.append("")
    imported_files = sorted(glob.glob(os.path.join(imported_dir, "*.jsonl")))
    if not imported_files:
        lines.append("_No imported runner results available yet. The science team's runner")
        lines.append("output format is inventoried in `importers/FORMATS.md`; importers emit")
        lines.append("verbatim records under their metric names once result files are provided._")
    else:
        for imp in imported_files:
            bench = os.path.basename(imp).replace(".jsonl", "")
            n = sum(1 for _ in open(imp))
            lines.append(f"- `{imp}`: {n} records (benchmark: {bench})")
    lines.append("")

    # --- Caveats ---
    lines.append("## Caveats (§8)")
    lines.append("")
    lines.append("- **FP measurement asymmetry**: only OWASP has true-negative tasks. For")
    lines.append("  bountytasks/CWE-Bench, precision is computed against findings outside the")
    lines.append("  known vuln, which conflates FPs with undetected other real bugs.")
    lines.append("- **bountytasks ground truth is patch-derived**: the fix commit may touch")
    lines.append("  files for unrelated reasons (refactors, tests).")
    lines.append("- **CWE-Bench line drift**: method_start/end refer to the fixed commit;")
    lines.append("  the matcher uses method-identity first, line ranges second.")
    lines.append("- **OWASP is synthetic**: 2,740 tiny servlets; recall does not predict recall")
    lines.append("  on real codebases. That is why the combined eval exists.")
    lines.append("- **CyberGym is location-only**: no CWE ground truth, so a finding in a")
    lines.append("  patch.diff-touched file is a TP regardless of the tool's CWE label. This")
    lines.append("  is a static-analysis proxy, not CyberGym's canonical PoC-crash metric")
    lines.append("  (`success_rate` from the agent-eval server). Precision is inflated vs a")
    lines.append("  CWE-aware benchmark because wrong-CWE findings in the right file count as TP.")
    lines.append("- **Language coverage**: bountytasks is mostly Python/JS; the Java benchmarks")
    lines.append("  are Java-only; CyberGym is C/C++. Combined numbers only make sense")
    lines.append("  per-language for single-language tools.")
    lines.append("")

    text = "\n".join(lines)
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(text)
    return text


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score matched results and render scorecard (§6)")
    parser.add_argument("--matched", nargs="+", required=True, help="One or more results/matched/<tool>/ dirs")
    parser.add_argument("--imported", default="imported", help="Directory of imported/*.jsonl")
    parser.add_argument("--tasks", default="tasks", help="Directory of tasks/*.jsonl")
    parser.add_argument("--out", required=True, help="Output reports/scorecard.md path")
    parser.add_argument("--exploits", default=None, help="results/exploits/ root (§10 exploit-validation reports)")
    args = parser.parse_args(argv)

    render_scorecard(args.matched, args.tasks, args.imported, args.out, exploit_dir=args.exploits)
    print(f"Wrote scorecard to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
