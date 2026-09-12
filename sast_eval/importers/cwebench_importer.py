"""CWE-Bench-Java importer (science team's runner is canonical) — §3.3 / Step 3c.

Joins ``data/project_info.csv`` (one row per CVE) with ``data/fix_info.csv``
(one row per fixed method) on ``project_slug`` to build unified task records.

Per §3.3:
- ``source_root`` = ``project-sources/<slug>`` at ``buggy_commit_id``.
- ``vulnerable_methods`` <- fix_info rows: file, class, method, line ranges,
  signature. A CVE with multiple fix rows yields multiple method entries.
- Line-drift caveat: ``method_start/end`` refer to the *fixed* file; when
  scanning the *buggy* commit, ranges may be off by a few lines. The matcher
  prefers method-identity matching (file + method name/signature) and uses line
  ranges only as a secondary signal.

Also imports the science team's runner results verbatim into
``imported/cwebench.jsonl`` under their metric names.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path

from sast_eval.adapters.common import normalize_cwe


def _load_csv(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _int_or_none(v: str) -> int | None:
    v = (v or "").strip()
    if not v:
        return None
    try:
        return int(v)
    except ValueError:
        return None


def build_tasks(root: str) -> list[dict]:
    root_path = Path(root).resolve()
    project_info_path = root_path / "data" / "project_info.csv"
    fix_info_path = root_path / "data" / "fix_info.csv"
    if not project_info_path.exists():
        raise FileNotFoundError(f"data/project_info.csv not found at {project_info_path}")
    if not fix_info_path.exists():
        raise FileNotFoundError(f"data/fix_info.csv not found at {fix_info_path}")

    projects = _load_csv(project_info_path)
    fixes = _load_csv(fix_info_path)

    # Group fix rows by project_slug.
    fixes_by_slug: dict[str, list[dict]] = {}
    for fx in fixes:
        slug = fx.get("project_slug", "").strip()
        if slug:
            fixes_by_slug.setdefault(slug, []).append(fx)

    tasks: list[dict] = []
    for proj in projects:
        slug = proj.get("project_slug", "").strip()
        if not slug:
            continue
        cve = proj.get("cve_id", "").strip() or None
        cwe_raw = proj.get("cwe_id", "").strip()
        cwe = normalize_cwe(cwe_raw)
        cwe_name = proj.get("cwe_name", "").strip()
        buggy_commit = proj.get("buggy_commit_id", "").strip()

        # vulnerable_methods from fix_info rows for this slug.
        vuln_methods: list[dict] = []
        vuln_files: set[str] = set()
        for fx in fixes_by_slug.get(slug, []):
            file = fx.get("file", "").strip()
            if file:
                vuln_files.add(file)
            method = {
                "file": file,
                "class": fx.get("class", "").strip(),
                "method": fx.get("method", "").strip(),
                "start": _int_or_none(fx.get("method_start")),
                "end": _int_or_none(fx.get("method_end")),
                "signature": fx.get("signature", "").strip(),
                # class-level range (secondary signal)
                "class_start": _int_or_none(fx.get("class_start")),
                "class_end": _int_or_none(fx.get("class_end")),
            }
            vuln_methods.append(method)

        source_root = str(root_path / "project-sources" / slug)

        task = {
            "task_id": f"cwebench/{slug}",
            "benchmark": "cwebench",
            "language": "java",
            "source_root": source_root,
            "vcs": {
                "type": "git",
                "commit": buggy_commit,
                "checked_out": os.path.isdir(source_root) and bool(buggy_commit),
            },
            "ground_truth": {
                "cwe": cwe,
                "cwe_raw": cwe_raw or cwe_name,
                "cve": cve,
                "vulnerable_files": sorted(vuln_files),
                "vulnerable_methods": vuln_methods,
                "fp_trap": False,
                "notes": "method_start/end refer to the FIXED commit (line drift)",
            },
            "weights": {},
            "meta": {
                "project_slug": slug,
                "github_url": proj.get("github_url", "").strip(),
                "github_tag": proj.get("github_tag", "").strip(),
                "advisory_id": proj.get("advisory_id", "").strip(),
            },
        }
        tasks.append(task)
    return tasks


def import_runner_results(results_path: str | None, root: str) -> list[dict]:
    """Import the science team's runner results verbatim into unified records.

    Their CWE-Bench runner emits a per-tool CSV (e.g. ``spotbugs_result.csv``)
    with rows ``[project_slug, cwe, kind, message]`` (see
    ``baselines/output_*_result.py``). We map each row to a unified record with
    provenance, carrying the verbatim values. We do NOT recompute metrics.

    If ``results_path`` is a directory, we import every ``*_result.csv`` in it.
    If it is absent, we emit nothing (the pipeline still works; the importer
    must fail loudly on unrecognized fields per §12.2, so we do not guess).
    """
    if not results_path or not os.path.exists(results_path):
        return []

    imported: list[dict] = []
    root_path = Path(root).resolve()

    csv_files: list[str] = []
    if os.path.isdir(results_path):
        csv_files = sorted(
            str(p) for p in Path(results_path).glob("*_result.csv")
        )
    else:
        csv_files = [results_path]

    for cf in csv_files:
        tool = Path(cf).stem.replace("_result", "")
        file_hash = hashlib.sha256(Path(cf).read_bytes()).hexdigest()[:16]
        with open(cf, newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                if not row or len(row) < 4:
                    continue
                slug, cwe, kind, message = row[0], row[1], row[2], row[3]
                imported.append({
                    "task_id": f"cwebench/{slug}",
                    "benchmark": "cwebench",
                    "tool": tool,
                    "source": "science-team-runner",
                    "runner_version": "unknown",
                    "result_file_hash": file_hash,
                    "result_file": cf,
                    "metric": "raw_finding",
                    "value": {
                        "cwe": cwe,
                        "kind": kind,
                        "message": message,
                    },
                })
    return imported


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build CWE-Bench-Java task records + import runner results")
    parser.add_argument("--root", required=True, help="Path to cwe-bench-java repo root")
    parser.add_argument("--results", default=None, help="Path to science team runner results (CSV file or dir)")
    parser.add_argument("--tasks-out", required=True, help="Output task records JSONL")
    parser.add_argument("--imported-out", required=True, help="Output imported results JSONL")
    args = parser.parse_args(argv)

    tasks = build_tasks(args.root)
    os.makedirs(os.path.dirname(os.path.abspath(args.tasks_out)), exist_ok=True)
    with open(args.tasks_out, "w", encoding="utf-8") as f:
        for t in tasks:
            f.write(json.dumps(t, ensure_ascii=False, sort_keys=True) + "\n")
    print(f"Wrote {len(tasks)} CWE-Bench task records to {args.tasks_out}")

    imported = import_runner_results(args.results, args.root)
    os.makedirs(os.path.dirname(os.path.abspath(args.imported_out)), exist_ok=True)
    with open(args.imported_out, "w", encoding="utf-8") as f:
        for rec in imported:
            f.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")
    print(f"Wrote {len(imported)} imported CWE-Bench result records to {args.imported_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
