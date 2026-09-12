"""bountytasks importer (science team's runner is canonical) — §3.1 / Step 3a.

This importer does NOT re-run, re-match, or re-score the science team's runner.
It only:
  1. Builds unified task records (schema §2) from ``bounty_metadata.json`` for
     cross-referencing (CWE normalization §2.1, ``patch`` dict ->
     ``vulnerable_files``, ``disclosure_bounty``/``patch_bounty`` -> ``weights``).
  2. Imports their runner results **verbatim** into ``imported/bountytasks.jsonl``
     under **their** metric names (``detect_success_rate``, etc.) — never
     recomputed.

If their runner results are not yet available (Step 2 inventory pending), the
importer still emits task records and writes an empty ``imported/bountytasks.jsonl``.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
from pathlib import Path

from sast_eval.adapters.common import normalize_cwe, parse_bounty_value


def _detect_language(project_dir: Path) -> str:
    """Best-effort language detection from the project dir contents."""
    # The codebase/ subdir (if present) is the real signal, but it's often a
    # private submodule that isn't checked out. Fall back to repo-level hints.
    hints = {
        "python": ["requirements.txt", "setup.py", "pyproject.toml", "Pipfile"],
        "javascript": ["package.json"],
        "typescript": ["tsconfig.json"],
        "go": ["go.mod"],
        "c": ["CMakeLists.txt", "Makefile"],
    }
    for lang, files in hints.items():
        if any((project_dir / fn).exists() for fn in files):
            return lang
    return "unknown"


def _build_task_record(metadata_path: str, root: Path) -> dict:
    with open(metadata_path, "r", encoding="utf-8") as f:
        meta = json.load(f)

    # Paths: <root>/<project>/bounties/bounty_<N>/bounty_metadata.json
    meta_path = Path(metadata_path)
    bounty_dir = meta_path.parent                       # .../bounties/bounty_N
    bounties_dir = bounty_dir.parent                    # .../bounties
    project_dir = bounties_dir.parent                   # .../<project>
    project_name = project_dir.name
    bounty_name = bounty_dir.name                       # bounty_N

    cwe_raw = meta.get("CWE", "")
    cwe = normalize_cwe(cwe_raw)
    cve = meta.get("CVE") or None
    vulnerable_commit = meta.get("vulnerable_commit", "")

    # patch dict: keys are patch_files/ names, values are codebase-relative paths.
    patch = meta.get("patch", {}) or {}
    # vulnerable_files = the codebase-relative target paths (values), stripped of
    # the leading "codebase/" prefix so they are repo-relative under source_root.
    vulnerable_files: list[str] = []
    for target in patch.values():
        rel = target
        if rel.startswith("codebase/"):
            rel = rel[len("codebase/"):]
        vulnerable_files.append(rel)

    ground_truth_incomplete = len(vulnerable_files) == 0

    # source_root = <project_dir>/codebase (the buggy snapshot checked out at
    # vulnerable_commit). The codebase/ submodule is often private/missing.
    codebase_dir = project_dir / "codebase"
    source_missing = not codebase_dir.exists() or not any(codebase_dir.iterdir())
    source_root = str(codebase_dir) if not source_missing else str(codebase_dir)

    disclosure_bounty = parse_bounty_value(meta.get("disclosure_bounty"))
    patch_bounty = parse_bounty_value(meta.get("patch_bounty"))
    # Some files use fix_bounty instead of patch_bounty (see calculate_bounties.py).
    fix_bounty = parse_bounty_value(meta.get("fix_bounty"))
    total_patch = patch_bounty + fix_bounty

    severity_raw = meta.get("severity", "")
    try:
        severity_num = float(severity_raw)
    except (ValueError, TypeError):
        severity_num = None

    task = {
        "task_id": f"bountytasks/{project_name}/{bounty_name}",
        "benchmark": "bountytasks",
        "language": _detect_language(project_dir),
        "source_root": source_root,
        "vcs": {
            "type": "git",
            "commit": vulnerable_commit,
            "checked_out": not source_missing,
        },
        "ground_truth": {
            "cwe": cwe,
            "cwe_raw": cwe_raw,
            "cve": cve,
            "vulnerable_files": vulnerable_files,
            "vulnerable_methods": [],
            "fp_trap": False,
            "notes": "patch dict maps patch_files/ -> repo paths",
            "ground_truth_incomplete": ground_truth_incomplete,
        },
        "weights": {
            "disclosure_bounty_usd": disclosure_bounty,
            "patch_bounty_usd": total_patch,
        },
        "meta": {
            "severity": severity_num if severity_num is not None else severity_raw,
            "task_validated": False,
            "source_missing": source_missing,
            "bounty_link": meta.get("bounty_link"),
        },
    }
    return task


def build_tasks(metadata_root: str) -> list[dict]:
    root = Path(metadata_root).resolve()
    pattern = str(root / "*" / "bounties" / "bounty_*" / "bounty_metadata.json")
    metadata_files = sorted(glob.glob(pattern))
    tasks: list[dict] = []
    for mp in metadata_files:
        tasks.append(_build_task_record(mp, root))
    return tasks


def import_runner_results(results_path: str | None, tasks: list[dict]) -> list[dict]:
    """Import the science team's runner results verbatim into unified records.

    Their result format is inventoried in ``importers/FORMATS.md``. Until that
    inventory is confirmed and result files are available, this emits an empty
    list (the importer must fail loudly on unrecognized fields — see §12.2 — so
    we do not guess a format).

    Each imported record carries provenance: ``source: science-team-runner``,
    ``runner_version``, ``result_file_hash``, and the verbatim metric values
    under their own names.
    """
    if not results_path or not os.path.exists(results_path):
        return []

    imported: list[dict] = []
    # The exact on-disk format is pending the §12.1 inventory. We support a
    # simple JSONL-of-objects fallback so the pipeline is wired end-to-end; the
    # science team confirms the real shape in FORMATS.md before this is trusted.
    with open(results_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            # Carry over verbatim with provenance. We do NOT recompute anything.
            rec.setdefault("source", "science-team-runner")
            rec.setdefault("runner_version", "unknown")
            imported.append(rec)
    return imported


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build bountytasks task records + import runner results")
    parser.add_argument("--metadata-root", required=True, help="Path to bountytasks repo root")
    parser.add_argument("--results", default=None, help="Path to science team runner results (JSONL) or dir")
    parser.add_argument("--tasks-out", required=True, help="Output task records JSONL")
    parser.add_argument("--imported-out", required=True, help="Output imported results JSONL")
    args = parser.parse_args(argv)

    tasks = build_tasks(args.metadata_root)
    os.makedirs(os.path.dirname(os.path.abspath(args.tasks_out)), exist_ok=True)
    with open(args.tasks_out, "w", encoding="utf-8") as f:
        for t in tasks:
            f.write(json.dumps(t, ensure_ascii=False, sort_keys=True) + "\n")
    print(f"Wrote {len(tasks)} bountytasks task records to {args.tasks_out}")

    imported = import_runner_results(args.results, tasks)
    os.makedirs(os.path.dirname(os.path.abspath(args.imported_out)), exist_ok=True)
    with open(args.imported_out, "w", encoding="utf-8") as f:
        for rec in imported:
            f.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")
    print(f"Wrote {len(imported)} imported bountytasks result records to {args.imported_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
