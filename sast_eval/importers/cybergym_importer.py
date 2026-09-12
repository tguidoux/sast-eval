"""CyberGym importer (science team's agent-eval is canonical) — §3.3 / Step 3c.

CyberGym is a fuzzer-based benchmark (ARVO + OSS-Fuzz) for C/C++ projects. Its
task metadata lives in ``tasks.json`` (one record per task) downloaded from the
HuggingFace dataset ``sunblaze-ucb/cybergym``. Each task's source is a
``repo-vul.tar.gz`` (vulnerable source tree under ``src-vul/``) plus a
``patch.diff`` (the fix) and ``description.txt``.

Per §3.3:
- ``source_root`` = ``data/<type>/<id>`` (the per-task data directory). The
  SAST-analyzable source is ``repo-vul.tar.gz`` inside it; packaging extracts
  that tarball's ``src-vul/`` tree.
- ``vulnerable_files`` <- paths touched by ``patch.diff`` (``diff --git a/… b/…``).
- ``vulnerable_methods`` <- not available (fuzzer benchmarks don't enumerate
  method-level ground truth; the patch may touch non-method constructs).
- ``cwe`` <- ``CWE-UNKNOWN`` (CyberGym's ``tasks.json`` has no CWE field; the
  vulnerability type is only described in ``vulnerability_description``).
- ``cve`` <- ``None`` (not in ``tasks.json``).

This is an importer: CyberGym's canonical runner is the agent-eval server
(``verify_agent_result.py``), not a SARIF-based SAST. We import the task
metadata so the harness can package the vulnerable source for SAST analysis
and (optionally) import the agent-eval runner results later.
"""
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path

from sast_eval.adapters.common import normalize_cwe

# ``diff --git a/<path> b/<path>`` — captures the ``a/`` side (pre-image file).
_DIFF_GIT = re.compile(r"^diff --git a/(.+?) b/.+$")


def _parse_vulnerable_files(patch_path: Path) -> list[str]:
    """Extract the set of file paths touched by a ``patch.diff``.

    Returns the ``a/`` side (vulnerable/pre-image) paths, sorted and de-duped.
    """
    if not patch_path.is_file():
        return []
    files: set[str] = set()
    with open(patch_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = _DIFF_GIT.match(line)
            if m:
                files.add(m.group(1))
    return sorted(files)


def _language_map(raw: str) -> str:
    """Map CyberGym's ``project_language`` to our language field."""
    m = {
        "c": "c",
        "c++": "cpp",
        "cpp": "cpp",
        "python": "python",
        "go": "go",
        "rust": "rust",
        "java": "java",
    }
    return m.get((raw or "").strip().lower(), (raw or "").strip().lower() or "unknown")


def build_tasks(root: str) -> list[dict]:
    """Build unified task records from CyberGym's ``tasks.json``.

    ``root`` is the CyberGym data root (containing ``tasks.json`` and
    ``data/<type>/<id>/`` per-task directories).
    """
    root_path = Path(root).resolve()
    tasks_json = root_path / "tasks.json"
    if not tasks_json.is_file():
        raise FileNotFoundError(f"tasks.json not found at {tasks_json}")

    tasks_raw = json.loads(tasks_json.read_text(encoding="utf-8"))
    tasks: list[dict] = []

    for t in tasks_raw:
        tid = t.get("task_id", "").strip()
        if not tid:
            continue
        # task_id is "<type>:<id>" e.g. "arvo:1065"
        parts = tid.split(":", 1)
        if len(parts) != 2:
            continue
        task_type, task_num = parts
        data_dir = root_path / "data" / task_type / task_num
        repo_vul = data_dir / "repo-vul.tar.gz"
        patch_diff = data_dir / "patch.diff"

        vuln_files = _parse_vulnerable_files(patch_diff)
        source_missing = not repo_vul.is_file()

        description = t.get("vulnerability_description", "").strip()

        task = {
            "task_id": f"cybergym/{tid}",
            "benchmark": "cybergym",
            "language": _language_map(t.get("project_language", "")),
            "source_root": str(data_dir),
            "vcs": {
                "type": "archive",
                "commit": None,
                "checked_out": not source_missing,
            },
            "ground_truth": {
                "cwe": "CWE-UNKNOWN",
                "cwe_raw": "",
                "cve": None,
                "vulnerable_files": vuln_files,
                "vulnerable_methods": [],
                "fp_trap": False,
                "notes": description,
            },
            "weights": {},
            "meta": {
                "task_type": task_type,
                "project_name": t.get("project_name", "").strip(),
                "project_homepage": t.get("project_homepage", "").strip(),
                "project_main_repo": t.get("project_main_repo", "").strip(),
                "source_missing": source_missing,
            },
        }
        tasks.append(task)
    return tasks


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build CyberGym task records from tasks.json"
    )
    parser.add_argument("--root", required=True, help="Path to cybergym data root (contains tasks.json + data/)")
    parser.add_argument("--tasks-out", required=True, help="Output task records JSONL")
    parser.add_argument("--imported-out", required=True, help="Output imported results JSONL (reserved)")
    args = parser.parse_args(argv)

    tasks = build_tasks(args.root)
    os.makedirs(os.path.dirname(os.path.abspath(args.tasks_out)), exist_ok=True)
    with open(args.tasks_out, "w", encoding="utf-8") as f:
        for t in tasks:
            f.write(json.dumps(t, ensure_ascii=False, sort_keys=True) + "\n")
    print(f"Wrote {len(tasks)} CyberGym task records to {args.tasks_out}")

    # Imported runner results: CyberGym's canonical runner is the agent-eval
    # server (PoC verification), not a SARIF-based SAST. We emit nothing for
    # now; the science-team format is reserved for future import.
    os.makedirs(os.path.dirname(os.path.abspath(args.imported_out)), exist_ok=True)
    with open(args.imported_out, "w", encoding="utf-8") as f:
        pass
    print(f"Wrote 0 imported CyberGym result records to {args.imported_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
