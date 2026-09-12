"""Build per-task .tar.gz codebases for SAST analysis (§3.4).

Each task's vulnerable source is packaged into a self-contained tarball under
``codebases/<benchmark>/<task_id>.tar.gz``. The tarball contains exactly the
files a SAST needs to analyze the task — not the whole repo.

Packaging strategy per benchmark:

* **OWASP** (end-to-end adapter, source fully checked out): the vulnerable
  test file plus the shared ``helpers`` package (2056/2740 test files reference
  helper classes, so helpers must be included for cross-file taint resolution).
* **bountytasks** / **CWE-Bench** (importers, source often not checked out):
  the entire ``source_root`` tree if it exists; otherwise the task is skipped
  with a warning (``meta.source_missing``).

The tarball path layout preserves the package structure so a SAST sees a
realistic project layout::

    <task_id>/
    ├── src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00001.java
    └── src/main/java/org/owasp/benchmark/helpers/...

A ``MANIFEST.json`` is written alongside the tarballs recording what was
packaged, skipped, and why.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tarfile
from pathlib import Path
from typing import Iterable

# ── OWASP packaging ──────────────────────────────────────────────────────

OWASP_HELPERS_REL = "src/main/java/org/owasp/benchmark/helpers"
OWASP_TESTCODE_REL = "src/main/java/org/owasp/benchmark/testcode"


def _owasp_files(source_root: Path, vulnerable_files: list[str]) -> list[tuple[Path, str]]:
    """Return (abs_path, arcname) pairs for an OWASP task.

    Includes the vulnerable test file(s) and the entire helpers package.
    """
    pairs: list[tuple[Path, str]] = []
    seen: set[str] = set()

    for vf in vulnerable_files:
        abs_vf = source_root / vf
        if abs_vf.is_file():
            arc = f"{{task}}/{vf}"
            pairs.append((abs_vf, arc))
            seen.add(vf)

    helpers_dir = source_root / OWASP_HELPERS_REL
    if helpers_dir.is_dir():
        for root, _dirs, files in os.walk(helpers_dir):
            for fn in files:
                if not fn.endswith(".java"):
                    continue
                abs_p = Path(root) / fn
                rel = abs_p.relative_to(source_root)
                arc = f"{{task}}/{rel}"
                if str(rel) not in seen:
                    pairs.append((abs_p, arc))

    return pairs


# ── CyberGym packaging (nested repo-vul.tar.gz) ───────────────────────────


def _cybergym_files(source_root: Path) -> list[tuple[Path, str]]:
    """Extract the ``repo-vul.tar.gz`` inside a CyberGym task's data dir and
    return (abs_path, arcname) pairs for the vulnerable source tree.

    The nested tarball contains ``src-vul/`` with the project source plus a
    fuzzer harness and ``build.sh``. We include all source files (C/C++/etc.)
    so a SAST sees the vulnerable program.
    """
    repo_vul = source_root / "repo-vul.tar.gz"
    if not repo_vul.is_file():
        return []
    extract_dir = source_root / ".extracted"
    if not extract_dir.is_dir():
        extract_dir.mkdir(parents=True, exist_ok=True)
        try:
            import tarfile

            with tarfile.open(repo_vul, "r:gz") as tar:
                tar.extractall(extract_dir, filter="data")
        except Exception:
            return []
    # The tarball extracts to ``src-vul/`` at the top level.
    src_vul = extract_dir / "src-vul"
    if not src_vul.is_dir():
        # fall back to the extract dir itself
        src_vul = extract_dir
    return _tree_files(src_vul, SOURCE_EXTS)


# ── Generic packaging (bountytasks, cwebench) ──────────────────────────────


def _tree_files(source_root: Path, exts: set[str] | None) -> list[tuple[Path, str]]:
    """All source files under source_root, preserving relative layout."""
    if not source_root.is_dir():
        return []
    pairs: list[tuple[Path, str]] = []
    for root, _dirs, files in os.walk(source_root):
        # skip VCS / build noise
        parts = Path(root).relative_to(source_root).parts
        if any(p in {".git", "target", "build", ".gradle", "node_modules"} for p in parts):
            continue
        for fn in files:
            if exts and not any(fn.endswith(e) for e in exts):
                continue
            abs_p = Path(root) / fn
            rel = abs_p.relative_to(source_root)
            pairs.append((abs_p, f"{{task}}/{rel}"))
    return pairs


# ── Driver ────────────────────────────────────────────────────────────────

SOURCE_EXTS = {".java", ".py", ".js", ".ts", ".jsx", ".tsx", ".c", ".cc", ".cpp", ".h", ".hpp", ".go", ".rb", ".php", ".kt", ".scala", ".rs", ".cs", ".clj", ".cljs", ".cljc", ".edn", ".swift"}


def package_task(task: dict, out_dir: Path) -> dict:
    """Package one task into a tar.gz. Returns a manifest entry."""
    task_id = task["task_id"]
    benchmark = task["benchmark"]
    source_root = Path(task["source_root"])
    safe_id = task_id.replace("/", "__")
    tar_path = out_dir / benchmark / f"{safe_id}.tar.gz"

    meta = task.get("meta", {})
    entry = {
        "task_id": task_id,
        "benchmark": benchmark,
        "tarball": str(tar_path),
        "status": "ok",
        "file_count": 0,
        "bytes": 0,
        "note": "",
    }

    if meta.get("source_missing") or not source_root.exists():
        entry["status"] = "skipped"
        entry["note"] = "source_missing" if meta.get("source_missing") else "source_root_not_found"
        return entry

    if benchmark == "owasp":
        pairs = _owasp_files(source_root, task["ground_truth"]["vulnerable_files"])
    elif benchmark == "cybergym":
        pairs = _cybergym_files(source_root)
    elif benchmark == "sastbench":
        # SASTbench: package the source tree (Core Track project/ or Full Track
        # .repos/<snapshot>/). Region paths are relative to this root.
        pairs = _tree_files(source_root, SOURCE_EXTS)
    else:
        pairs = _tree_files(source_root, SOURCE_EXTS)

    if not pairs:
        entry["status"] = "empty"
        entry["note"] = "no source files found"
        return entry

    tar_path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tar_path, "w:gz") as tar:
        for abs_p, arc in pairs:
            tar.add(abs_p, arcname=arc.replace("{task}", safe_id))

    entry["file_count"] = len(pairs)
    entry["bytes"] = tar_path.stat().st_size
    return entry


def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Build per-task .tar.gz codebases for SAST analysis")
    ap.add_argument("--tasks", required=True, help="Directory of tasks/*.jsonl")
    ap.add_argument("--out", required=True, help="Output directory for codebases/")
    args = ap.parse_args(argv)

    tasks_dir = Path(args.tasks)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    manifest: list[dict] = []
    counts = {"ok": 0, "skipped": 0, "empty": 0}
    for jl in sorted(tasks_dir.glob("*.jsonl")):
        for line in open(jl):
            line = line.strip()
            if not line:
                continue
            task = json.loads(line)
            e = package_task(task, out_dir)
            manifest.append(e)
            counts[e["status"]] += 1
            if e["status"] != "ok":
                print(f"  skip {e['task_id']}: {e['note']}", file=sys.stderr)

    manifest_path = out_dir / "MANIFEST.json"
    with open(manifest_path, "w") as f:
        json.dump(
            {"codebases": manifest, "summary": {k: counts[k] for k in ("ok", "skipped", "empty")}},
            f,
            indent=2,
        )

    total = sum(counts.values())
    print(f"Packaged {counts['ok']}/{total} tasks -> {out_dir} (skipped {counts['skipped']}, empty {counts['empty']})")
    print(f"Manifest: {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
