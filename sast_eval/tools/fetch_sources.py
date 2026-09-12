"""Materialize source code for bountytasks and CWE-Bench-Java tasks.

Both importers mark tasks ``source_missing`` when the codebase isn't checked
out locally. This tool fetches the source so ``make package`` can build
tarballs for them.

* **bountytasks**: each ``<project>/codebase`` is a git submodule pointing at a
  ``cy-suite/<project>.git`` mirror. We clone it at the task's
  ``vulnerable_commit`` (shallow fetch of that commit). Multiple bounties on
  the same project share one codebase checkout.
* **CWE-Bench-Java**: delegates to the repo's own ``scripts/fetch_one.py``,
  which clones at the buggy commit and applies the buildability patch.

Usage::

    python -m tools.fetch_sources --bountytasks corpus/bountytasks --cwebench corpus/cwe-bench-java
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import sys
from pathlib import Path


def _run(cmd: list[str], cwd: str | None = None) -> int:
    print("  $ " + " ".join(cmd), file=sys.stderr)
    return subprocess.run(cmd, cwd=cwd).returncode


# ── bountytasks ────────────────────────────────────────────────────────────


def fetch_bountytasks(root: Path) -> dict:
    """Clone each cy-suite codebase mirror at its vulnerable commit."""
    root = root.resolve()
    stats = {"fetched": 0, "skipped": 0, "failed": 0}
    seen: set[str] = set()

    pattern = str(root / "*" / "bounties" / "bounty_*" / "bounty_metadata.json")
    import glob

    for mf in sorted(glob.glob(pattern)):
        meta = json.load(open(mf))
        project_dir = Path(mf).parent.parent.parent  # <root>/<project>
        codebase = project_dir / "codebase"
        key = str(codebase)
        if key in seen:
            continue
        seen.add(key)

        # already checked out and non-empty
        if codebase.is_dir() and any(codebase.iterdir()):
            stats["skipped"] += 1
            continue

        # find the submodule url from .gitmodules
        url = _gitmodules_url(root, project_dir.name)
        if not url:
            print(f"  ! no submodule url for {project_dir.name}", file=sys.stderr)
            stats["failed"] += 1
            continue

        commit = meta.get("vulnerable_commit", "")
        if not commit:
            print(f"  ! no vulnerable_commit in {mf}", file=sys.stderr)
            stats["failed"] += 1
            continue

        codebase.parent.mkdir(parents=True, exist_ok=True)
        print(f"  fetching {project_dir.name} @ {commit[:8]}", file=sys.stderr)
        rc = _run(["git", "clone", "--depth", "1", url, str(codebase)])
        if rc != 0:
            stats["failed"] += 1
            continue
        rc = _run(["git", "fetch", "--depth", "1", "origin", commit], cwd=str(codebase))
        if rc != 0:
            stats["failed"] += 1
            continue
        rc = _run(["git", "checkout", commit], cwd=str(codebase))
        if rc != 0:
            stats["failed"] += 1
            continue
        stats["fetched"] += 1

    return stats


def _gitmodules_url(root: Path, project: str) -> str | None:
    gm = root / ".gitmodules"
    if not gm.is_file():
        return None
    import configparser

    cp = configparser.ConfigParser()
    cp.read(gm)
    for s in cp.sections():
        if cp[s].get("path") == f"{project}/codebase":
            return cp[s].get("url")
    return None


# ── CWE-Bench-Java ────────────────────────────────────────────────────────


def fetch_cwebench(root: Path) -> dict:
    """Delegate to the repo's scripts/fetch_one.py for each project slug."""
    root = root.resolve()
    fetch_script = root / "scripts" / "fetch_one.py"
    info_csv = root / "data" / "project_info.csv"
    if not fetch_script.is_file() or not info_csv.is_file():
        print("  ! cwe-bench-java scripts/data not found", file=sys.stderr)
        return {"fetched": 0, "skipped": 0, "failed": 0}

    stats = {"fetched": 0, "skipped": 0, "failed": 0}
    with open(info_csv) as f:
        reader = csv.reader(f)
        next(reader)  # header
        for row in reader:
            if len(row) < 11:
                continue
            project_slug = row[1]
            target = root / "project-sources" / project_slug
            if target.exists():
                stats["skipped"] += 1
                continue
            print(f"  fetching {project_slug}", file=sys.stderr)
            rc = _run([sys.executable, str(fetch_script), project_slug])
            if rc == 0:
                stats["fetched"] += 1
            else:
                stats["failed"] += 1
    return stats


# ── CyberGym ──────────────────────────────────────────────────────────────

CYBERGYM_HF_BASE = "https://huggingface.co/datasets/sunblaze-ucb/cybergym/resolve/main"
# Per-task files we fetch (level1 set: source + description; patch.diff for
# ground-truth vulnerable-file extraction).
CYBERGYM_FILES = ["repo-vul.tar.gz", "patch.diff", "description.txt"]


def fetch_cybergym(root: Path, limit: int | None = None) -> dict:
    """Download per-task files from the HuggingFace dataset.

    ``root`` is the CyberGym data root (containing ``tasks.json``). For each
    task in ``tasks.json``, fetch ``repo-vul.tar.gz``, ``patch.diff``, and
    ``description.txt`` into ``data/<type>/<id>/`` unless already present.

    The full dataset is ~240GB; ``--limit`` caps the number of tasks fetched
    for a quick test run.
    """
    import urllib.request

    root = root.resolve()
    tasks_json = root / "tasks.json"
    if not tasks_json.is_file():
        print("  ! cybergym tasks.json not found", file=sys.stderr)
        return {"fetched": 0, "skipped": 0, "failed": 0}

    tasks = json.loads(tasks_json.read_text())
    stats = {"fetched": 0, "skipped": 0, "failed": 0}

    for i, t in enumerate(tasks):
        if limit and i >= limit:
            break
        tid = t.get("task_id", "")
        parts = tid.split(":", 1)
        if len(parts) != 2:
            continue
        task_type, task_num = parts
        data_dir = root / "data" / task_type / task_num
        data_dir.mkdir(parents=True, exist_ok=True)

        # skip if the big file is already present
        if (data_dir / "repo-vul.tar.gz").is_file():
            stats["skipped"] += 1
            continue

        ok = True
        for fn in CYBERGYM_FILES:
            out = data_dir / fn
            if out.is_file():
                continue
            url = f"{CYBERGYM_HF_BASE}/data/{task_type}/{task_num}/{fn}"
            try:
                urllib.request.urlretrieve(url, out)
            except Exception as e:
                print(f"  ! {tid}: {fn} failed: {e}", file=sys.stderr)
                ok = False
                break
        if ok:
            stats["fetched"] += 1
            print(f"  fetched {tid}", file=sys.stderr)
        else:
            stats["failed"] += 1

    return stats


# ── driver ────────────────────────────────────────────────────────────────


def fetch_sastbench(root: Path) -> dict:
    """Fetch SASTbench Full Track repos by delegating to the repo's setup script.

    SASTbench's Full Track cases reference real-world repos at vulnerable
    commits (``realWorld.repo`` / ``realWorld.vulnerableCommit``). The repo's
    own ``scripts/setup_repos.py`` clones each into ``.repos/<owner_repo>__<sha>/``
    so the adapter can resolve ``files.root`` for packaging.

    Core Track cases are self-contained (``project/`` ships with the repo) and
    need no fetching.
    """
    root = root.resolve()
    setup = root / "scripts" / "setup_repos.py"
    if not setup.is_file():
        print(f"  ! sast-bench setup_repos.py not found at {setup}", file=sys.stderr)
        return {"fetched": 0, "skipped": 0, "failed": 1}

    rc = _run([sys.executable, str(setup)], cwd=str(root))
    # setup_repos.py prints its own per-repo progress; we just summarize.
    return {"fetched": 0 if rc else 1, "skipped": 0, "failed": 1 if rc else 0}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Fetch source code for bountytasks + CWE-Bench-Java + CyberGym + SASTbench")
    ap.add_argument("--bountytasks", help="Path to bountytasks repo root")
    ap.add_argument("--cwebench", help="Path to cwe-bench-java repo root")
    ap.add_argument("--cybergym", help="Path to cybergym data root (contains tasks.json)")
    ap.add_argument("--cybergym-limit", type=int, default=None, help="Cap CyberGym tasks fetched (for testing)")
    ap.add_argument("--sastbench", help="Path to sast-bench repo root")
    args = ap.parse_args(argv)

    if not args.bountytasks and not args.cwebench and not args.cybergym and not args.sastbench:
        ap.error("at least one of --bountytasks / --cwebench / --cybergym / --sastbench is required")

    if args.bountytasks:
        print("=== Fetching bountytasks codebases ===", file=sys.stderr)
        s = fetch_bountytasks(Path(args.bountytasks))
        print(f"bountytasks: fetched={s['fetched']} skipped={s['skipped']} failed={s['failed']}")

    if args.cwebench:
        print("=== Fetching CWE-Bench-Java project-sources ===", file=sys.stderr)
        s = fetch_cwebench(Path(args.cwebench))
        print(f"cwebench: fetched={s['fetched']} skipped={s['skipped']} failed={s['failed']}")

    if args.cybergym:
        print("=== Fetching CyberGym task data from HuggingFace ===", file=sys.stderr)
        s = fetch_cybergym(Path(args.cybergym), limit=args.cybergym_limit)
        print(f"cybergym: fetched={s['fetched']} skipped={s['skipped']} failed={s['failed']}")

    if args.sastbench:
        print("=== Fetching SASTbench Full Track repos ===", file=sys.stderr)
        s = fetch_sastbench(Path(args.sastbench))
        print(f"sastbench: fetched={s['fetched']} skipped={s['skipped']} failed={s['failed']}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
