"""Download benchmark corpora into ``corpus/`` (Step 1 of EVAL_SPEC §3).

This is the missing on-ramp: it clones the benchmark *metadata* repos so
``sast-eval build`` can run. The companion ``sast-eval fetch`` then materializes
the *source* trees (bountytasks codebases, CWE-Bench project-sources, CyberGym
per-task tarballs, SASTbench Full Track repos).

Per-benchmark selection via ``--benchmark`` (comma-separated):

    sast-eval download --benchmark owasp,bountytasks
    sast-eval download --benchmark cybergym --cybergym-limit 20
    sast-eval download                       # all five

CyberGym is special: it is a HuggingFace dataset (~240GB full), not a git repo.
We download ``tasks.json`` first, then per-task files (``repo-vul.tar.gz``,
``patch.diff``, ``description.txt``) up to ``--cybergym-limit``. The metadata
repos (OWASP, bountytasks, CWE-Bench, SASTbench) are git clones (shallow by
default — pass ``--full`` for full history).

Idempotent: if a target dir already exists and is non-empty, it is skipped
(use ``--force`` to remove and re-clone).
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

# ── Benchmark metadata-repo URLs ──────────────────────────────────────────
# These are the repos that contain the task metadata (CSVs, case.json, etc.).
# Source *trees* are fetched separately by fetch_sources.py.
REPOS: dict[str, dict] = {
    "owasp": {
        "url": "https://github.com/OWASP-Benchmark/BenchmarkJava.git",
        "dir": "BenchmarkJava",
        "note": "OWASP BenchmarkJava v1.2 (~1GB with history; shallow recommended)",
    },
    "bountytasks": {
        "url": "https://github.com/bountybench/bountytasks.git",
        "dir": "bountytasks",
        "note": "bountytasks metadata (bounty_metadata.json); codebases are submodules",
    },
    "cwebench": {
        "url": "https://github.com/iris-sast/CWE-Bench-Java.git",
        "dir": "cwe-bench-java",
        "note": "CWE-Bench-Java seed data (project_info.csv + fix_info.csv)",
    },
    "sastbench": {
        "url": "https://github.com/Har1sh-k/sast-bench.git",
        "dir": "sast-bench",
        "note": "SASTbench cases + taxonomy (Core Track self-contained)",
    },
}

# CyberGym is a HuggingFace dataset, not a git repo.
CYBERGYM_HF_BASE = "https://huggingface.co/datasets/sunblaze-ucb/cybergym/resolve/main"
CYBERGYM_TASKS_JSON = f"{CYBERGYM_HF_BASE}/tasks.json"
CYBERGYM_PER_TASK_FILES = ["repo-vul.tar.gz", "patch.diff", "description.txt"]

ALL_BENCHMARKS = list(REPOS.keys()) + ["cybergym"]


def _run(cmd: list[str], cwd: str | None = None) -> int:
    print("  $ " + " ".join(cmd), file=sys.stderr)
    return subprocess.run(cmd, cwd=cwd).returncode


def _clone_repo(name: str, info: dict, corpus: Path, shallow: bool, force: bool) -> str:
    """Clone one git metadata repo. Returns 'cloned' | 'skipped' | 'failed'."""
    target = corpus / info["dir"]
    if target.is_dir() and any(target.iterdir()):
        if force:
            print(f"  --force: removing existing {target}", file=sys.stderr)
            shutil.rmtree(target)
        else:
            print(f"  skip {name}: {target} already exists (use --force to re-clone)", file=sys.stderr)
            return "skipped"

    target.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["git", "clone"]
    if shallow:
        cmd += ["--depth", "1"]
    cmd += [info["url"], str(target)]
    rc = _run(cmd)
    if rc != 0:
        return "failed"
    return "cloned"


def _download_cybergym(corpus: Path, limit: int | None, force: bool) -> dict:
    """Download CyberGym tasks.json + per-task data from HuggingFace.

    CyberGym is ~240GB full; ``limit`` caps the number of tasks whose
    ``repo-vul.tar.gz`` we download. ``tasks.json`` (the metadata index) is
    always downloaded so the importer can build all task records — only the
    source tarballs are capped.
    """
    root = corpus / "cybergym"
    root.mkdir(parents=True, exist_ok=True)

    stats = {"cloned": 0, "skipped": 0, "failed": 0}

    # 1. tasks.json (the index — small, always fetch)
    tasks_json = root / "tasks.json"
    if tasks_json.is_file() and not force:
        print("  skip cybergym: tasks.json already present", file=sys.stderr)
        stats["skipped"] += 1
    else:
        print(f"  downloading tasks.json from HuggingFace", file=sys.stderr)
        try:
            urllib.request.urlretrieve(CYBERGYM_TASKS_JSON, tasks_json)
            stats["cloned"] += 1
        except Exception as e:
            print(f"  ! tasks.json failed: {e}", file=sys.stderr)
            stats["failed"] += 1
            return stats

    # 2. per-task source tarballs (capped by --limit)
    try:
        tasks = json.loads(tasks_json.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"  ! could not parse tasks.json: {e}", file=sys.stderr)
        stats["failed"] += 1
        return stats

    fetched_tasks = 0
    for i, t in enumerate(tasks):
        if limit is not None and i >= limit:
            break
        tid = t.get("task_id", "")
        parts = tid.split(":", 1)
        if len(parts) != 2:
            continue
        task_type, task_num = parts
        data_dir = root / "data" / task_type / task_num
        data_dir.mkdir(parents=True, exist_ok=True)

        if (data_dir / "repo-vul.tar.gz").is_file() and not force:
            continue  # already have this task

        ok = True
        for fn in CYBERGYM_PER_TASK_FILES:
            out = data_dir / fn
            if out.is_file() and not force:
                continue
            url = f"{CYBERGYM_HF_BASE}/data/{task_type}/{task_num}/{fn}"
            try:
                urllib.request.urlretrieve(url, out)
            except Exception as e:
                print(f"  ! {tid}: {fn} failed: {e}", file=sys.stderr)
                ok = False
                break
        if ok:
            fetched_tasks += 1
            if fetched_tasks % 10 == 0:
                print(f"  fetched {fetched_tasks} cybergym tasks...", file=sys.stderr)
        else:
            stats["failed"] += 1

    print(f"  cybergym: downloaded {fetched_tasks} task tarballs "
          f"({'all' if limit is None else f'first {limit}'} of {len(tasks)})", file=sys.stderr)
    return stats


def download_benchmarks(
    benchmarks: list[str],
    corpus: Path,
    shallow: bool = True,
    force: bool = False,
    cybergym_limit: int | None = None,
) -> int:
    """Download the selected benchmarks into ``corpus/``. Returns 0 on success."""
    corpus = Path(corpus).resolve()
    corpus.mkdir(parents=True, exist_ok=True)
    rc = 0

    for name in benchmarks:
        if name == "cybergym":
            print("=== Downloading CyberGym from HuggingFace ===", file=sys.stderr)
            s = _download_cybergym(corpus, cybergym_limit, force)
            print(f"cybergym: cloned={s['cloned']} skipped={s['skipped']} failed={s['failed']}")
            if s["failed"]:
                rc = 1
            continue

        info = REPOS.get(name)
        if not info:
            print(f"  ! unknown benchmark: {name}", file=sys.stderr)
            rc = 1
            continue

        print(f"=== Cloning {name} ({info['dir']}) ===", file=sys.stderr)
        print(f"  {info['note']}", file=sys.stderr)
        status = _clone_repo(name, info, corpus, shallow, force)
        print(f"{name}: {status}")
        if status == "failed":
            rc = 1

    return rc


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Download benchmark corpora into corpus/ (Step 1 of the eval pipeline)",
    )
    ap.add_argument(
        "--benchmark", "-b",
        default="all",
        help=f"Comma-separated benchmark names to download (default: all). "
             f"One or more of: {', '.join(ALL_BENCHMARKS)}",
    )
    ap.add_argument("--corpus", default="corpus", help="Corpus root dir (default: corpus)")
    ap.add_argument("--full", action="store_true", help="Full git history (default: shallow clone)")
    ap.add_argument("--force", action="store_true",
                    help="Remove existing dir and re-download (default: skip if present)")
    ap.add_argument("--cybergym-limit", type=int, default=None,
                    help="Cap CyberGym task tarballs downloaded (full dataset is ~240GB)")
    args = ap.parse_args(argv)

    if args.benchmark == "all":
        benchmarks = ALL_BENCHMARKS
    else:
        benchmarks = [b.strip() for b in args.benchmark.split(",") if b.strip()]

    unknown = [b for b in benchmarks if b not in ALL_BENCHMARKS]
    if unknown:
        ap.error(f"unknown benchmark(s): {', '.join(unknown)}. "
                 f"Valid: {', '.join(ALL_BENCHMARKS)}")

    return download_benchmarks(
        benchmarks,
        Path(args.corpus),
        shallow=not args.full,
        force=args.force,
        cybergym_limit=args.cybergym_limit,
    )


if __name__ == "__main__":
    raise SystemExit(main())
