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


def _load_task_ids(tasks_dir: str | None) -> set[str] | None:
    """Load task_ids from tasks/*.jsonl. Returns None if no filter (fetch all).

    Each line in tasks/<bench>.jsonl is a task record with a ``task_id`` field
    like ``"owasp/BenchmarkTest00001"`` or ``"bountytasks/InvokeAI/bounty_0"``.
    The fetch functions only need the benchmark-relative part, so callers
    extract what they need from the returned set.
    """
    if not tasks_dir:
        return None
    import glob

    ids: set[str] = set()
    for f in sorted(glob.glob(str(Path(tasks_dir) / "*.jsonl"))):
        for line in Path(f).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                ids.add(json.loads(line)["task_id"])
            except (json.JSONDecodeError, KeyError):
                continue
    return ids or None


def fetch_bountytasks(root: Path, limit: int | None = None, task_ids: set[str] | None = None) -> dict:
    """Clone each cy-suite codebase mirror at its vulnerable commit.

    ``limit`` caps the number of *distinct codebases* fetched (a codebase is
    shared across all bounties of a project, so this is per-project, not
    per-bounty). ``task_ids`` (if given) restricts fetching to codebases
    referenced by those task_ids — pass the set from ``_load_task_ids`` filtered
    to ``bountytasks/...`` entries.
    """
    root = root.resolve()
    stats = {"fetched": 0, "skipped": 0, "failed": 0}
    seen: set[str] = set()

    pattern = str(root / "*" / "bounties" / "bounty_*" / "bounty_metadata.json")
    import glob

    all_metas = sorted(glob.glob(pattern))
    # Pre-filter by task_ids if provided: a bountytasks task_id is
    # "bountytasks/<project>/bounty_<N>", so the project name is field [1].
    wanted_projects: set[str] | None = None
    if task_ids is not None:
        wanted_projects = set()
        for tid in task_ids:
            if tid.startswith("bountytasks/"):
                parts = tid.split("/")
                if len(parts) >= 3:
                    wanted_projects.add(parts[1])
        if not wanted_projects:
            return stats  # no bountytasks tasks in the filter

    # First pass: count how many distinct codebases we'll consider, for progress.
    candidate_projects: list[str] = []
    for mf in all_metas:
        project_dir = Path(mf).parent.parent.parent  # <root>/<project>
        if wanted_projects is not None and project_dir.name not in wanted_projects:
            continue
        if str(project_dir / "codebase") in seen:
            continue
        seen.add(str(project_dir / "codebase"))
        candidate_projects.append(project_dir.name)
    seen.clear()

    total = len(candidate_projects)
    for mf in all_metas:
        meta = json.load(open(mf))
        project_dir = Path(mf).parent.parent.parent  # <root>/<project>
        codebase = project_dir / "codebase"
        key = str(codebase)
        if key in seen:
            continue
        if wanted_projects is not None and project_dir.name not in wanted_projects:
            continue
        seen.add(key)

        # already checked out and non-empty
        if codebase.is_dir() and any(codebase.iterdir()):
            stats["skipped"] += 1
            continue

        # enforce limit (counted against distinct codebases we actually try to fetch)
        if limit is not None and stats["fetched"] + stats["failed"] >= limit:
            break

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
        n = stats["fetched"] + stats["skipped"] + stats["failed"] + 1
        print(f"  [{n}/{total}] fetching {project_dir.name} @ {commit[:8]}", file=sys.stderr)
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


def fetch_cwebench(root: Path, limit: int | None = None, task_ids: set[str] | None = None) -> dict:
    """Delegate to the repo's scripts/fetch_one.py for each project slug.

    ``limit`` caps the number of project-sources fetched. ``task_ids`` (if
    given) restricts to slugs referenced by those task_ids — a cwebench
    task_id is ``"cwebench/<project_slug>"``.
    """
    root = root.resolve()
    fetch_script = root / "scripts" / "fetch_one.py"
    info_csv = root / "data" / "project_info.csv"
    if not fetch_script.is_file() or not info_csv.is_file():
        print("  ! cwe-bench-java scripts/data not found", file=sys.stderr)
        return {"fetched": 0, "skipped": 0, "failed": 0}

    # Build the set of wanted slugs from task_ids if provided.
    wanted_slugs: set[str] | None = None
    if task_ids is not None:
        wanted_slugs = set()
        for tid in task_ids:
            if tid.startswith("cwebench/"):
                wanted_slugs.add(tid.split("/", 1)[1])
        if not wanted_slugs:
            return {"fetched": 0, "skipped": 0, "failed": 0}

    # First pass: collect candidate rows (for total + limit accounting).
    rows: list[list[str]] = []
    with open(info_csv) as f:
        reader = csv.reader(f)
        next(reader)  # header
        for row in reader:
            if len(row) < 11:
                continue
            slug = row[1]
            if wanted_slugs is not None and slug not in wanted_slugs:
                continue
            rows.append(row)

    stats = {"fetched": 0, "skipped": 0, "failed": 0}
    total = len(rows)
    for row in rows:
        project_slug = row[1]
        target = root / "project-sources" / project_slug
        if target.exists():
            stats["skipped"] += 1
            continue
        if limit is not None and stats["fetched"] + stats["failed"] >= limit:
            break
        n = stats["fetched"] + stats["skipped"] + stats["failed"] + 1
        print(f"  [{n}/{total}] fetching {project_slug}", file=sys.stderr)
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


def fetch_cybergym(root: Path, limit: int | None = None, task_ids: set[str] | None = None) -> dict:
    """Download per-task files from the HuggingFace dataset.

    ``root`` is the CyberGym data root (containing ``tasks.json``). For each
    task in ``tasks.json``, fetch ``repo-vul.tar.gz``, ``patch.diff``, and
    ``description.txt`` into ``data/<type>/<id>/`` unless already present.

    The full dataset is ~240GB; ``limit`` caps the number of tasks fetched
    for a quick test run. ``task_ids`` (if given) restricts to those tasks —
    a cybergym task_id is ``"cybergym/<type>:<id>"``.
    """
    import urllib.request

    root = root.resolve()
    tasks_json = root / "tasks.json"
    if not tasks_json.is_file():
        print("  ! cybergym tasks.json not found", file=sys.stderr)
        return {"fetched": 0, "skipped": 0, "failed": 0}

    tasks = json.loads(tasks_json.read_text())
    stats = {"fetched": 0, "skipped": 0, "failed": 0}

    # Filter to wanted task_ids if provided.
    wanted_cybergym_ids: set[str] | None = None
    if task_ids is not None:
        wanted_cybergym_ids = set()
        for tid in task_ids:
            if tid.startswith("cybergym/"):
                wanted_cybergym_ids.add(tid.split("/", 1)[1])

    candidate_tasks = [t for t in tasks if wanted_cybergym_ids is None
                       or t.get("task_id", "") in wanted_cybergym_ids]

    total = len(candidate_tasks)
    for i, t in enumerate(candidate_tasks):
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
            n = stats["fetched"] + stats["skipped"] + stats["failed"]
            print(f"  [{n}/{total}] fetched {tid}", file=sys.stderr)
        else:
            stats["failed"] += 1

    return stats


# ── driver ────────────────────────────────────────────────────────────────


def fetch_sastbench(root: Path, limit: int | None = None, task_ids: set[str] | None = None) -> dict:
    """Fetch SASTbench Full Track repos by cloning each at its vulnerable commit.

    SASTbench's Full Track cases reference real-world repos at vulnerable
    commits (``realWorld.repo`` / ``realWorld.vulnerableCommit``). We clone
    each into ``.repos/<owner_repo>__<sha>/`` so the adapter can resolve
    ``files.root`` for packaging.

    Core Track cases are self-contained (``project/`` ships with the repo) and
    need no fetching.

    ``limit`` caps the number of repos cloned. ``task_ids`` (if given)
    restricts to cases referenced by those task_ids — a sastbench task_id is
    ``"sastbench/<case_id>"``.
    """
    root = root.resolve()
    full_cases_dir = root / "cases" / "full"
    repos_dir = root / ".repos"
    if not full_cases_dir.is_dir():
        print(f"  ! sast-bench cases/full not found at {full_cases_dir}", file=sys.stderr)
        return {"fetched": 0, "skipped": 0, "failed": 1}

    REAL_WORLD_CASE_TYPES = {"real_world_disclosed", "real_world_generic"}

    # Build wanted case-ids from task_ids if provided.
    wanted_case_ids: set[str] | None = None
    if task_ids is not None:
        wanted_case_ids = set()
        for tid in task_ids:
            if tid.startswith("sastbench/"):
                wanted_case_ids.add(tid.split("/", 1)[1])

    cases: list[tuple[Path, dict]] = []
    for case_json in sorted(full_cases_dir.rglob("case.json")):
        try:
            case = json.loads(case_json.read_text(encoding="utf-8"))
        except Exception:
            continue
        if case.get("caseType") not in REAL_WORLD_CASE_TYPES:
            continue
        if wanted_case_ids is not None and case.get("id") not in wanted_case_ids:
            continue
        cases.append((case_json.parent, case))

    stats = {"fetched": 0, "skipped": 0, "failed": 0}
    total = len(cases)
    for case_dir, case in cases:
        rw = case.get("realWorld", {})
        repo = rw.get("repo", "")
        commit = rw.get("vulnerableCommit", "")
        case_id = case.get("id", "?")

        if not repo or not commit:
            print(f"  ! [{case_id}] missing repo or commit, skipping", file=sys.stderr)
            stats["failed"] += 1
            continue

        owner_repo = repo.replace("/", "_")
        dir_name = f"{owner_repo}__{commit[:8]}"
        target = repos_dir / dir_name

        # already checked out?
        if target.is_dir() and any(p.name != ".git" for p in target.iterdir()):
            stats["skipped"] += 1
            continue

        if limit is not None and stats["fetched"] + stats["failed"] >= limit:
            break

        n = stats["fetched"] + stats["skipped"] + stats["failed"] + 1
        print(f"  [{n}/{total}] fetching {case_id}: {repo} @ {commit[:8]}", file=sys.stderr)
        repos_dir.mkdir(parents=True, exist_ok=True)
        rc = _run(["git", "clone", "--depth", "1", f"https://github.com/{repo}.git", str(target)])
        if rc != 0:
            stats["failed"] += 1
            continue
        rc = _run(["git", "fetch", "--depth", "1", "origin", commit], cwd=str(target))
        if rc != 0:
            stats["failed"] += 1
            continue
        rc = _run(["git", "checkout", commit], cwd=str(target))
        if rc != 0:
            stats["failed"] += 1
            continue
        stats["fetched"] += 1

    return stats


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Fetch source code for bountytasks + CWE-Bench-Java + CyberGym + SASTbench",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  # Fetch everything (all benchmarks, all tasks):
  sast-eval fetch

  # Fetch only specific benchmarks:
  sast-eval fetch --benchmark bountytasks,cwebench

  # Fetch only the codebases needed for the tasks you already built
  # (reads tasks/*.jsonl and fetches only those — the fastest option):
  sast-eval fetch --tasks tasks

  # Cap each benchmark to N codebases (quick test):
  sast-eval fetch --limit 5

  # Combine: only cybergym, only the tasks you built, cap at 5:
  sast-eval fetch --benchmark cybergym --tasks tasks --limit 5
""",
    )
    ap.add_argument("--bountytasks", help="Path to bountytasks repo root")
    ap.add_argument("--cwebench", help="Path to cwe-bench-java repo root")
    ap.add_argument("--cybergym", help="Path to cybergym data root (contains tasks.json)")
    ap.add_argument("--sastbench", help="Path to sast-bench repo root")
    ap.add_argument("--benchmark", "-b", default=None,
                    help="Comma-separated benchmarks to fetch (bountytasks,cwebench,cybergym,sastbench). "
                         "Default: all whose --<bench> path is set. Ignored if explicit --<bench> paths are given.")
    ap.add_argument("--tasks", default=None,
                    help="Tasks dir (tasks/*.jsonl). If set, only fetch codebases referenced by "
                         "the built task records — the fastest way to fetch exactly what you need to package.")
    ap.add_argument("--limit", type=int, default=None,
                    help="Cap the number of codebases fetched per benchmark (quick test).")
    ap.add_argument("--cybergym-limit", type=int, default=None,
                    help="Alias for --limit applied to CyberGym only (kept for backwards compat).")
    args = ap.parse_args(argv)

    # Resolve which benchmarks to run.
    explicit_paths = {
        "bountytasks": args.bountytasks,
        "cwebench": args.cwebench,
        "cybergym": args.cybergym,
        "sastbench": args.sastbench,
    }
    any_explicit = any(explicit_paths.values())

    if not any_explicit and not args.benchmark:
        ap.error("no benchmark paths given. Pass --benchmark <names> (and --corpus via the CLI), "
                 "or explicit --bountytasks/--cwebench/--cybergym/--sastbench paths.")

    # If --benchmark is given, treat it as the selection (paths come from the
    # CLI wrapper which sets --<bench> per selected benchmark).
    if args.benchmark:
        selected = {b.strip() for b in args.benchmark.split(",") if b.strip()}
        valid = set(explicit_paths)
        bad = selected - valid
        if bad:
            ap.error(f"unknown benchmark(s): {','.join(bad)}. Valid: {','.join(sorted(valid))}")
    else:
        selected = {b for b, p in explicit_paths.items() if p}

    # Load task_ids filter once (shared across all benchmarks).
    task_ids = _load_task_ids(args.tasks)

    rc = 0
    if "bountytasks" in selected:
        path = args.bountytasks or (Path("corpus") / "bountytasks")
        print("=== Fetching bountytasks codebases ===", file=sys.stderr)
        s = fetch_bountytasks(Path(path), limit=args.limit, task_ids=task_ids)
        print(f"bountytasks: fetched={s['fetched']} skipped={s['skipped']} failed={s['failed']}")
        if s["failed"]:
            rc = 1

    if "cwebench" in selected:
        path = args.cwebench or (Path("corpus") / "cwe-bench-java")
        print("=== Fetching CWE-Bench-Java project-sources ===", file=sys.stderr)
        s = fetch_cwebench(Path(path), limit=args.limit, task_ids=task_ids)
        print(f"cwebench: fetched={s['fetched']} skipped={s['skipped']} failed={s['failed']}")
        if s["failed"]:
            rc = 1

    if "cybergym" in selected:
        path = args.cybergym or (Path("corpus") / "cybergym")
        print("=== Fetching CyberGym task data from HuggingFace ===", file=sys.stderr)
        # --cybergym-limit takes precedence over --limit for cybergym if both set.
        cy_limit = args.cybergym_limit if args.cybergym_limit is not None else args.limit
        s = fetch_cybergym(Path(path), limit=cy_limit, task_ids=task_ids)
        print(f"cybergym: fetched={s['fetched']} skipped={s['skipped']} failed={s['failed']}")
        if s["failed"]:
            rc = 1

    if "sastbench" in selected:
        path = args.sastbench or (Path("corpus") / "sast-bench")
        print("=== Fetching SASTbench Full Track repos ===", file=sys.stderr)
        s = fetch_sastbench(Path(path), limit=args.limit, task_ids=task_ids)
        print(f"sastbench: fetched={s['fetched']} skipped={s['skipped']} failed={s['failed']}")
        if s["failed"]:
            rc = 1

    return rc


if __name__ == "__main__":
    raise SystemExit(main())
