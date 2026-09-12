"""Unified CLI for the sast-eval harness.

Subcommands map to the existing module mains (each accepts ``argv: list[str]``):

    sast-eval prepare     download + build + fetch + package (one command to
                          produce standardized codebases; the usual entry point)
    sast-eval download    download benchmark corpora into corpus/ (Step 1)
    sast-eval build       build all 5 benchmarks' tasks (tasks/*.jsonl)
    sast-eval fetch       fetch source for bountytasks/CWE-Bench/CyberGym/SASTbench
    sast-eval package     build per-task .tar.gz codebases for SAST analysis
    sast-eval match       match SARIF results against ground truth
    sast-eval exploit     run exploit-validation oracles on matched results
    sast-eval score       render the scorecard from matched + exploit results
    sast-eval all         download + build + fetch + package + match + exploit + score

Run ``sast-eval <subcommand> --help`` for per-subcommand options.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Default layout (matches the repo's Makefile defaults).
CORPUS = "corpus"
TASKS = "tasks"
IMPORTED = "imported"
RESULTS = "results"
REPORTS = "reports"
CODEBASES = "codebases"


def _run(module: str, func: str, argv: list[str]) -> int:
    """Import module.func and call it with argv."""
    import importlib

    mod = importlib.import_module(module)
    fn = getattr(mod, func)
    return fn(argv)


def _add_corpus_args(p: argparse.ArgumentParser) -> None:
    """Add --corpus/--tasks/--imported/--results/--reports/--codebases overrides."""
    p.add_argument("--corpus", default=CORPUS, help="Corpus repos root (default: corpus)")
    p.add_argument("--tasks", default=TASKS, help="Tasks dir (default: tasks)")
    p.add_argument("--imported", default=IMPORTED, help="Imported results dir (default: imported)")
    p.add_argument("--results", default=RESULTS, help="Results root (default: results)")
    p.add_argument("--reports", default=REPORTS, help="Reports dir (default: reports)")
    p.add_argument("--codebases", default=CODEBASES, help="Codebases dir (default: codebases)")


def cmd_download(args: argparse.Namespace) -> int:
    argv = ["--corpus", args.corpus]
    if args.benchmark:
        argv += ["--benchmark", args.benchmark]
    if args.full:
        argv += ["--full"]
    if args.force:
        argv += ["--force"]
    if args.cybergym_limit is not None:
        argv += ["--cybergym-limit", str(args.cybergym_limit)]
    return _run("sast_eval.tools.download_corpus", "main", argv)


def _build_one(module: str, func: str, argv: list[str], benchmark: str, corpus_dir: Path) -> int:
    """Run one benchmark's build step, skipping gracefully if its corpus is missing.

    This lets ``sast-eval build`` compose with selective ``sast-eval download``:
    if you only downloaded some benchmarks, build only those and warn about the
    rest instead of crashing on a missing CSV/file.
    """
    if not corpus_dir.is_dir():
        print(f"  skip {benchmark}: {corpus_dir} not present "
              f"(run `sast-eval download --benchmark {benchmark}` to fetch it)", file=sys.stderr)
        return 0
    return _run(module, func, argv)


def cmd_build(args: argparse.Namespace) -> int:
    rc = 0
    Path(args.tasks).mkdir(parents=True, exist_ok=True)
    Path(args.imported).mkdir(parents=True, exist_ok=True)
    selected = None
    if getattr(args, "benchmark", None):
        selected = {b.strip() for b in args.benchmark.split(",") if b.strip()}

    def _want(b: str) -> bool:
        return selected is None or b in selected

    if _want("owasp"):
        rc |= _build_one("sast_eval.adapters.owasp_adapter", "main",
                         ["--root", str(Path(args.corpus) / "BenchmarkJava"), "--out", f"{args.tasks}/owasp.jsonl"],
                         "owasp", Path(args.corpus) / "BenchmarkJava")
    if _want("bountytasks"):
        rc |= _build_one("sast_eval.importers.bountytasks_importer", "main",
                         ["--metadata-root", str(Path(args.corpus) / "bountytasks"),
                          "--tasks-out", f"{args.tasks}/bountytasks.jsonl",
                          "--imported-out", f"{args.imported}/bountytasks.jsonl"],
                         "bountytasks", Path(args.corpus) / "bountytasks")
    if _want("cwebench"):
        rc |= _build_one("sast_eval.importers.cwebench_importer", "main",
                         ["--root", str(Path(args.corpus) / "cwe-bench-java"),
                          "--tasks-out", f"{args.tasks}/cwebench.jsonl",
                          "--imported-out", f"{args.imported}/cwebench.jsonl"],
                         "cwebench", Path(args.corpus) / "cwe-bench-java")
    if _want("cybergym"):
        rc |= _build_one("sast_eval.importers.cybergym_importer", "main",
                         ["--root", str(Path(args.corpus) / "cybergym"),
                          "--tasks-out", f"{args.tasks}/cybergym.jsonl",
                          "--imported-out", f"{args.imported}/cybergym.jsonl"],
                         "cybergym", Path(args.corpus) / "cybergym")
    if _want("sastbench"):
        rc |= _build_one("sast_eval.adapters.sastbench_adapter", "main",
                         ["--root", str(Path(args.corpus) / "sast-bench"), "--out", f"{args.tasks}/sastbench.jsonl"],
                         "sastbench", Path(args.corpus) / "sast-bench")
    return rc


def cmd_fetch(args: argparse.Namespace) -> int:
    argv = [
        "--bountytasks", str(Path(args.corpus) / "bountytasks"),
        "--cwebench", str(Path(args.corpus) / "cwe-bench-java"),
        "--cybergym", str(Path(args.corpus) / "cybergym"),
        "--sastbench", str(Path(args.corpus) / "sast-bench"),
    ]
    if args.benchmark:
        # fetch only handles these four; owasp is self-contained (no fetch step).
        # Silently drop owasp so `prepare --benchmark owasp` doesn't error here.
        fetch_benchmarks = [b.strip() for b in args.benchmark.split(",")
                            if b.strip() in {"bountytasks", "cwebench", "cybergym", "sastbench"}]
        if fetch_benchmarks:
            argv += ["--benchmark", ",".join(fetch_benchmarks)]
    # --tasks-filter (explicit) takes precedence; otherwise use the --tasks dir
    # if it exists and contains jsonl files (so `sast-eval fetch` after `build`
    # automatically fetches only built tasks).
    tasks_filter = getattr(args, "tasks_filter", None) or args.tasks
    if tasks_filter and Path(tasks_filter).is_dir() and any(Path(tasks_filter).glob("*.jsonl")):
        argv += ["--tasks", tasks_filter]
    if args.limit is not None:
        argv += ["--limit", str(args.limit)]
    if args.cybergym_limit is not None:
        argv += ["--cybergym-limit", str(args.cybergym_limit)]
    return _run("sast_eval.tools.fetch_sources", "main", argv)


def cmd_package(args: argparse.Namespace) -> int:
    Path(args.codebases).mkdir(parents=True, exist_ok=True)
    argv = ["--tasks", args.tasks, "--out", args.codebases]
    if args.benchmark:
        argv += ["--benchmark", args.benchmark]
    if args.limit is not None:
        argv += ["--limit", str(args.limit)]
    return _run("sast_eval.tools.package_codebases", "main", argv)


def cmd_match(args: argparse.Namespace) -> int:
    out = f"{args.results}/matched/{args.tool}"
    Path(out).mkdir(parents=True, exist_ok=True)
    argv = ["--tasks", args.tasks, "--results", f"{args.results}/raw/{args.tool}", "--out", out, "--tool", args.tool]
    rules_path = Path(f"tools/{args.tool}/rules.json")
    if rules_path.exists():
        argv += ["--rules", str(rules_path)]
    return _run("sast_eval.matching.matcher", "main", argv)


def cmd_exploit(args: argparse.Namespace) -> int:
    out = f"{args.results}/exploits/{args.tool}"
    Path(out).mkdir(parents=True, exist_ok=True)
    return _run("sast_eval.exploit.oracle", "main",
                ["--matched", f"{args.results}/matched/{args.tool}",
                 "--tasks", args.tasks, "--out", out, "--codebases", args.codebases])


def cmd_score(args: argparse.Namespace) -> int:
    Path(args.reports).mkdir(parents=True, exist_ok=True)
    out = f"{args.reports}/scorecard.md"
    argv = ["--matched", f"{args.results}/matched/{args.tool}",
            "--imported", args.imported, "--tasks", args.tasks, "--out", out]
    exploits_dir = Path(f"{args.results}/exploits")
    if exploits_dir.is_dir():
        argv += ["--exploits", str(exploits_dir)]
    return _run("sast_eval.scoring.metrics", "main", argv)


def cmd_prepare(args: argparse.Namespace) -> int:
    """One command to produce standardized codebases: download (missing) →
    build → fetch → package. ``--benchmark`` and ``--limit`` apply throughout.

    By default caps each benchmark to 20 codebases so the command always
    finishes fast; pass ``--all`` to remove the cap.
    """
    rc = 0
    # Resolve the effective limit: --all wins, then --limit, then the safe default.
    if args.all:
        limit = None
    elif args.limit is not None:
        limit = args.limit
    else:
        limit = 20  # safe default so `prepare` always finishes quickly

    # 1. Download any missing corpora (only what's absent; idempotent).
    print("\n=== [1/4] download — fetch missing benchmark corpora ===")
    dl_args = argparse.Namespace(**vars(args))
    dl_args.benchmark = args.benchmark or "all"
    dl_args.full = args.full
    dl_args.force = False  # prepare never re-downloads; it only fills gaps
    dl_args.cybergym_limit = limit
    rc |= cmd_download(dl_args)

    # 2. Build task records from the corpora.
    print("\n=== [2/4] build — normalize corpora into tasks/*.jsonl ===")
    rc |= cmd_build(args)

    # 3. Fetch source trees for the built tasks (capped by `limit`).
    print("\n=== [3/4] fetch — clone source trees for built tasks ===")
    fetch_args = argparse.Namespace(**vars(args))
    fetch_args.benchmark = args.benchmark
    fetch_args.tasks_filter = args.tasks  # only fetch codebases referenced by built tasks
    fetch_args.limit = limit
    fetch_args.cybergym_limit = limit
    rc |= cmd_fetch(fetch_args)

    # 4. Package per-task .tar.gz codebases (capped by `limit`).
    print("\n=== [4/4] package — build per-task .tar.gz codebases ===")
    pkg_args = argparse.Namespace(**vars(args))
    pkg_args.benchmark = args.benchmark
    pkg_args.limit = limit
    rc |= cmd_package(pkg_args)

    print("\n=== prepare done ===")
    print(f"  tasks/        {sum(1 for _ in Path(args.tasks).glob('*.jsonl'))} benchmark records")
    print(f"  codebases/    {len(list(Path(args.codebases).rglob('*.tar.gz')))} tarballs")
    if not args.all and limit is not None:
        print(f"  (capped at {limit} per benchmark — pass --all for everything)")
    return rc


def cmd_all(args: argparse.Namespace) -> int:
    rc = cmd_download(args)
    rc |= cmd_build(args)
    rc |= cmd_fetch(args)
    rc |= cmd_package(args)
    Path(f"{args.results}/raw/{args.tool}").mkdir(parents=True, exist_ok=True)
    rc |= cmd_match(args)
    rc |= cmd_exploit(args)
    rc |= cmd_score(args)
    return rc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sast-eval",
        description="Unified SAST evaluation harness across 5 vulnerability benchmarks.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # download
    p = sub.add_parser("download", help="Download benchmark corpora into corpus/ (Step 1)")
    _add_corpus_args(p)
    p.add_argument("--benchmark", "-b", default="all",
                   help="Comma-separated benchmarks to download (default: all). "
                        "One or more of: owasp,bountytasks,cwebench,cybergym,sastbench")
    p.add_argument("--full", action="store_true", help="Full git history (default: shallow clone)")
    p.add_argument("--force", action="store_true",
                   help="Remove existing dir and re-download (default: skip if present)")
    p.add_argument("--cybergym-limit", type=int, default=None,
                   help="Cap CyberGym task tarballs downloaded (full dataset is ~240GB)")
    p.set_defaults(func=cmd_download)

    # prepare — the one command that produces standardized codebases
    p = sub.add_parser("prepare", help="Download + build + fetch + package in one command",
                       formatter_class=argparse.RawDescriptionHelpFormatter,
                       epilog="""\
Produces standardized per-task .tar.gz codebases from the benchmark corpora.
Does whatever is required: downloads missing corpora, builds task records,
fetches source trees, and packages tarballs.

By default caps each benchmark to 20 codebases so the command always finishes
fast. Pass --all to remove the cap (fetches every codebase — CyberGym is ~240GB,
SASTbench Full Track is 189 real-world repos).

Examples:
  sast-eval prepare                         # fast: all benchmarks, 20 each
  sast-eval prepare --all                   # everything (slow)
  sast-eval prepare --benchmark owasp        # only OWASP
  sast-eval prepare --benchmark cybergym --limit 5
""")
    _add_corpus_args(p)
    p.add_argument("--benchmark", "-b", default=None,
                   help="Comma-separated benchmarks to prepare "
                        "(owasp,bountytasks,cwebench,cybergym,sastbench). Default: all.")
    p.add_argument("--limit", type=int, default=None,
                   help="Cap codebases per benchmark (default: 20; --all removes the cap).")
    p.add_argument("--all", action="store_true",
                   help="Prepare every codebase (no cap). Slow for CyberGym/SASTbench.")
    p.add_argument("--full", action="store_true",
                   help="Full git history when downloading corpora (default: shallow).")
    p.set_defaults(func=cmd_prepare)

    # build
    p = sub.add_parser("build", help="Build all 5 benchmarks' tasks (tasks/*.jsonl)")
    _add_corpus_args(p)
    p.add_argument("--benchmark", "-b", default=None,
                   help="Comma-separated benchmarks to build "
                        "(owasp,bountytasks,cwebench,cybergym,sastbench). Default: all.")
    p.set_defaults(func=cmd_build)

    # fetch
    p = sub.add_parser("fetch", help="Fetch source for bountytasks/CWE-Bench/CyberGym/SASTbench",
                       formatter_class=argparse.RawDescriptionHelpFormatter,
                       epilog="""\
Examples:
  sast-eval fetch                              # fetch all benchmarks, all tasks
  sast-eval fetch --benchmark bountytasks      # only one benchmark
  sast-eval fetch --tasks-filter tasks         # only codebases for built tasks (fastest)
  sast-eval fetch --limit 5                    # cap each benchmark to 5 codebases
  sast-eval fetch --benchmark cybergym --tasks-filter tasks --limit 5
""")
    _add_corpus_args(p)
    p.add_argument("--benchmark", "-b", default=None,
                   help="Comma-separated benchmarks to fetch "
                        "(bountytasks,cwebench,cybergym,sastbench). Default: all.")
    p.add_argument("--tasks-filter", default=None,
                   help="Tasks dir (tasks/*.jsonl). If set, only fetch codebases "
                        "referenced by the built task records — the fastest option. "
                        "(Defaults to the --tasks dir if not given.)")
    p.add_argument("--limit", type=int, default=None,
                   help="Cap the number of codebases fetched per benchmark (quick test).")
    p.add_argument("--cybergym-limit", type=int, default=None,
                   help="Cap CyberGym tasks fetched from HuggingFace (alias for --limit on cybergym).")
    p.set_defaults(func=cmd_fetch)

    # package
    p = sub.add_parser("package", help="Build per-task .tar.gz codebases for SAST analysis",
                      formatter_class=argparse.RawDescriptionHelpFormatter,
                      epilog="""\
Examples:
  sast-eval package                       # package all built tasks
  sast-eval package --benchmark owasp     # only one benchmark
  sast-eval package --limit 10            # first 10 tasks per benchmark
""")
    _add_corpus_args(p)
    p.add_argument("--benchmark", "-b", default=None,
                   help="Comma-separated benchmarks to package (e.g. owasp,cwebench). Default: all.")
    p.add_argument("--limit", type=int, default=None,
                   help="Cap the number of tasks packaged per benchmark (quick test).")
    p.set_defaults(func=cmd_package)

    # match
    p = sub.add_parser("match", help="Match SARIF results against ground truth")
    _add_corpus_args(p)
    p.add_argument("--tool", required=True, help="Tool name (results/raw/<tool>/)")
    p.set_defaults(func=cmd_match)

    # exploit
    p = sub.add_parser("exploit", help="Run exploit-validation oracles on matched results")
    _add_corpus_args(p)
    p.add_argument("--tool", required=True, help="Tool name (results/matched/<tool>/)")
    p.set_defaults(func=cmd_exploit)

    # score
    p = sub.add_parser("score", help="Render the scorecard from matched + exploit results")
    _add_corpus_args(p)
    p.add_argument("--tool", required=True, help="Tool name (results/matched/<tool>/)")
    p.set_defaults(func=cmd_score)

    # all
    p = sub.add_parser("all", help="download + build + fetch + package + match + exploit + score")
    _add_corpus_args(p)
    p.add_argument("--tool", required=True, help="Tool name")
    p.add_argument("--cybergym-limit", type=int, default=None,
                   help="Cap CyberGym tasks fetched from HuggingFace (empty = all)")
    p.set_defaults(func=cmd_all)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
