"""Unified CLI for the sast-eval harness.

Thin argparse adapter over :mod:`sast_eval.api` — the CLI and the programmatic
API run the exact same code, so behavior is identical.

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

from sast_eval.api import SastEval, ResultRun

# Default layout (mirrors sast_eval.api).
CORPUS = "corpus"
TASKS = "tasks"
IMPORTED = "imported"
RESULTS = "results"
REPORTS = "reports"
CODEBASES = "codebases"


def _add_corpus_args(p: argparse.ArgumentParser) -> None:
    """Add --corpus/--tasks/--imported/--results/--reports/--codebases overrides."""
    p.add_argument("--corpus", default=CORPUS, help="Corpus repos root (default: corpus)")
    p.add_argument("--tasks", default=TASKS, help="Tasks dir (default: tasks)")
    p.add_argument("--imported", default=IMPORTED, help="Imported results dir (default: imported)")
    p.add_argument("--results", default=RESULTS, help="Results root (default: results)")
    p.add_argument("--reports", default=REPORTS, help="Reports dir (default: reports)")
    p.add_argument("--codebases", default=CODEBASES, help="Codebases dir (default: codebases)")


def _sast_from_args(args: argparse.Namespace, *, limit: int | None = None) -> SastEval:
    """Build a SastEval from the shared corpus args."""
    return SastEval(
        benchmark=getattr(args, "benchmark", None),
        limit=limit if limit is not None else getattr(args, "limit", None),
        corpus=args.corpus,
        tasks=args.tasks,
        imported=args.imported,
        results=args.results,
        reports=args.reports,
        codebases_dir=args.codebases,
    )


def cmd_download(args: argparse.Namespace) -> int:
    sast = _sast_from_args(args)
    return sast.download(
        full=args.full,
        force=args.force,
        cybergym_limit=args.cybergym_limit,
    )


def cmd_build(args: argparse.Namespace) -> int:
    return _sast_from_args(args).build()


def cmd_fetch(args: argparse.Namespace) -> int:
    sast = _sast_from_args(args)
    return sast.fetch(
        tasks_filter=getattr(args, "tasks_filter", None),
        cybergym_limit=getattr(args, "cybergym_limit", None),
    )


def cmd_package(args: argparse.Namespace) -> int:
    return _sast_from_args(args).package()


def cmd_match(args: argparse.Namespace) -> int:
    sast = _sast_from_args(args)
    with sast.results(args.tool) as run:
        run.match()
    return 0


def cmd_exploit(args: argparse.Namespace) -> int:
    sast = _sast_from_args(args)
    with sast.results(args.tool) as run:
        run.matched_dir.mkdir(parents=True, exist_ok=True)
        run.exploit()
    return 0


def cmd_score(args: argparse.Namespace) -> int:
    sast = _sast_from_args(args)
    with sast.results(args.tool) as run:
        run.matched_dir.mkdir(parents=True, exist_ok=True)
        run.score()
    return 0


def cmd_prepare(args: argparse.Namespace) -> int:
    """One command to produce standardized codebases: download (missing) →
    build → fetch → package. ``--benchmark`` and ``--limit`` apply throughout.

    By default caps each benchmark to 20 codebases so the command always
    finishes fast; pass ``--all`` to remove the cap.
    """
    if args.all:
        limit = None
    elif args.limit is not None:
        limit = args.limit
    else:
        limit = 20  # safe default so `prepare` always finishes quickly
    sast = _sast_from_args(args, limit=limit)
    return sast.prepare(full=args.full, all_=args.all)


def cmd_all(args: argparse.Namespace) -> int:
    sast = _sast_from_args(args)
    rc = sast.download(cybergym_limit=getattr(args, "cybergym_limit", None))
    rc |= sast.build()
    rc |= sast.fetch(cybergym_limit=getattr(args, "cybergym_limit", None))
    rc |= sast.package()
    with sast.results(args.tool) as run:
        run.match()
        run.exploit()
        run.score()
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
