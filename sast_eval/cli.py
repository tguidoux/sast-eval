"""Unified CLI for the sast-eval harness.

Subcommands map to the existing module mains (each accepts ``argv: list[str]``):

    sast-eval build       build all 5 benchmarks' tasks (tasks/*.jsonl)
    sast-eval fetch       fetch source for bountytasks/CWE-Bench/CyberGym/SASTbench
    sast-eval package     build per-task .tar.gz codebases for SAST analysis
    sast-eval match       match SARIF results against ground truth
    sast-eval exploit     run exploit-validation oracles on matched results
    sast-eval score       render the scorecard from matched + exploit results
    sast-eval all         build + fetch + package + match + exploit + score

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


def cmd_build(args: argparse.Namespace) -> int:
    rc = 0
    Path(args.tasks).mkdir(parents=True, exist_ok=True)
    Path(args.imported).mkdir(parents=True, exist_ok=True)
    rc |= _run("sast_eval.adapters.owasp_adapter", "main",
                ["--root", str(Path(args.corpus) / "BenchmarkJava"), "--out", f"{args.tasks}/owasp.jsonl"])
    rc |= _run("sast_eval.importers.bountytasks_importer", "main",
                ["--metadata-root", str(Path(args.corpus) / "bountytasks"),
                 "--tasks-out", f"{args.tasks}/bountytasks.jsonl",
                 "--imported-out", f"{args.imported}/bountytasks.jsonl"])
    rc |= _run("sast_eval.importers.cwebench_importer", "main",
                ["--root", str(Path(args.corpus) / "cwe-bench-java"),
                 "--tasks-out", f"{args.tasks}/cwebench.jsonl",
                 "--imported-out", f"{args.imported}/cwebench.jsonl"])
    rc |= _run("sast_eval.importers.cybergym_importer", "main",
                ["--root", str(Path(args.corpus) / "cybergym"),
                 "--tasks-out", f"{args.tasks}/cybergym.jsonl",
                 "--imported-out", f"{args.imported}/cybergym.jsonl"])
    rc |= _run("sast_eval.adapters.sastbench_adapter", "main",
                ["--root", str(Path(args.corpus) / "sast-bench"), "--out", f"{args.tasks}/sastbench.jsonl"])
    return rc


def cmd_fetch(args: argparse.Namespace) -> int:
    argv = [
        "--bountytasks", str(Path(args.corpus) / "bountytasks"),
        "--cwebench", str(Path(args.corpus) / "cwe-bench-java"),
        "--cybergym", str(Path(args.corpus) / "cybergym"),
        "--sastbench", str(Path(args.corpus) / "sast-bench"),
    ]
    if args.cybergym_limit is not None:
        argv += ["--cybergym-limit", str(args.cybergym_limit)]
    return _run("sast_eval.tools.fetch_sources", "main", argv)


def cmd_package(args: argparse.Namespace) -> int:
    Path(args.codebases).mkdir(parents=True, exist_ok=True)
    return _run("sast_eval.tools.package_codebases", "main",
                ["--tasks", args.tasks, "--out", args.codebases])


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


def cmd_all(args: argparse.Namespace) -> int:
    rc = cmd_build(args)
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

    # build
    p = sub.add_parser("build", help="Build all 5 benchmarks' tasks (tasks/*.jsonl)")
    _add_corpus_args(p)
    p.set_defaults(func=cmd_build)

    # fetch
    p = sub.add_parser("fetch", help="Fetch source for bountytasks/CWE-Bench/CyberGym/SASTbench")
    _add_corpus_args(p)
    p.add_argument("--cybergym-limit", type=int, default=None,
                   help="Cap CyberGym tasks fetched from HuggingFace (empty = all)")
    p.set_defaults(func=cmd_fetch)

    # package
    p = sub.add_parser("package", help="Build per-task .tar.gz codebases for SAST analysis")
    _add_corpus_args(p)
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
    p = sub.add_parser("all", help="build + fetch + package + match + exploit + score")
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
