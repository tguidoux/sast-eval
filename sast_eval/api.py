"""Programmatic API for the sast-eval harness — the single engine.

The CLI (``sast_eval.cli``) is a thin argparse adapter over this module, so
both ``sast-eval <cmd>`` and ``SastEval.<method>`` run the exact same code.
Use this when you want to drive the harness from Python — e.g. running a
SAST tool over each codebase in a sandbox and collecting SARIF, then
matching/scoring programmatically.

    from sast_eval import SastEval

    sast = SastEval(benchmark="owasp", limit=20)

    sast.prepare()                       # download → build → fetch → package

    with sast.results("mytool") as run:
        for cb in sast.codebases():
            tar_path = cb.download("/tmp/sandbox")     # streamed .tar.gz
            sarif = my_sast_tool(tar_path)             # your code here
            run.save_sarif(sarif, cb.task_id)

        run.match()
        run.exploit()
        run.score()
        print(run.scorecard_path)

All path/benchmark/limit defaults match the CLI (``corpus/``, ``tasks/``,
``results/``, ``codebases/``, …). Override any of them in the constructor.
"""
from __future__ import annotations

import argparse
import importlib
import json
import shutil
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

__all__ = ["SastEval", "Codebase", "ResultRun"]

# Default layout (matches the repo's Makefile defaults; mirrored in cli.py).
CORPUS = "corpus"
TASKS = "tasks"
IMPORTED = "imported"
RESULTS = "results"
REPORTS = "reports"
CODEBASES = "codebases"

# Benchmarks that have a fetch step (OWASP is self-contained — already checked
# out in the corpus, no source to clone).
_FETCH_BENCHMARKS = {"bountytasks", "cwebench", "cybergym", "sastbench"}


def _run(module: str, func: str, argv: list[str]) -> int:
    """Import ``module.func`` and call it with ``argv``. Single dispatch point."""
    mod = importlib.import_module(module)
    fn = getattr(mod, func)
    return fn(argv)


class SastEval:
    """Configuration object holding the same defaults as the CLI.

    Parameters mirror the CLI flags. ``benchmark`` is a comma-separated string
    (``"owasp"``, ``"owasp,cwebench"``) or ``None`` for all. ``limit`` caps each
    benchmark; ``None`` means no cap.
    """

    def __init__(
        self,
        *,
        benchmark: str | None = None,
        limit: int | None = None,
        corpus: str = CORPUS,
        tasks: str = TASKS,
        imported: str = IMPORTED,
        results: str = RESULTS,
        reports: str = REPORTS,
        codebases_dir: str = CODEBASES,
    ) -> None:
        self.benchmark = benchmark
        self.limit = limit
        self.corpus = corpus
        self.tasks = tasks
        self.imported = imported
        self.results_dir = results
        self.reports = reports
        self.codebases_dir = codebases_dir

    # ── download ────────────────────────────────────────────────────────

    def download(
        self,
        *,
        full: bool = False,
        force: bool = False,
        cybergym_limit: int | None = None,
    ) -> int:
        """Download benchmark corpora into ``corpus/``. Equivalent to
        ``sast-eval download``. ``benchmark`` defaults to ``"all"`` here.
        """
        argv = ["--corpus", self.corpus]
        argv += ["--benchmark", self.benchmark or "all"]
        if full:
            argv += ["--full"]
        if force:
            argv += ["--force"]
        if cybergym_limit is not None:
            argv += ["--cybergym-limit", str(cybergym_limit)]
        return _run("sast_eval.tools.download_corpus", "main", argv)

    # ── build ───────────────────────────────────────────────────────────

    def build(self) -> int:
        """Build task records (``tasks/*.jsonl``). Equivalent to ``sast-eval build``."""
        Path(self.tasks).mkdir(parents=True, exist_ok=True)
        Path(self.imported).mkdir(parents=True, exist_ok=True)
        selected = self._selected_benchmarks()
        rc = 0
        rc |= self._build_one(
            "sast_eval.adapters.owasp_adapter", "main",
            ["--root", str(Path(self.corpus) / "BenchmarkJava"),
             "--out", f"{self.tasks}/owasp.jsonl"],
            "owasp", Path(self.corpus) / "BenchmarkJava", selected,
        )
        rc |= self._build_one(
            "sast_eval.importers.bountytasks_importer", "main",
            ["--metadata-root", str(Path(self.corpus) / "bountytasks"),
             "--tasks-out", f"{self.tasks}/bountytasks.jsonl",
             "--imported-out", f"{self.imported}/bountytasks.jsonl"],
            "bountytasks", Path(self.corpus) / "bountytasks", selected,
        )
        rc |= self._build_one(
            "sast_eval.importers.cwebench_importer", "main",
            ["--root", str(Path(self.corpus) / "cwe-bench-java"),
             "--tasks-out", f"{self.tasks}/cwebench.jsonl",
             "--imported-out", f"{self.imported}/cwebench.jsonl"],
            "cwebench", Path(self.corpus) / "cwe-bench-java", selected,
        )
        rc |= self._build_one(
            "sast_eval.importers.cybergym_importer", "main",
            ["--root", str(Path(self.corpus) / "cybergym"),
             "--tasks-out", f"{self.tasks}/cybergym.jsonl",
             "--imported-out", f"{self.imported}/cybergym.jsonl"],
            "cybergym", Path(self.corpus) / "cybergym", selected,
        )
        rc |= self._build_one(
            "sast_eval.adapters.sastbench_adapter", "main",
            ["--root", str(Path(self.corpus) / "sast-bench"),
             "--out", f"{self.tasks}/sastbench.jsonl"],
            "sastbench", Path(self.corpus) / "sast-bench", selected,
        )
        return rc

    def _build_one(
        self, module: str, func: str, argv: list[str], benchmark: str,
        corpus_dir: Path, selected: set[str] | None,
    ) -> int:
        """Run one benchmark's build step, skipping gracefully if its corpus
        is missing or not selected. Lets ``build`` compose with selective
        ``download``."""
        if selected is not None and benchmark not in selected:
            return 0
        if not corpus_dir.is_dir():
            print(f"  skip {benchmark}: {corpus_dir} not present "
                  f"(run `sast-eval download --benchmark {benchmark}` to fetch it)",
                  file=sys.stderr)
            return 0
        return _run(module, func, argv)

    # ── fetch ───────────────────────────────────────────────────────────

    def fetch(
        self,
        *,
        tasks_filter: str | None = None,
        cybergym_limit: int | None = None,
    ) -> int:
        """Fetch source trees. Equivalent to ``sast-eval fetch``."""
        argv = [
            "--bountytasks", str(Path(self.corpus) / "bountytasks"),
            "--cwebench", str(Path(self.corpus) / "cwe-bench-java"),
            "--cybergym", str(Path(self.corpus) / "cybergym"),
            "--sastbench", str(Path(self.corpus) / "sast-bench"),
        ]
        if self.benchmark:
            fetch_benchmarks = [b.strip() for b in self.benchmark.split(",")
                               if b.strip() in _FETCH_BENCHMARKS]
            if fetch_benchmarks:
                argv += ["--benchmark", ",".join(fetch_benchmarks)]
        tf = tasks_filter or self.tasks
        if tf and Path(tf).is_dir() and any(Path(tf).glob("*.jsonl")):
            argv += ["--tasks", tf]
        if self.limit is not None:
            argv += ["--limit", str(self.limit)]
        cl = cybergym_limit if cybergym_limit is not None else self.limit
        if cl is not None:
            argv += ["--cybergym-limit", str(cl)]
        return _run("sast_eval.tools.fetch_sources", "main", argv)

    # ── package ─────────────────────────────────────────────────────────

    def package(self) -> int:
        """Package per-task ``.tar.gz`` codebases. Equivalent to ``sast-eval package``."""
        Path(self.codebases_dir).mkdir(parents=True, exist_ok=True)
        argv = ["--tasks", self.tasks, "--out", self.codebases_dir]
        if self.benchmark:
            argv += ["--benchmark", self.benchmark]
        if self.limit is not None:
            argv += ["--limit", str(self.limit)]
        return _run("sast_eval.tools.package_codebases", "main", argv)

    # ── prepare ──────────────────────────────────────────────────────────

    def prepare(self, *, full: bool = False, all_: bool = False) -> int:
        """Run download → build → fetch → package (idempotent; skips done work).

        Equivalent to ``sast-eval prepare``. By default caps each benchmark to
        20 codebases so it always finishes fast; pass ``all_=True`` to remove
        the cap.
        """
        rc = 0
        if all_:
            limit = None
        else:
            limit = self.limit if self.limit is not None else 20

        print("\n=== [1/4] download — fetch missing benchmark corpora ===")
        rc |= self.download(full=full, force=False, cybergym_limit=limit)

        print("\n=== [2/4] build — normalize corpora into tasks/*.jsonl ===")
        rc |= self.build()

        print("\n=== [3/4] fetch — clone source trees for built tasks ===")
        # Temporarily apply the resolved limit + tasks_filter for this step.
        saved_limit, self.limit = self.limit, limit
        try:
            rc |= self.fetch(tasks_filter=self.tasks, cybergym_limit=limit)
        finally:
            self.limit = saved_limit

        print("\n=== [4/4] package — build per-task .tar.gz codebases ===")
        saved_limit, self.limit = self.limit, limit
        try:
            rc |= self.package()
        finally:
            self.limit = saved_limit

        print("\n=== prepare done ===")
        print(f"  tasks/        {sum(1 for _ in Path(self.tasks).glob('*.jsonl'))} benchmark records")
        print(f"  codebases/    {len(list(Path(self.codebases_dir).rglob('*.tar.gz')))} tarballs")
        if not all_ and limit is not None:
            print(f"  (capped at {limit} per benchmark — pass --all for everything)")
        return rc

    # ── codebase iteration ───────────────────────────────────────────────

    def codebases(self) -> Iterator["Codebase"]:
        """Yield :class:`Codebase` for every packaged tarball, filtered by
        ``benchmark``/``limit``.

        Reads ``codebases/MANIFEST.json`` (written by :meth:`package`). Each
        yielded ``Codebase`` carries the full ground-truth task record and a
        streaming :meth:`~Codebase.download`.
        """
        manifest_path = Path(self.codebases_dir) / "MANIFEST.json"
        if not manifest_path.is_file():
            raise FileNotFoundError(
                f"{manifest_path} not found — run `sast.prepare()` or "
                f"`sast-eval prepare` first to package codebases."
            )
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        selected = self._selected_benchmarks()
        per_bench_count: dict[str, int] = {}
        tasks_by_id = self._load_tasks()

        for entry in manifest.get("codebases", []):
            bench = entry["benchmark"]
            if selected is not None and bench not in selected:
                continue
            if entry.get("status") != "ok":
                continue
            if self.limit is not None and per_bench_count.get(bench, 0) >= self.limit:
                continue
            per_bench_count[bench] = per_bench_count.get(bench, 0) + 1
            task = tasks_by_id.get(entry["task_id"], {})
            yield Codebase(entry, task, self)

    def _selected_benchmarks(self) -> set[str] | None:
        if not self.benchmark:
            return None
        return {b.strip() for b in self.benchmark.split(",") if b.strip()}

    def _load_tasks(self) -> dict[str, dict]:
        tasks: dict[str, dict] = {}
        tasks_dir = Path(self.tasks)
        if not tasks_dir.is_dir():
            return tasks
        for p in sorted(tasks_dir.glob("*.jsonl")):
            with open(p, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    t = json.loads(line)
                    tasks[t["task_id"]] = t
        return tasks

    # ── results / scoring ────────────────────────────────────────────────

    @contextmanager
    def results(self, tool: str) -> Iterator["ResultRun"]:
        """Context manager for collecting SARIF for ``tool`` and running the
        match → exploit → score pipeline.

        Creates ``results/raw/<tool>/`` up front. Call :meth:`ResultRun.save_sarif`
        inside the block, then :meth:`ResultRun.match` / :meth:`ResultRun.exploit`
        / :meth:`ResultRun.score` (each optional).
        """
        run = ResultRun(tool, self)
        try:
            yield run
        finally:
            pass


class Codebase:
    """One packaged task: a ``.tar.gz`` tarball plus its ground-truth record.

    Created by :meth:`SastEval.codebases`; not instantiated directly.
    """

    def __init__(self, manifest_entry: dict, task: dict, owner: SastEval) -> None:
        self._entry = manifest_entry
        self.task = task
        self._owner = owner

    @property
    def task_id(self) -> str:
        return self._entry["task_id"]

    @property
    def benchmark(self) -> str:
        return self._entry["benchmark"]

    @property
    def tarball_path(self) -> Path:
        return Path(self._entry["tarball"])

    @property
    def bytes(self) -> int:
        return self._entry.get("bytes", 0)

    @property
    def file_count(self) -> int:
        return self._entry.get("file_count", 0)

    @property
    def status(self) -> str:
        return self._entry.get("status", "ok")

    @property
    def ground_truth(self) -> dict:
        return self.task.get("ground_truth", {})

    @property
    def source_root(self) -> str:
        return self.task.get("source_root", "")

    def download(self, dest_dir: str | Path, *, extract: bool = False) -> Path:
        """Stream the tarball to ``dest_dir`` (chunked, low memory).

        By default writes ``dest_dir/<task_id with /→__>.tar.gz`` and returns
        that path — the raw ``.tar.gz``, ready to hand to a sandbox/agent. Pass
        ``extract=True`` to also extract to ``dest_dir/<task_id>/`` and return
        the extracted directory path instead.
        """
        dest_dir = Path(dest_dir)
        dest_dir.mkdir(parents=True, exist_ok=True)
        safe_id = self.task_id.replace("/", "__")
        dest_tar = dest_dir / f"{safe_id}.tar.gz"

        src = self.tarball_path
        if not src.is_file():
            raise FileNotFoundError(f"tarball not found: {src}")

        # Stream in 64KB chunks so a 200MB tarball never loads fully into memory.
        with open(src, "rb") as f_in, open(dest_tar, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out, length=64 * 1024)

        if not extract:
            return dest_tar

        extract_dir = dest_dir / safe_id
        extract_dir.mkdir(parents=True, exist_ok=True)
        import tarfile

        with tarfile.open(dest_tar, "r:gz") as tar:
            tar.extractall(extract_dir, filter="data")
        return extract_dir

    def __repr__(self) -> str:
        return f"Codebase(task_id={self.task_id!r}, benchmark={self.benchmark!r}, bytes={self.bytes})"


class ResultRun:
    """Scoped handle for one tool's results, created by :meth:`SastEval.results`.

    Collect SARIF with :meth:`save_sarif`, then run :meth:`match`, :meth:`exploit`,
    :meth:`score` (each optional, in that order).
    """

    def __init__(self, tool: str, owner: SastEval) -> None:
        self.tool = tool
        self._owner = owner
        self.raw_dir = Path(owner.results_dir) / "raw" / tool
        self.matched_dir = Path(owner.results_dir) / "matched" / tool
        self.exploits_dir = Path(owner.results_dir) / "exploits" / tool
        self.raw_dir.mkdir(parents=True, exist_ok=True)

    def _sarif_name(self, task_id: str) -> str:
        return task_id.replace("/", "__") + ".sarif"

    def save_sarif(self, sarif: dict | str | Path, task_id: str) -> Path:
        """Save SARIF for ``task_id`` to ``results/raw/<tool>/<task_id>.sarif``.

        Accepts a SARIF ``dict``, a JSON string, or a path to an existing SARIF
        file (copied, streamed). Returns the written path.
        """
        out = self.raw_dir / self._sarif_name(task_id)
        if isinstance(sarif, dict):
            with open(out, "w", encoding="utf-8") as f:
                json.dump(sarif, f, ensure_ascii=False, indent=2)
        elif isinstance(sarif, str) and not sarif.strip().startswith("{"):
            # Treat as a file path.
            src = Path(sarif)
            if not src.is_file():
                raise FileNotFoundError(f"SARIF file not found: {src}")
            with open(src, "rb") as f_in, open(out, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out, length=64 * 1024)
        elif isinstance(sarif, str):
            # JSON string.
            with open(out, "w", encoding="utf-8") as f:
                f.write(sarif)
        elif isinstance(sarif, Path):
            src = sarif
            if not src.is_file():
                raise FileNotFoundError(f"SARIF file not found: {src}")
            with open(src, "rb") as f_in, open(out, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out, length=64 * 1024)
        else:
            raise TypeError(f"sarif must be dict | str | Path, got {type(sarif).__name__}")
        return out

    def match(self) -> Path:
        """Match saved SARIF against ground truth → ``results/matched/<tool>/``."""
        self.matched_dir.mkdir(parents=True, exist_ok=True)
        argv = [
            "--tasks", self._owner.tasks,
            "--results", str(self.raw_dir),
            "--out", str(self.matched_dir),
            "--tool", self.tool,
        ]
        rules_path = Path(f"tools/{self.tool}/rules.json")
        if rules_path.exists():
            argv += ["--rules", str(rules_path)]
        _run("sast_eval.matching.matcher", "main", argv)
        return self.matched_dir

    def exploit(self) -> Path:
        """Run exploit-validation oracles on matched results → ``results/exploits/<tool>/``."""
        self.exploits_dir.mkdir(parents=True, exist_ok=True)
        _run("sast_eval.exploit.oracle", "main", [
            "--matched", str(self.matched_dir),
            "--tasks", self._owner.tasks,
            "--out", str(self.exploits_dir),
            "--codebases", self._owner.codebases_dir,
        ])
        return self.exploits_dir

    def score(self) -> Path:
        """Render the scorecard → ``reports/scorecard.md``. Returns its path."""
        Path(self._owner.reports).mkdir(parents=True, exist_ok=True)
        out = f"{self._owner.reports}/scorecard.md"
        argv = [
            "--matched", str(self.matched_dir),
            "--imported", self._owner.imported,
            "--tasks", self._owner.tasks,
            "--out", out,
        ]
        exploits_root = Path(self._owner.results_dir) / "exploits"
        if exploits_root.is_dir():
            argv += ["--exploits", str(exploits_root)]
        _run("sast_eval.scoring.metrics", "main", argv)
        self.scorecard_path = Path(out)
        return self.scorecard_path

    scorecard_path: Path
