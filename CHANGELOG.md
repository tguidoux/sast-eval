# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-09-13

### Added

- **Exploit leg (Tier 3 PoC contract).** Tools can now emit a declarative PoC
  spec per finding that the harness runs in a sandbox and judges — the tool
  never self-certifies. The spec declares an `executor` (`http-request`,
  `cli-stdin`, `file-read`, `grpc-call`, `custom-script`), an `invoke` block,
  and a `success` criterion (`response-body-contains`, `exit-code`,
  `file-exists`, `file-contains`, etc.). The harness dispatches to the
  executor, runs it in a `Sandbox`, and applies `judge()` — the trust boundary.
  - `from sast_eval.poc import PoCSpec, run_poc, validate_poc, LocalSandbox,
    REFERENCE_POC` — public API for the exploit leg.
  - `sast-eval validate-poc` and `sast-eval run-poc` CLI commands to validate
    and dry-run PoC specs.
  - Generic Tier 3 oracle (`sast_eval.exploit.oracles.poc_oracle`) registered
    under `"*"` — looks up `<task_id>.poc.json` in the poc dir, runs it, sets
    `exploit_attempted`/`exploit_passed` on each `FindingVerdict`.

- **SARIF contract validation.** `sast_eval.sarif_contract` validates the 4
  required fields per finding (`ruleId`, `message.text`, `locations[].uri`,
  `locations[].startLine`) and the `properties.tags` CWE convention.
  - `from sast_eval import validate_sarif, validate_file, SarifReport`.
  - `sast-eval validate-sarif` CLI command.

- **OWASP Tier 2 canary oracle.** A static taint check from the servlet entry
  point (`doGet`/`doPost`) to the vulnerable sink per CWE — deterministic,
  no-runtime confirmation that tainted input reaches the vulnerable operation.
  Replaces the generic "file is in src tree" heuristic with a real reachability
  check that's still static and fast.

- **`ResultRun.save_poc()`** — programmatic API to write a PoC spec to
  `results/pocs/<tool>/<task_id>.poc.json`. Mirrors `save_sarif`. The
  `exploit()` method injects the poc dir into task records so the generic
  oracle finds the specs.

- **`docs/CONTRACT.md`** — consolidated detect + exploit contract for tool
  authors. Makes the trust boundary explicit: "the tool claims (SARIF) and
  proposes a recipe (PoC); the harness proves (runs + judges)."

- **`examples/llm-sast-e2e/`** — a standalone uv project demonstrating the
  full contract with a toy LLM SAST (regex heuristics emitting SARIF + PoC
  specs). Shows detect scoring (precision, recall) and exploit scoring (the
  tier ladder: static → canary → PoC) for 3 OWASP codebases.

- Test suites for the new contract: `test_sarif_contract.py` (12),
  `test_poc_contract.py` (27), `test_poc_oracle.py` (3), `test_exploit_oracle.py` (6).

### Changed

- `sast_eval.exploit.oracle.validate_task` now runs all tiers in sequence
  (Tier 1 → 2 → 3) and resolves the outcome as the highest tier that ran.
  `_highest_tier` and `_resolve_outcome` pick the verdict per finding.

- `sast_eval.exploit.oracles.__init__` now imports and registers the OWASP
  canary and generic PoC oracles alongside the existing bountytasks/cybergym
  oracles.

### Fixed

- The exploit leg now reliably evaluates across all benchmarks: OWASP via
  the Tier 2 canary, others via the Tier 3 PoC oracle (generic `*` fallback).

## [0.1.5] - 2026-09-12

### Changed

- **The CLI now runs on the programmatic API.** `sast_eval.cli` is a thin
  argparse adapter over `sast_eval.api` (`SastEval` / `ResultRun`): every
  `sast-eval <cmd>` builds a `SastEval` and calls the same method a Python
  user would. One code path, identical behavior, no drift.
  - `cmd_download`/`cmd_build`/`cmd_fetch`/`cmd_package`/`cmd_prepare`/`cmd_all`
    delegate to `SastEval.download/build/fetch/package/prepare`.
  - `cmd_match`/`cmd_exploit`/`cmd_score` delegate to `ResultRun.match/exploit/score`
    via `SastEval.results(tool)`.
  - The dispatch logic (`_run`) moved from `cli.py` to `api.py`, so the API
    no longer imports the CLI — the dependency direction is now `cli → api`.

## [0.1.4] - 2026-09-12

### Added

- **Programmatic Python API** — `from sast_eval import SastEval, Codebase,
  ResultRun` lets you drive the whole pipeline from code instead of the CLI,
  reusing the exact same code paths (so behavior is identical to `sast-eval`).
  ```python
  from sast_eval import SastEval
  sast = SastEval(benchmark="owasp", limit=20)   # same defaults as the CLI
  sast.prepare()                                # download + build + fetch + package
  with sast.results("mytool") as run:
      for cb in sast.codebases():                # iterate per-task tarballs
          tar = cb.download("/tmp/sandbox")      # stream the .tar.gz (64KB chunks)
          run.save_sarif(my_sast(tar), cb.task_id)
      run.match(); run.exploit(); run.score()
  ```
  - `SastEval(benchmark=, limit=, corpus=, tasks=, imported=, results=, reports=,
    codebases_dir=)` — config object mirroring the CLI flags; `prepare()`,
    `build()`, `fetch()`, `package()` call the same `cmd_*` functions the CLI
    uses.
  - `SastEval.codebases()` — iterator over packaged per-task tarballs (reads
    `codebases/MANIFEST.json`), filtered by `benchmark`/`limit`, yielding
    `Codebase` objects with `task_id`, `benchmark`, `bytes`, `file_count`, and
    `ground_truth`.
  - `Codebase.download(dest_dir, extract=False)` — **streams** the tarball to a
    sandbox directory in 64KB chunks (low memory for 200MB tarballs); pass
    `extract=True` to also extract it. Designed for running a SAST tool + agent
    in an external sandbox: download there, scan, ship the SARIF back.
  - `SastEval.results(tool)` — context manager yielding a `ResultRun` with
    `save_sarif(sarif, task_id)` (accepts a dict, JSON string, or `Path`),
    `match()`, `exploit()`, `score()`, and `scorecard_path`.
- `test/test_api.py` — lightweight end-to-end API test (no network; uses a
  prepared OWASP corpus, fake SARIF, throwaway result dirs). Run with
  `make test` or `uv run python test/test_api.py`.

### Changed

- `sast_eval/__init__.py` now exports `SastEval`, `Codebase`, `ResultRun` and
  documents the programmatic API in the module docstring.

## [0.1.3] - 2026-09-12

### Added

- **`sast-eval prepare`** — a single command that does everything required to
  get codebases ready: download missing corpora → build task records
  (`tasks/*.jsonl`) → fetch source trees → package per-task `.tar.gz` tarballs.
  This replaces the previous `build && fetch && package` three-command flow.
  - Defaults to a safe cap of 20 codebases per benchmark so it always finishes
    fast; pass `--all` to remove the cap (slow: CyberGym is ~240GB, SASTbench
    Full Track is 189 real-world repos).
  - `--benchmark` and `--limit` apply to all four steps, so you can prepare a
    subset: `sast-eval prepare --benchmark owasp --limit 5`.
  - `make prepare` (the new default `make` target) wraps it with `BENCHMARK=`,
    `LIMIT=`, and `ALL=1` knobs.

### Changed

- **`sast-eval build` now respects `--benchmark`** — previously `build` always
  ran all five adapters; now `build --benchmark owasp` only builds OWASP. This
  makes `prepare --benchmark X` consistent across all steps.
- **`sast-eval fetch` tolerates `owasp` in `--benchmark`** — OWASP is
  self-contained (already checked out, no fetch step), so `prepare
  --benchmark owasp` no longer errors.

## [0.1.2] - 2026-09-12

### Added

- **`sast-eval fetch` filters** — `--benchmark`, `--tasks-filter`, and `--limit`
  let you clone only the codebases you actually need instead of every repo for
  every benchmark. Previously `fetch` cloned all 120 CWE-Bench repos, all 189
  SASTbench Full Track repos, and CyberGym's ~240GB dataset with no way to cap
  it (only `--cybergym-limit` existed). Now:
  - `--benchmark bountytasks,cwebench` selects benchmarks.
  - `--tasks-filter tasks` only fetches codebases referenced by the built
    `tasks/*.jsonl` records — the fastest path after `sast-eval build`.
  - `--limit 5` caps each benchmark to 5 codebases (applies to all benchmarks,
    not just CyberGym; `--cybergym-limit` is kept as a backwards-compatible alias).
- **Progress counts** — `fetch` now prints `[N/total]` per codebase and a
  `fetched=… skipped=… failed=…` summary per benchmark, so you can see it
  working instead of a silent multi-minute clone.
- **`sast-eval package` filters** — `--benchmark` and `--limit` mirror `fetch`,
  so you can package a subset (e.g. `package --benchmark owasp --limit 10`).
- `fetch_sastbench` is now self-contained — it reads `cases/full/*/case.json`
  directly and clones into `.repos/<owner_repo>__<sha>/` instead of delegating
  to the upstream `scripts/setup_repos.py`, which took no arguments and cloned
  every Full Track repo.

### Changed

- `Makefile` `fetch`/`package` targets accept `BENCHMARK=`, `LIMIT=`, and
  `CYBERGYM_LIMIT=` overrides; `fetch` always passes `--tasks $(TASKS)` so only
  built-task codebases are fetched by default.
- README and QUICKSTART document the new filters with a fast-path example:
  `build → fetch --tasks-filter tasks --limit 5 → package --limit 5`.

## [0.1.1] - 2026-09-12

### Added

- **`sast-eval download`** — new subcommand that clones the benchmark metadata
  repos into `corpus/` (the previously-manual Step 1 of the eval pipeline).
  Supports per-benchmark selection (`--benchmark owasp,bountytasks,cybergym`),
  shallow clones by default (`--full` for full history), `--force` to re-clone,
  and `--cybergym-limit` to cap CyberGym's ~240GB HuggingFace dataset.
- CyberGym download path fetches `tasks.json` + per-task tarballs directly from
  the `sunblaze-ucb/cybergym` HuggingFace dataset (no `huggingface_hub`
  dependency — plain `urllib`).
- `sast-eval all` now starts with `download`, so the full pipeline can run from
  a clean checkout with no manual `git clone`s.

### Changed

- **`sast-eval build` no longer crashes when a benchmark's corpus is missing.**
  It now skips the missing benchmark with a helpful message pointing to
  `sast-eval download --benchmark <name>` and builds the rest. This composes
  with selective `download` — e.g. `download --benchmark sastbench && build`
  builds only SASTbench instead of crashing on the missing OWASP CSV.

## [0.1.0] - 2026-09-11

### Added

- Initial release of `sast-eval`, a unified SAST evaluation harness across five
  vulnerability benchmarks: OWASP BenchmarkJava, bountytasks, CWE-Bench-Java,
  CyberGym, and SASTbench.
- Unified task schema (§2) normalizing all five benchmarks into comparable
  records with CWE, vulnerable files/methods/regions, FP traps, and weights.
- Adapters (end-to-end, this repo owns matching/scoring) for OWASP
  BenchmarkJava and SASTbench.
- Importers (science-team runner is canonical) for bountytasks, CWE-Bench-Java,
  and CyberGym.
- SARIF matcher (§5) classifying findings as TP/FP/FN against ground truth,
  with CWE-class equivalence, method-identity matching, and region-level
  overlap for SASTbench.
- 4-tier exploit-validation oracle (§6) for matched results.
- Scorecard renderer (§7) producing a comparable summary across benchmarks.
- `sast-eval` CLI with `build`, `fetch`, `package`, `match`, `exploit`,
  `score`, and `all` subcommands.
- `exampletool` sample SARIF + `rules.json` for trying the pipeline.
- Trusted-publisher PyPI workflow (GitHub Actions OIDC) and `RELEASING.md`.
- `QUICKSTART.md` runnable end-to-end walkthrough.
