# sast-eval

A unified SAST evaluation harness over five benchmarks, with a single
comparable methodology. See `EVAL_SPEC.md` for the full specification.

## Install

```bash
# From source (this repo)
uv sync            # or: pip install -e .

# From PyPI (when published)
pip install sast-eval
```

This installs a `sast-eval` CLI. The benchmark corpora are **not** bundled —
clone them separately and symlink into `corpus/` (see *Usage* below).

| Benchmark | Connector | Ground-truth granularity | Owner |
|---|---|---|---|
| [bountytasks](../bountytasks) | `sast_eval/importers/bountytasks_importer.py` (importer) | file-level (`patch` dict) | science team (canonical runner) |
| [OWASP BenchmarkJava v1.2](../BenchmarkJava) | `sast_eval/adapters/owasp_adapter.py` (adapter) | file-level + FP traps (`real=false` rows) | **this repo** (end-to-end) |
| [CWE-Bench-Java](../cwe-bench-java) | `sast_eval/importers/cwebench_importer.py` (importer) | method-level (`fix_info.csv`) | science team (canonical runner) |
| [CyberGym](../cybergym) | `sast_eval/importers/cybergym_importer.py` (importer) | file-level (`patch.diff`) | science team (agent-eval runner) |
| [SASTbench](../sast-bench) | `sast_eval/adapters/sastbench_adapter.py` (adapter) | region-level (`vulnerable_regions` + capability-safe FP traps) | **this repo** (end-to-end) |

Per `EVAL_SPEC.md` §0: this repo does **not** reimplement bountytasks,
CWE-Bench, or CyberGym. Their runners stay canonical; this repo only *imports*
their results. The end-to-end adapters are OWASP and SASTbench (self-contained
ground truth we score ourselves).

## Layout

```
sast-eval/
├── EVAL_SPEC.md
├── PROVENANCE.md               harness version, corpus hashes, metric defs
├── pyproject.toml              installable package; `sast-eval` console script
├── Makefile                    thin wrapper over the `sast-eval` CLI
├── corpus/                     symlinked benchmark repos (NOT committed)
│   ├── bountytasks/
│   ├── BenchmarkJava/
│   ├── cwe-bench-java/
│   ├── cybergym/               tasks.json + data/<type>/<id>/ (HF dataset)
│   └── sast-bench/             cases/{core,full}/<type>/<id>/case.json
├── sast_eval/                  the installable Python package
│   ├── adapters/
│   │   ├── common.py           CWE normalization (§2.1), bounty-value parsing
│   │   ├── owasp_adapter.py    end-to-end adapter (§3.2)
│   │   └── sastbench_adapter.py end-to-end adapter (region-level ground truth)
│   ├── importers/
│   │   ├── FORMATS.md          science-team runner output inventory (§12.1)
│   │   ├── bountytasks_importer.py
│   │   ├── cwebench_importer.py
│   │   └── cybergym_importer.py
│   ├── matching/
│   │   ├── cwe_map.json        CWE equivalence classes (§2.2)  [package data]
│   │   └── matcher.py          TP/FP/FN classification (§5)
│   ├── exploit/
│   │   ├── oracle.py           4-tier exploit-validation oracle (§10)
│   │   └── oracles/            bespoke per-benchmark oracle adapters
│   ├── scoring/
│   │   └── metrics.py          headline + per-CWE + benchmark-specific (§6)
│   ├── tools/
│   │   ├── fetch_sources.py    clone/checkout source for packaging
│   │   └── package_codebases.py build per-task .tar.gz
│   └── cli.py                  unified `sast-eval` CLI (build/fetch/package/match/exploit/score/all)
├── tools/<tool>/rules.json     ruleId → CWE map for the SAST tool (user data)
├── tasks/                      normalized task records (JSONL, §2)
├── imported/                   science-team results in unified format
├── results/raw/<tool>/         SARIF per task (OWASP + delegated runs)
├── results/matched/<tool>/     TP/FP/FN per task
├── results/exploits/<tool>/    exploit-validation verdicts per task (§10)
└── reports/
    ├── scorecard.md
    └── equivalence_report.md   (§12.3, pending science-team sign-off)
```

## Pipeline

```
benchmark repos ──adapters/importers──▶ tasks/*.jsonl
                                            │
              OWASP + SASTbench + delegated runs ──your SAST (SARIF)──▶ results/raw/<tool>/
                                            │
                             matching/matcher.py ◀── cwe_map.json
                                           │
                                    results/matched/<tool>/
                                           │
                             exploit/oracle.py (§10 — 4-tier oracle)
                                           │
                                    results/exploits/<tool>/
                                           │
                       scoring/metrics.py + imported/*.jsonl ──▶ reports/scorecard.md
```

## Usage

The `sast-eval` CLI and the `Makefile` are interchangeable — the Makefile is a
thin wrapper over the CLI. Pick whichever you prefer. (With `uv`, prefix CLI
commands with `uv run`; with a plain `pip install`, `sast-eval` is on PATH.)

```bash
# 0. Corpus (repos already cloned at workspace root; symlinked into corpus/)
ls corpus/  # bountytasks  BenchmarkJava  cwe-bench-java  cybergym  sast-bench

# 1. Setup (creates a uv venv and installs the sast-eval package)
make setup            # or: uv sync

# 2. Prepare standardized codebases in ONE command.
#    `prepare` does everything required: downloads missing corpora, builds
#    task records (tasks/*.jsonl), fetches source trees, and packages per-task
#    .tar.gz codebases (codebases/<benchmark>/<task_id>.tar.gz).
#
#    By default it caps each benchmark to 20 codebases so it always finishes
#    fast. Pass --all for everything (slow: CyberGym is ~240GB, SASTbench
#    Full Track is 189 real-world repos).
sast-eval prepare                       # fast: all benchmarks, 20 codebases each
sast-eval prepare --all                 # everything (slow)
sast-eval prepare --benchmark owasp      # only OWASP
sast-eval prepare --benchmark cybergym --limit 5
# or: make prepare BENCHMARK=owasp LIMIT=5

# 3. Run your SAST tool over each task's source_root, emit SARIF v2.1.0 to:
#    results/raw/<tool>/<task_id with / → __>.sarif
#    Map the tool's ruleIds to CWEs via tools/<tool>/rules.json.
#    (Or analyze the per-task tarballs from `sast-eval prepare`.)

# 4. Match findings against ground truth (§5)
sast-eval match --tool <tool>      # or: make match TOOL=<tool>

# 5. Run exploit-validation oracles on matched results (§10)
sast-eval exploit --tool <tool>    # or: make exploit TOOL=<tool>

# 6. Score + report (§6, includes exploit-validation section)
sast-eval score --tool <tool>      # or: make score TOOL=<tool>

# Or: prepare + match (empty results) + exploit + score in one go
sast-eval all --tool <tool>        # or: make all TOOL=<tool>
```

<details>
<summary>Equivalent raw commands (without the CLI / make)</summary>

```bash
uv run python -m sast_eval.adapters.owasp_adapter --root corpus/BenchmarkJava --out tasks/owasp.jsonl
uv run python -m sast_eval.importers.bountytasks_importer --metadata-root corpus/bountytasks \
    --tasks-out tasks/bountytasks.jsonl --imported-out imported/bountytasks.jsonl
uv run python -m sast_eval.importers.cwebench_importer --root corpus/cwe-bench-java \
    --tasks-out tasks/cwebench.jsonl --imported-out imported/cwebench.jsonl
uv run python -m sast_eval.importers.cybergym_importer --root corpus/cybergym \
    --tasks-out tasks/cybergym.jsonl --imported-out imported/cybergym.jsonl
uv run python -m sast_eval.adapters.sastbench_adapter --root corpus/sast-bench --out tasks/sastbench.jsonl
uv run python -m sast_eval.matching.matcher --tasks tasks/ --results results/raw/<tool>/ \
    --out results/matched/<tool>/ --tool <tool>
uv run python -m sast_eval.scoring.metrics --matched results/matched/<tool>/ \
    --imported imported --tasks tasks --out reports/scorecard.md
```
</details>

## Programmatic API

For automation or running a SAST tool + agent in a sandbox, use the Python API
(`sast_eval.api`). It reuses the exact same code paths as the CLI, so behavior
is identical — just scriptable.

```python
from sast_eval import SastEval

# Same defaults as the CLI; customize benchmark/limit/paths here.
sast = SastEval(benchmark="owasp", limit=20)
sast.prepare()                       # download + build + fetch + package

with sast.results("mytool") as run:
    for cb in sast.codebases():      # iterate per-task .tar.gz tarballs
        # Stream the tarball to a sandbox dir (64KB chunks, low memory).
        tar = cb.download("/tmp/sandbox")
        # ...run your SAST tool on `tar` (or cb.download(dest, extract=True))
        #    and produce SARIF v2.1.0...
        run.save_sarif(sarif, cb.task_id)
    run.match()                      # classify TP/FP/FN against ground truth
    run.exploit()                    # 4-tier exploit-validation oracle
    run.score()                      # render scorecard -> run.scorecard_path
```

- `SastEval(benchmark=, limit=, corpus=, tasks=, imported=, results=, reports=, codebases_dir=)`
  mirrors the CLI flags. `prepare()`, `build()`, `fetch()`, `package()` call
  the same `cmd_*` functions the CLI uses.
- `SastEval.codebases()` yields `Codebase` objects (`task_id`, `benchmark`,
  `bytes`, `file_count`, `ground_truth`) read from `codebases/MANIFEST.json`.
- `Codebase.download(dest_dir, extract=False)` streams the tarball — designed
  for shipping the codebase to an external sandbox, scanning it there, and
  piping the SARIF back via `run.save_sarif(...)`.
- `ResultRun.save_sarif(sarif, task_id)` accepts a dict, a JSON string, or a
  `Path` to a `.sarif` file.

See [`test/test_api.py`](test/test_api.py) for a runnable end-to-end example
(`make test`).

## Notes

- **OWASP** (`sast_eval/adapters/owasp_adapter.py`): the only end-to-end adapter.
  `real=false` rows are FP traps — any finding there is a false positive.
  Category → CWE mapping in §3.2; the CSV's per-row `cwe` column is preferred.
- **bountytasks** (`sast_eval/importers/bountytasks_importer.py`): importer only. The
  science team's runner is canonical; this repo imports their results verbatim
  under their metric names (`detect_success_rate`). The `codebase/` submodules
  are often private/unchecked-out → tasks marked `source_missing`. Empty `patch`
  dict → `ground_truth_incomplete` (excluded from headline metrics).
- **CWE-Bench-Java** (`sast_eval/importers/cwebench_importer.py`): importer only. Joins
  `project_info.csv` ⋈ `fix_info.csv`. `method_start/end` refer to the *fixed*
  commit; the matcher prefers method-identity matching and uses line ranges
  only as a secondary signal (line-drift caveat, §3.3).
- **CyberGym** (`sast_eval/importers/cybergym_importer.py`): importer only. Fuzzer-based
  C/C++ benchmark (ARVO + OSS-Fuzz, 1507 tasks). Task metadata comes from
  `tasks.json` (HuggingFace dataset); per-task source is `repo-vul.tar.gz`
  (extracted to `src-vul/` for packaging). Ground truth = files touched by
  `patch.diff`. No CWE/CVE in the metadata → `cwe=CWE-UNKNOWN`; the
  vulnerability type is in `notes` (the `vulnerability_description`). The full
  dataset is ~240GB; use `CYBERGYM_LIMIT` to fetch a subset.
- **SASTbench** (`sast_eval/adapters/sastbench_adapter.py`): end-to-end adapter. Evaluates
  SAST on agentic codebases (206 cases: 17 Core Track synthetic + 189 Full Track
  real-world, 7 languages). Ground truth is region-level: each case has
  `vulnerable_regions` (vulnerable + capability_safe). Capability-safe cases
  contain properly guarded dangerous code; flagging them is a capability false
  positive (tracked as `capability_fp` in the matcher, surfaced as Capability
  FP Rate in the scorecard). `fp_trap=true` for capability_safe cases. Full
  Track source requires `make fetch` to run `scripts/setup_repos.py` (clones
  real-world repos into `.repos/`); Core Track is self-contained. See
  [docs/SASTBENCH_INTEGRATION.md](docs/SASTBENCH_INTEGRATION.md).
- **CWE normalization** (`sast_eval/adapters/common.py`): `"CWE-22: Path Traversal"`,
  `"400: Denial of Service"`, `"22"` → canonical `CWE-022`; empty → `CWE-UNKNOWN`.
- **CWE equivalence classes** (`sast_eval/matching/cwe_map.json`): symmetric matching,
  e.g. `CWE-22 ↔ {23,36,29,73}`, `CWE-78 ↔ {77}`.
- **Provenance**: every table in `reports/scorecard.md` carries a `unit:` label
  (§9.5); imported metrics carry `source: science-team-runner`. Cross-benchmark
  claims are blocked until `reports/equivalence_report.md` is co-signed (§12.3).

## Extending the harness

See [docs/ADDING_A_BENCHMARK.md](docs/ADDING_A_BENCHMARK.md) for a step-by-step
guide to adding a new benchmark: registering the corpus, writing an adapter or
importer, materializing source, and packaging per-task `.tar.gz` codebases.

See [docs/RELEASING.md](docs/RELEASING.md) for publishing `sast-eval` to PyPI
(Trusted Publishing setup + per-release checklist).

## Try it with the example tool

`tools/exampletool/` ships a hand-crafted SARIF sample per benchmark (one TP +
deliberate FPs each) plus a `rules.json` mapping its ruleIds to CWEs. It exercises
the full match → exploit → score pipeline without needing a real SAST tool:

```bash
sast-eval match  --tool exampletool
sast-eval exploit --tool exampletool
sast-eval score  --tool exampletool
cat reports/scorecard.md
```

See [tools/exampletool/README.md](tools/exampletool/README.md) for the expected
TP/FP classification per benchmark.

## Documentation

- [docs/QUICKSTART.md](docs/QUICKSTART.md) — end-to-end walkthrough with runnable
  examples (install, build, run the example tool, plug in your own SAST).
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — pipeline, module ownership,
  unified task schema, matching rules, scorecard structure.
- [docs/SCORING.md](docs/SCORING.md) — TP/FP/FN classification, metric
  definitions, per-benchmark metrics, caveats.
- [docs/CYBERGYM_INTEGRATION.md](docs/CYBERGYM_INTEGRATION.md) — how CyberGym
  (a non-SAST, fuzzer-based benchmark) was made SAST-scoreable as a
  location-only proxy.
- [docs/SASTBENCH_INTEGRATION.md](docs/SASTBENCH_INTEGRATION.md) — how SASTbench
  (region-level ground truth, capability-safe FP traps, agentic-code scoring)
  was integrated as the second end-to-end adapter.
- [docs/README.md](docs/README.md) — index of all documentation.
