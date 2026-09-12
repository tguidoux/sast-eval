# Unified SAST Evaluation Specification

**Evaluating one SAST tool across three vulnerability benchmarks with a single, comparable methodology.**

## 0. Context: what already exists vs. what this repo builds

The science team **already has working implementations** for two of the three
benchmarks:

| Benchmark | Status | Owner |
|-----------|--------|-------|
| bountytasks (bountybench) | ✅ implemented (science team runner) | science team — **canonical** |
| CWE-Bench-Java | ✅ implemented (science team runner) | science team — **canonical** |
| OWASP BenchmarkJava v1.2 | ❌ not implemented | **this repo builds it** |

**Consequence: this repo does NOT reimplement bountytasks or CWE-Bench.**
Their runners stay canonical for those benchmarks. This repo's build targets are:

1. **The OWASP adapter** (the unique addition — the only benchmark of the three
   with true FP traps, i.e., the only honest false-positive-rate measurement).
2. **Importers** that map the science team's existing result formats into the
   unified matched-results format (they change nothing on their side).
3. **The aggregation layer**: unified task schema, matcher, scorecard,
   provenance, and the model-level comparison instrument (§9).
4. **The differential-test protocol** (§12.3) that proves the importers do not
   distort their numbers — the acceptance criterion that pre-empts the
   "cannot be compared" objection.

Benchmarks covered by the unified layer:

| # | Benchmark | Location | Tasks | Languages | Ground-truth granularity |
|---|-----------|----------|-------|-----------|--------------------------|
| 1 | bountytasks (bountybench) | `../bountytasks` | ~46+ bounties across ~25 repos | Python, JS/TS, C, Go | file-level (`patch` dict) |
| 2 | OWASP BenchmarkJava v1.2 | `../BenchmarkJava` | 2,740 test cases | Java | file-level + FP traps |
| 3 | CWE-Bench-Java | `../cwe-bench-java` | 120 CVEs | Java | method-level (`fix_info.csv`) |

---

## 1. Design principles

1. **One task schema, adapters/importers.** Every benchmark is normalized into
   an identical task record before any tool runs. The SAST tool and the scorer
   never know which benchmark a task came from.
2. **Canonical runners are never replaced.** Where the science team has an
   implementation, it stays the source of truth; this repo only *imports* its
   results. Reimplementation of an owned benchmark is out of scope by policy.
3. **SARIF as the tool-output contract** for anything this repo runs directly
   (OWASP scans, and any tool runs the science team delegates to this harness).
   [SARIF v2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html).
4. **Detection is decoupled from exploitation.** None of the three benchmarks
   natively scores "did the tool find the bug by reading code" — bountytasks
   scores exploit success, OWASP scores test-case-level findings, CWE-Bench
   scores LLM detection reports. Our harness scores *findings vs. ground truth*
   directly.
5. **Report per-benchmark AND combined.** Cross-benchmark numbers are only
   meaningful when per-benchmark numbers are shown next to them (different task
   difficulty, different FP-trap density).
6. **Distinct metrics never share names.** If the science team measures
   exploit-verified Detect-leg success on bountytasks and this harness measures
   static finding-matching, both are valid but are reported under different
   metric names with provenance — never mixed in one table.

---

## 2. Unified task schema

One JSON object per task, serialized as JSONL in `tasks/<benchmark>.jsonl`.

```json
{
  "task_id": "bountytasks/mlflow/bounty_0",
  "benchmark": "bountytasks",
  "language": "python",
  "source_root": "/abs/path/to/mlflow/codebase",
  "vcs": {
    "type": "git",
    "commit": "<vulnerable_commit>",
    "checked_out": true
  },
  "ground_truth": {
    "cwe": "CWE-23",
    "cwe_raw": "CWE-23: Relative Path Traversal",
    "cve": "CVE-2023-6833",
    "vulnerable_files": ["mlflow/server/handlers.py"],
    "vulnerable_methods": [],
    "fp_trap": false,
    "notes": "patch dict maps patch_files/ -> repo paths"
  },
  "weights": {
    "disclosure_bounty_usd": 1523.0,
    "patch_bounty_usd": 0.0
  },
  "meta": {
    "severity": "critical",
    "task_validated": true
  }
}
```

Field semantics:

- `source_root` — the directory the SAST tool must scan. Always the **buggy**
  snapshot (vulnerable commit checked out).
- `ground_truth.vulnerable_files` — repo-relative paths the official fix touched.
  A finding in one of these files is a *location candidate*.
- `ground_truth.vulnerable_methods` — optional method-level refinement
  (CWE-Bench only): `{file, class, method, start, end, signature}`.
- `ground_truth.fp_trap` — `true` for OWASP `real=false` rows: ground truth is
  **zero findings**; any finding is a FP.
- `weights` — only bountytasks provides these; used for $-weighted recall.

### 2.1 CWE normalization

Raw CWE strings differ wildly across benchmarks:

| Benchmark | Example raw values |
|-----------|--------------------|
| bountytasks | `"CWE-22: Path Traversal"`, `"400: Denial of Service"`, `"CWE-29: Path Traversal: '\\..\\filename'"`, `""` |
| OWASP CSV | numeric category codes (`22`, `78`, `89`, …) |
| CWE-Bench | `"CWE-022"`, `"CWE-078"`, `"CWE-079"`, `"CWE-094"` |

Normalization rule: extract the integer → canonical form `CWE-<int>` (zero-padded
to 3 for display). Empty/unparseable → `CWE-UNKNOWN` (excluded from
category-matched metrics, still counted for location-only metrics).

### 2.2 CWE equivalence classes (`matching/cwe_map.json`)

Some benchmarks split what is conceptually one weakness. Findings match ground
truth if their CWEs are in the same equivalence class:

```json
{
  "CWE-22":  ["CWE-23", "CWE-36", "CWE-29", "CWE-73"],
  "CWE-78":  ["CWE-77"],
  "CWE-79":  ["CWE-80", "CWE-116", "CWE-117"],
  "CWE-94":  ["CWE-776"],
  "CWE-400": ["CWE-404", "CWE-662"],
  "CWE-502": [],
  "CWE-918": ["CWE-444"]
}
```

Matching is **symmetric**: `matches(a, b) := a == b or b in class(a) or a in class(b)`.

---

## 3. Adapters and importers

Two kinds of connectors, distinguished by ownership:

- **Adapter** — this repo owns the benchmark end-to-end (only OWASP today):
  builds task records, runs the tool, matches, scores.
- **Importer** — the science team owns the benchmark and its runner; this repo
  only maps their *result files* into the unified matched-results format. The
  importer never re-runs, re-matches, or re-scores anything the canonical runner
  already produced; it is a format translation, not a reimplementation.

### 3.1 bountytasks importer (science team's runner is canonical)

- Input: the science team runner's per-bounty result files (format to be
  inventoried in Step 1 of §12 — expected: per-bounty JSON with Detect/Exploit/
  Patch leg outcomes, verify.sh exit codes, timing, token usage).
- Output: unified matched-results records with `metric: detect_success_rate`
  (their definition, primary) — NOT re-derived static recall.
- The importer also emits the *task records* (schema §2) for cross-referencing,
  derived from `bounty_metadata.json` (CWE normalization §2.1, `patch` dict →
  `vulnerable_files`, `disclosure_bounty`/`patch_bounty` → `weights`), because
  the unified scorecard needs task metadata their results don't carry.
  Empty `patch` dict → `ground_truth_incomplete: true`.
- If this repo ever needs *static* SARIF matching on bountytasks (e.g., for
  Tier 1 screening), that is an **additional, separately-labeled metric**
  (`static_recall`), never a replacement for their `detect_success_rate`.

### 3.2 OWASP BenchmarkJava adapter (this repo owns it)

- Parses `expectedresults-1.2.csv`: `# test name, category, real vulnerability, cwe`.
- One task per row. `source_root` = the benchmark repo root (tool scans whole
  repo; matching is per test-case file), `vulnerable_files` =
  `src/main/java/org/owasp/benchmark/testcode/<TestName>.java`.
- `real=false` rows → `fp_trap: true` (~1,000 of 2,740 rows are FP traps).
- Category code → CWE via the fixed OWASP mapping (`sqli→89`, `xss→79`,
  `cmdi→78`, `pathtraver→22`, `ldapi→90`, `xpi→643`, `crypto→327`,
  `hash→328`, `weakrand→330`, `trustbound→501`, `securecookie→614`).
- No weights (all tasks equal).

### 3.3 CWE-Bench-Java importer (science team's runner is canonical)

- Input: the science team runner's per-slug result files (inventory in §12).
- Output: unified matched-results records under their metric names.
- The importer also emits task records by joining `data/project_info.csv`
  (one row per CVE) with `data/fix_info.csv` (one row per fixed method) on
  `project_slug` — needed for the unified scorecard's per-CWE tables:
  - `source_root` = `project-sources/<slug>` at `buggy_commit_id`
  - `vulnerable_methods` ← fix_info rows: file, class, method, line ranges,
    signature. A CVE with multiple fix rows yields multiple method entries.
  - **Line-drift caveat:** `method_start/end` refer to the *fixed* file; when
    scanning the *buggy* commit, ranges may be off by a few lines. Any
    static-matching path (if added) must prefer **method-identity matching**
    (file + method name/signature) and use line ranges only as a secondary
    signal.

---

## 4. Tool-output contract

- **Format:** SARIF v2.1.0, one file per task, at
  `results/raw/<tool_name>/<task_id>.sarif` (task_id with `/` → `__`).
- Required per result: `locations[0].physicalLocation.artifactLocation.uri`
  (repo-relative), `ruleId` (mapped to CWE via the tool's rule table,
  `tools/<tool>/rules.json`), optional `region.startLine`.
- A missing SARIF file for a task = tool produced no findings (counted as all-FN
  for that task, with a `run_failed` note if the wrapper logged an error).

---

## 5. Matching rules

For each task, classify every finding:

```
location_hit(f)  := normalize(f.file) ∈ task.vulnerable_files
                  (or, if vulnerable_methods exist:
                   f.file == m.file AND (method-identity or line-range overlap))
category_hit(f) := cwe_matches(f.cwe, task.cwe)

TP  := location_hit AND category_hit
FP  := NOT (location_hit AND category_hit)      # includes right-file-wrong-CWE
FN  := ground-truth vuln with no TP finding against it
```

Granularity hierarchy — score at the finest level the benchmark supports:

| Benchmark | Primary match | Secondary |
|-----------|---------------|-----------|
| bountytasks | file + CWE | — |
| OWASP | test-case file + CWE | — |
| CWE-Bench | file + method identity | line-range overlap |

Special cases:

- **FP traps (OWASP `real=false`):** any finding in the test-case file is a FP,
  regardless of CWE.
- **`ground_truth_incomplete` tasks (bountytasks, empty patch dict):** excluded
  from TP/FP/FN; reported separately as "detected-CWE-only" (did the tool emit
  *any* finding of the right CWE anywhere in the repo? — a weak signal, reported
  but not merged into headline metrics).
- **Duplicate findings:** multiple TPs on the same ground truth count once for
  recall; each still counts toward precision's denominator.

---

## 6. Metrics

### 6.1 Headline metrics (per benchmark + combined)

| Metric | Definition |
|--------|------------|
| **Recall / TPR** | `TP / (TP + FN)` — fraction of true vulns found |
| **FPR** | `FP / (FP + TN)` — OWASP-style; TN available only where FP traps exist (OWASP). For bountytasks/CWE-Bench, report *precision* instead and note FPR is undefined without clean-code tasks |
| **Precision** | `TP / (TP + FP)` |
| **F1** | harmonic mean of precision & recall |
| **OWASP Benchmark score** | `TPR − FPR` (OWASP convention, for comparability with published scorecards) |

### 6.2 Per-CWE breakdown

Recall, precision, and task counts per canonical CWE class — the primary
cross-benchmark comparison axis (CWE-22/23/29 path traversal, CWE-78/77 command
injection, CWE-79 XSS, CWE-94 code injection exist in all three benchmarks).

### 6.3 Benchmark-specific metrics

**bountytasks:**
- **$-weighted recall** — `Σ bounty(found) / Σ bounty(all)` using
  `disclosure_bounty_usd`. Answers: "what share of real-world bounty dollars
  would this tool have surfaced?"
- **Per-bounty binary detection** — each bounty is one vuln, so also report
  simple `found / total`.

**OWASP:**
- Standard scorecard table (per-category TPR/FPR) to stay comparable with the
  published FindBugs/PMD/ZAP scorecards in `BenchmarkJava/scorecard/`.

**CWE-Bench:**
- **Method-level recall** (finding inside the fixed method) vs **file-level
  recall** (finding anywhere in the fixed file) — the delta measures localization
  precision.

### 6.4 Efficiency metrics

- Wall-clock time per task, per KLOC
- Findings emitted per task (noise indicator)

### 6.5 Combined reporting

Combined metrics are computed **only over the CWE classes present in all three
benchmarks** (the "common CWE core": 22/23/29, 78/77, 79, 94) to avoid mixing
incomparable task populations. The full-corpus combined number is reported as a
secondary, clearly-caveated figure.

---

## 7. Output artifacts

```
sast-eval/
├── tasks/
│   ├── bountytasks.jsonl        # normalized task records
│   ├── owasp.jsonl
│   └── cwebench.jsonl
├── tools/<tool>/rules.json      # ruleId → CWE mapping for the tool
├── results/
│   ├── raw/<tool>/<task>.sarif
│   └── matched/<tool>/<task>.json   # per-task TP/FP/FN classification
├── reports/
│   ├── scorecard.md             # headline + per-benchmark + per-CWE tables
│   └── scorecard.html           # optional rendered version
└── matching/cwe_map.json
```

`reports/scorecard.md` layout:

1. Headline table (per benchmark + combined): recall, precision, F1, FPR*, score
2. Per-CWE table (common core)
3. Benchmark-specific sections ($-weighted recall; OWASP category scorecard;
   method-vs-file recall)
4. Excluded tasks audit (unvalidated bounties, missing sources, incomplete
   ground truth) — **always reported, never silently dropped**

---

## 8. Known caveats

1. **bountytasks ground truth is patch-derived**: the fix commit may touch files
   for unrelated reasons (refactors, tests). Mitigation: manual spot-audit of the
   `patch` dicts for the top-$ bounties.
2. **CWE-Bench line drift** (fixed-commit line numbers vs buggy snapshot) —
   handled by method-identity-first matching.
3. **OWASP is synthetic**: 2,740 tiny servlets; recall there does not predict
   recall on real codebases. That's precisely why the combined eval exists.
4. **FP measurement asymmetry**: only OWASP has true-negative tasks. For the
   other two, precision is computed against "findings outside the known vuln",
   which conflates FPs with undetected *other* real bugs. Caveat in every report.
5. **Language coverage**: bountytasks is mostly Python/JS, the Java benchmarks
   are Java-only. If the tool is single-language, per-benchmark numbers are the
   honest comparison; combined numbers only make sense per-language.

---

## 9. Comparison methodology: system-level vs model-level

The system under test is **model + harness**. A benchmark score is therefore
always `f(model quality, harness quality)` and never isolates the model when the
harness varies. Every reported number must be labeled with its unit of
comparison.

### 9.1 Mode 1 — System-level (external)

Compare the **complete tool** (model + harness + SARIF post-processing) against
other complete tools: Semgrep, CodeQL, FindBugs/FindSecBugs, PMD, IRIS+LLM.
This is the standard published convention (OWASP scorecards, IRIS paper) and is
legitimate: a tool's score measures the tool, not its algorithm in isolation.

- Use for: papers, marketing, external claims.
- Baselines: reuse published scorecards where tool versions match; re-run
  baselines with this harness where they don't.

### 9.2 Mode 2 — Model-level (internal, for the science team)

Hold the harness **fixed** and swap the model. Same tasks, same matching rules,
same metrics → the only variable is the model. This is the harness's primary
value to the model team: it is the instrument that makes model-vs-model
comparison scientifically valid.

```
                 FIXED harness (this repo)
Model A    ──▶  adapters ──▶ SARIF ──▶ matcher ──▶ metrics
Model B    ──▶  (identical)
Model C    ──▶  (identical)
```

- Use for: model release tracking, ablations, regression testing between model
  versions.
- Rule: any harness change invalidates previous model-level numbers; re-run the
  model matrix after harness changes and version-pin the harness.

### 9.3 Mode 3 — Harness-level ablations

Hold the model fixed, vary harness components (context window size, retrieval
on/off, SARIF post-filter on/off, prompt template). Justifies harness design
choices independently of model quality.

### 9.4 Exploit-validation tier: ablate the two models separately

The exploit-validation tier (Section 10) stacks **two** variable components:
the detection model and the exploit-generation model. For model-level claims,
run three separate measurements:

| Measurement | Setup | Isolates |
|---|---|---|
| (a) Detection-only | static SARIF matching (Tier 1) | detection model |
| (b) Exploit-only | feed ground-truth bounty report to exploit agent (the benchmark's Exploit leg) | exploit model |
| (c) Combined | detection output → exploit agent (the benchmark's Detect leg) | the handoff + both |

Deltas between (a), (b), (c) localize weakness: discovery, weaponization, or
the handoff between them.

### 9.5 Reporting rule

Every table in `reports/scorecard.md` carries a `unit:` field:
`unit: system | model:<harness-version> | harness:<model-version>`. Numbers
without a unit label are invalid.

---

## 10. Finding validation via the 4-tier oracle

Tier 0 (static matching, §5) is a proxy. Tiers 1–3 confirm findings by grading
each SARIF finding to the **highest tier that could be run** for its benchmark.
Tier 1 (reachability) is the key cross-benchmark addition — a static, no-runtime
signal that filters dead code and works for all 5 benchmarks. Tiers 2–3 layer
on runtime evidence only where a native oracle exists.

```
Tier 0 — static match      (always available; from matching/matcher.py)
Tier 1 — reachability      (static call-graph + taint; no runtime)   ← key addition
Tier 2 — canary probe       (lightweight runtime: plant canary, send one input)
Tier 3 — full exploit       (benchmark-native oracle: verify.sh / PoC)
```

```
SARIF finding (file, line, CWE)
      │  Tier 1: reachability (static, all benchmarks)
      ▼
reachable / unreachable / unknown
      │  Tier 2: canary probe (runtime, where oracle exists)
      ▼
canary hit / canary miss
      │  Tier 3: full exploit (runtime, benchmark-native)
      ▼
ORACLE ──▶ confirmed / unconfirmed
```

### 10.1 Oracle tiers and per-benchmark availability

| Tier | What it does | Where it runs |
|---|---|---|
| **Tier 1 — reachability** | Static: is the finding's location on a live path from a public entry point? | All 5 benchmarks (generic fallback; no runtime) |
| **Tier 2 — canary probe** | Lightweight runtime: plant a canary, send one input, observe side effect | OWASP (servlet canary, TODO); bountytasks (generic probes below) |
| **Tier 3 — full exploit** | Benchmark-native oracle: `verify.sh` (bountytasks), PoC crash (CyberGym) | bountytasks, CyberGym |

Tier 3 sub-levels (bountytasks):

- **Level 1 — `verify.sh`** (for the known vuln): if a finding overlaps the
  ground-truth vuln and a generated exploit passes `verify.sh` (exit 0), the
  finding is a **confirmed TP**. The oracle already exists; zero extra work.
- **Level 2 — generic impact probes** (for findings outside the known vuln):
  pre-plant canaries during setup, aim the generated exploit at them:

  | CWE class | Probe (success condition) |
  |---|---|
  | Path traversal (22/23/29/73) | read a canary file outside the allowed dir (`/tmp/canary_<random>`) |
  | Command injection (78/77) | `touch /tmp/pwned_<random>` inside the app container |
  | Code injection / deserialization (94/502) | observable side effect file |
  | SSRF (918) | callback hits a listener container on `shared_net` (mlflow `malicious_server` pattern) |
  | XSS (79) | payload round-trips unescaped |
  | DoS (400) | server process dies / stops responding within timeout |

- **Level 3 — LLM judge** (fallback, unreachable code): judge the exploit
  reasoning against the finding. Weakest signal; report separately, never
  merged with Levels 1–2.

CyberGym Tier 3: submit a PoC to the CyberGym FastAPI server, which runs it
against two Docker images (`-vul` and `-fix`). `vul_exit_code != 0` AND
`fix_exit_code == 0` = confirmed.

### 10.2 Outcome buckets (four, never two)

- `confirmed` — Tier 1/2/3 demonstrated impact (reachable +, or canary hit, or exploit passed)
- `unconfirmed` — a higher tier was attempted but failed (canary miss, exploit exit≠0)
- `matched-static-only` — only Tier 0 ran (no source for Tier 1, or reachable but no runtime oracle)
- `unreachable` — Tier 1 found the finding is on dead code (test/example/doc path heuristic)

New metrics: **confirmed precision** (confirmed / (confirmed + unconfirmed) —
measures actionability), **confirmation rate per CWE**, **exploitability gap**
(statically-matched but unexploitable).

### 10.3 Cost model

- **Tier 1** runs on all 5 benchmarks, no runtime, ~instant per finding.
- **Tier 2/3** run only where a native oracle exists (bountytasks ~46 bounties,
  CyberGym), need Docker + an LLM exploit agent, ~minutes per finding. Run on
  release candidates, not per commit.

See [docs/EXPLOIT_VALIDATION.md](docs/EXPLOIT_VALIDATION.md) for the
implementation (`exploit/oracle.py` + `exploit/oracles/`).

---

## 11. Building the package from scratch (executable instructions)

This section is written to be executed by an AI agent or a fresh contributor.
Follow it top to bottom. **Scope reminder (§0): only the OWASP benchmark is
built end-to-end here; bountytasks and CWE-Bench enter via importers of the
science team's existing runner outputs.** Target layout after completion:

```
sast-eval/
├── EVAL_SPEC.md                 (this file)
├── README.md
├── corpus/                      (cloned benchmark repos — NOT committed)
│   ├── bountytasks/             (metadata only; runner lives with science team)
│   ├── BenchmarkJava/           (fully used by the OWASP adapter)
│   └── cwe-bench-java/          (seed data for task records; runner is theirs)
├── importers/                   (science-team result formats → unified format)
│   ├── __init__.py
│   ├── bountytasks_importer.py
│   └── cwebench_importer.py
├── adapters/
│   ├── __init__.py
│   ├── common.py               (CWE normalization, bounty-value parsing)
│   └── owasp_adapter.py        (the only end-to-end adapter)
├── matching/
│   ├── __init__.py
│   ├── cwe_map.json
│   └── matcher.py
├── scoring/
│   ├── __init__.py
│   └── metrics.py
├── tools/<tool>/rules.json      (ruleId → CWE map for the SAST tool)
├── tasks/                       (task records, JSONL — all three benchmarks)
├── imported/                    (science-team results in unified format)
├── results/raw/<tool>/          (SARIF per task — OWASP + any delegated runs)
├── results/matched/<tool>/      (TP/FP/FN per task)
├── reports/
│   ├── scorecard.md
│   └── equivalence_report.md   (§12.3 differential-test output)
└── PROVENANCE.md                (harness version, corpus hashes, metric defs)
```

### Step 0 — Prerequisites

- Python 3.10+, `git`, `docker` (only for Tier 2 and bountytasks validation).
- No `pip install` needed beyond stdlib for the harness itself; add
  `jsonschema` only if validating task records against a schema.
- **Access to the science team's runner result files** for bountytasks and
  CWE-Bench (path or repo — inventory them per §12.1 before writing importers).

### Step 1 — Clone the benchmark repos

```bash
mkdir -p corpus && cd corpus

# bountytasks: needed for task metadata (bounty_metadata.json) even though the
# runner is the science team's. Private submodules may be unavailable; tolerate
# missing codebase/ dirs (mark task source_missing, continue).
git clone https://github.com/bountybench/bountytasks.git

# OWASP BenchmarkJava (large, ~1GB with history) — fully used by our adapter
git clone https://github.com/OWASP-Benchmark/BenchmarkJava.git

# CWE-Bench-Java (seed data for task records; runner is the science team's)
git clone https://github.com/iris-sast/CWE-Bench-Java.git cwe-bench-java
```

Idempotency: if a directory already exists and is a git repo, `git pull`
instead of cloning. Never modify anything inside `corpus/`.

### Step 2 — Inventory the science team's runner outputs (BEFORE writing importers)

Per §12.1: for each of their two benchmarks, document (a) result file format
and location, (b) metric names and definitions they publish, (c) task
identifiers, (d) any per-run provenance they already record. Write the
inventory to `importers/FORMATS.md`. **Do not write a line of importer code
before this document exists and the science team has confirmed it.**

### Step 3 — Build the task corpus (all three benchmarks)

Task records (schema §2) are needed for all benchmarks — the unified scorecard
joins their *results* to our *task metadata* (CWE, weights, vulnerable files).

**3a. bountytasks task records** (`python -m importers.bountytasks_importer --metadata-root corpus/bountytasks --results <their-results> --tasks-out tasks/bountytasks.jsonl --imported-out imported/bountytasks.jsonl`)

1. Glob `<root>/*/bounties/bounty_*/bounty_metadata.json`.
2. For each: parse `CWE` (normalize per §2.1 — handle `"CWE-22: Path Traversal"`,
   `"400: Denial of Service"`, `""`), `CVE`, `vulnerable_commit`,
   `disclosure_bounty`/`patch_bounty` (reuse the parsing rules of
   `corpus/bountytasks/calculate_bounties.py`: `$`-strip, `"X to Y"` → average).
3. `vulnerable_files` ← values of the `patch` dict. Empty `patch` dict →
   `ground_truth_incomplete: true` (excluded from headline metrics, reported in
   the audit section).
4. `source_root` = `<env_dir>/codebase`. If the dir is missing (private
   submodule), mark `source_missing` and keep the task record.
5. Import their runner results verbatim into `imported/bountytasks.jsonl`
   under **their** metric names (`detect_success_rate`, etc.). Do not recompute.
6. Optional `--validate` mode (only if the science team's runner doesn't
   already validate): shell out to `run_ci_local.sh <env>/bounties/bounty_N
   --patch --check-invariants`, cache in `tasks/validation.json`.

**3b. OWASP task records + scan** (`python -m adapters.owasp_adapter --root corpus/BenchmarkJava --out tasks/owasp.jsonl`)

1. Parse `expectedresults-1.2.csv` (skip the `#` comment line). Columns:
   test name, category, real vulnerability, cwe.
2. One task per row. `source_root` = the benchmark repo root (tools scan the
   whole repo; matching is per test-case file).
   `vulnerable_files` = `["src/main/java/org/owasp/benchmark/testcode/<TestName>.java"]`
   (NOTE: the directory is `testcode`, not `testcases` — verify with
   `ls corpus/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode | head`).
3. `real=false` → `fp_trap: true`. Category code → CWE via the fixed mapping
   (§3.2). No weights.

**3c. CWE-Bench task records** (`python -m importers.cwebench_importer --root corpus/cwe-bench-java --results <their-results> --tasks-out tasks/cwebench.jsonl --imported-out imported/cwebench.jsonl`)

1. Join `data/project_info.csv` and `data/fix_info.csv` on `project_slug` for
   task metadata: `source_root` = `project-sources/<slug>` at `buggy_commit_id`;
   `vulnerable_methods` ← fix_info rows `{file, class, method, start, end,
   signature}` (line ranges refer to the FIXED commit — §3.3 caveat).
2. Import their runner results verbatim under their metric names.

### Step 4 — Run the SAST tool (OWASP + any delegated runs)

For every task this repo owns end-to-end (OWASP; optionally bountytasks
static-screening as a separately-labeled `static_recall` metric):

1. Run the tool against `source_root`, emit SARIF v2.1.0 to
   `results/raw/<tool>/<task_id with / → __>.sarif`.
2. Map the tool's `ruleId`s to CWEs via `tools/<tool>/rules.json`.
3. A missing SARIF file = zero findings for that task (all-FN), logged.

### Step 5 — Match (`python -m matching.matcher --tasks tasks/ --results results/raw/<tool>/ --out results/matched/`)

Implement §5 exactly: location hit (file, or method-identity for CWE-Bench),
CWE-equivalence hit via `matching/cwe_map.json`, FP traps, three outcome
buckets. Per-task output JSON: classified findings + FN list + which rule
fired. **Only applies to runs this repo performed — imported results are
already scored by the canonical runner.**

### Step 6 — Score (`python -m scoring.metrics --matched results/matched/ --imported imported/ --out reports/scorecard.md`)

Implement §6: headline table (per benchmark + common-CWE-core combined),
per-CWE table, benchmark-specific metrics ($-weighted recall, OWASP scorecard,
method-vs-file recall), efficiency metrics, excluded-tasks audit. Imported
metrics appear under their own names with `source: science-team-runner` and
are never blended with this harness's metrics. Every table carries a `unit:`
label (§9.5).

### Step 7 — Differential test (§12.3) — REQUIRED before publishing any cross-benchmark claim

Run one shared tool through both pipelines on the overlapping benchmark
(choose whichever of bountytasks/CWE-Bench the science team prefers), produce
`reports/equivalence_report.md`, and get science-team sign-off. Only after
sign-off may the unified scorecard be circulated.

### Step 8 — Tier 2 (optional, release candidates only)

For bountytasks tasks only: bring up the environment
(`setup_repo_env.sh` + `setup_files/setup_bounty_env.sh`), pre-plant canaries
(§10.1 Level 2), generate exploits per finding, run oracles, record the three
outcome buckets (§10.2), and add confirmed-precision / exploitability-gap
columns to the scorecard.

### Build-order dependency graph

```
Step 1 (clone) ──▶ Step 2 (inventory their formats) ──▶ importers/FORMATS.md
                                                            │
        ┌───────────────────────────────────────────────────┤
        ▼                                                   ▼
Step 3a/3c (importers: tasks + verbatim results)   Step 3b (OWASP adapter)
        │                                                   │
        │                              tools/<tool>/rules.json
        │                                                   │
        │                                          Step 4 (scan, OWASP)
        │                                                   │
        └────────────▶ Step 6 (score) ◀── Step 5 (match) ◀──┘
                            │
                     Step 7 (differential test) ──▶ equivalence_report.md
                            │
                     Step 8 (Tier 2, optional)
```

### Acceptance criteria for the build

1. `tasks/bountytasks.jsonl`, `tasks/owasp.jsonl`, `tasks/cwebench.jsonl`
   exist, are valid JSONL, and record counts match source data
   (OWASP: 2,740 rows; CWE-Bench: 120 slugs; bountytasks: count of
   `bounty_metadata.json` files found).
2. Every task record validates against the Section 2 schema (required fields
   present; `CWE-UNKNOWN` allowed).
3. `importers/FORMATS.md` exists, is confirmed by the science team, and each
   importer's output round-trips: importing their result file twice yields
   byte-identical unified records, and every metric value in the unified
   record equals the value in their source file (no recomputation).
4. `matcher.py` on an empty results dir yields 100% FN with zero crashes.
5. `matcher.py` on a synthetic SARIF containing one perfect finding per
   OWASP task yields 100% recall on non-FP-trap tasks and 100% FP on FP-trap
   tasks.
6. `scorecard.md` renders all §6 tables with `unit:` labels, `source:` labels
   on imported metrics, and the excluded-tasks audit.
7. `equivalence_report.md` exists and shows per-metric agreement (§12.3);
   cross-benchmark claims are blocked until it has science-team sign-off.
8. Re-running any adapter/importer is idempotent (same output bytes, modulo
   timestamps).

---

## 12. Interoperability with the science team's existing implementations

The science team already operates runners for bountytasks and CWE-Bench.
This section defines how this harness coexists with them without triggering
the "cannot be compared" objection.

### 12.1 Non-negotiable rules

1. **Their runners are canonical.** This repo never reimplements, re-runs, or
   re-scores their benchmarks. Importers are format translations only.
2. **Their metric definitions win** on their benchmarks. If they define
   recall differently, their definition is the primary number; ours (if any)
   is secondary and separately named.
3. **Distinct metrics never share names.** Exploit-verified Detect-leg
   success vs. static SARIF matching are different metrics on the same corpus:
   both valid, both reported, never blended (`detect_success_rate` vs.
   `static_recall`).
4. **Nothing is frozen without their review.** Matching rules, CWE equivalence
   classes, and metric names in this spec are a proposal until co-signed.

### 12.2 Importer contract

For each of their runners, an importer must:

- consume their result files **read-only**, at a pinned path/repo recorded in
  `PROVENANCE.md`;
- map task identifiers to the unified `task_id` (bounty path / project slug);
- carry over metric values **verbatim** with `source: science-team-runner`,
  `runner_version`, and `result_file_hash` provenance fields;
- emit unified matched-results records (schema §2 + their metrics) into
  `imported/<benchmark>.jsonl`;
- fail loudly (not silently skip) on unrecognized fields or version drift in
  their format — format changes are a joint event, not something an importer
  papers over.

### 12.3 Differential-testing protocol (the equivalence proof)

Purpose: prove the import/aggregation layer does not distort their numbers,
so all future cross-benchmark comparisons are legitimate.

1. Pick one overlapping benchmark (their choice) and one shared tool run:
   the same tool, same model version, same inputs, run through their runner.
2. Import their results; independently compute the same metrics from raw
   artifacts where possible.
3. Produce `reports/equivalence_report.md`: per-metric agreement table
   (their value, our value, delta, explanation for any nonzero delta).
4. Outcomes:
   - **Agreement** → the layer is certified; numbers are comparable.
   - **Disagreement** → a spec bug (e.g., duplicate counting, different CWE
     equivalence) — resolve jointly, record the resolution in this spec,
     re-run. Either outcome builds trust; neither blocks the other work.
5. Re-run the differential test whenever: their runner version changes, this
   harness's matcher changes, or the task corpus is re-generated.

### 12.4 What this repo adds (the standing pitch)

1. **OWASP BenchmarkJava** — the only benchmark of the three with true FP
   traps (~1,000 `real=false` tasks): the only honest false-positive-rate
   measurement. Not covered by their runners.
2. **The aggregation layer** — one task schema, one scorecard, one
   provenance model across all three benchmarks.
3. **The model-level comparison instrument (§9.2)** — their two runners were
   built separately; a unified layer is what makes "model A improved" a single
   comparable statement across benchmarks.
4. **Tier 2 exploit-validation and $-weighted recall** — metrics their native
   runners don't emit.

### 12.5 Governance

- `EVAL_SPEC.md` lives in a shared repo; changes to §2 (schema), §5 (matching),
  §6 (metrics), or this section require science-team review.
- `PROVENANCE.md` records: harness version, corpus commit hashes, their runner
  versions, importer versions, and the date of the last differential test.
- Historical numbers remain valid under their original provenance; the unified
  scorecard simply labels which provenance each column carries.
