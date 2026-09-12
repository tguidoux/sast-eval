# Architecture

This document describes the structure of the `sast-eval` harness: how the
pipeline flows from benchmark repos to a comparable scorecard, what each module
owns, and where the seams between "this repo" and "the science team's runner"
fall. It is a companion to `EVAL_SPEC.md` (the specification) and
`README.md` (the quick-start).

## Design principles (§1)

The harness exists because no single SAST benchmark is sufficient on its own:

- **OWASP BenchmarkJava** is synthetic (2,740 tiny servlets) with true FP traps,
  but recall on it does not predict recall on real codebases.
- **bountytasks** is real-world (bounty-valued CVEs) but has no FP traps and its
  ground truth is patch-derived (fix commits touch files for unrelated reasons).
- **CWE-Bench-Java** is method-level (real CVEs with fix-info metadata) but has
  no FP traps and line ranges refer to the *fixed* commit (drift on the buggy
  commit).
- **CyberGym** is fuzzer-based (ARVO + OSS-Fuzz, C/C++) with no CWE ground truth
  at all — its canonical metric is PoC-crash verification, not static analysis.
- **SASTbench** is region-level (206 agentic-codebase cases) with capability-safe
  FP traps — it tests whether SAST can distinguish guarded dangerous code from
  unguarded vulnerabilities in agent code.

The harness normalizes all five into a single task schema, runs a single
matching methodology, and renders a scorecard that reports each benchmark
separately plus a combined "common CWE core" number that is only computed over
CWE classes present in all CWE-bearing benchmarks (so CyberGym's `CWE-UNKNOWN`
tasks never pollute the combined number).

### Adapters vs. importers (§0)

| Connector | When to use | Owns matching/scoring? |
|---|---|---|
| **Adapter** (`adapters/`) | You run the SAST end-to-end yourself | **Yes** — this repo |
| **Importer** (`importers/`) | A science team's runner is canonical; you only ingest their results | **No** — their runner |

OWASP and SASTbench are adapters. bountytasks, CWE-Bench, and CyberGym are
importers. This distinction matters for provenance: imported metrics carry
`source: science-team-runner` and are never blended with this harness's
metrics.

## Pipeline

```
benchmark repos ──adapters/importers──▶ tasks/*.jsonl
                                            │
              OWASP + delegated runs ──your SAST (SARIF)──▶ results/raw/<tool>/
                                            │
                              sast_eval/matching/matcher.py ◀── cwe_map.json
                                            │
                                     results/matched/<tool>/
                                            │
                       sast_eval/scoring/metrics.py + imported/*.jsonl ──▶ reports/scorecard.md
```

The pipeline has seven stages, each owned by a specific module:

1. **Build** (`make build`) — adapters/importers read each benchmark's metadata
   and emit one JSONL line per task in the unified schema (§2) into `tasks/`.
2. **Fetch** (`make fetch`) — materialize source that isn't pre-checked-out
   (bountytasks clones at the vulnerable commit, CyberGym downloads from
   HuggingFace, SASTbench clones Full Track real-world repos). OWASP and
   SASTbench Core Track are already checked out.
3. **Package** (`make package`) — build a self-contained `.tar.gz` per task at
   `codebases/<benchmark>/<task_id>.tar.gz` for SAST analysis.
4. **Run SAST** (your tool) — emit SARIF v2.1.0 to
   `results/raw/<tool>/<task_id>.sarif` (with `/` → `__` in the filename).
5. **Match** (`make match TOOL=<tool>`) — `sast_eval/matching/matcher.py` classifies each
   finding as TP/FP/FN against ground truth → `results/matched/<tool>/`.
6. **Score** (`make score TOOL=<tool>`) — `sast_eval/scoring/metrics.py` aggregates
   matched records + imported science-team results → `reports/scorecard.md`.
7. **Differential test** (§12.3) — blocked until `reports/equivalence_report.md`
   is co-signed; cross-benchmark claims are blocked until then.

## Module ownership

```
sast-eval/
├── EVAL_SPEC.md                 the specification (§0–§12)
├── PROVENANCE.md                harness version, corpus hashes, metric defs
├── adapters/
│   ├── common.py                CWE normalization (§2.1), bounty-value parsing
│   ├── owasp_adapter.py         end-to-end adapter (§3.2)
│   └── sastbench_adapter.py     end-to-end adapter (region-level ground truth)
├── importers/
│   ├── FORMATS.md               science-team runner output inventory (§12.1)
│   ├── bountytasks_importer.py  importer (§3.1)
│   ├── cwebench_importer.py     importer (§3.3)
│   └── cybergym_importer.py     importer (fuzzer-based, no CWE)
├── matching/
│   ├── cwe_map.json             CWE equivalence classes (§2.2)
│   └── matcher.py               TP/FP/FN classification (§5)
├── scoring/
│   └── metrics.py               headline + per-CWE + benchmark-specific (§6)
├── tools/
│   ├── fetch_sources.py         materialize source (bountytasks, cwebench, cybergym, sastbench)
│   └── package_codebases.py     per-task .tar.gz builder
├── tasks/                       normalized task records (JSONL, §2)
├── imported/                    science-team results in unified format
├── results/raw/<tool>/          SARIF per task
├── results/matched/<tool>/      TP/FP/FN per task
└── reports/
    ├── scorecard.md
    └── equivalence_report.md    (§12.3, pending science-team sign-off)
```

### The unified task schema (§2)

Every task record — regardless of benchmark — has this shape (required fields
in **bold**):

```jsonc
{
  "task_id": "<benchmark>/<id>",            // unique across all benchmarks
  "benchmark": "<short-lowercase-id>",
  "language": "java|python|cpp|...",
  "source_root": "/abs/path/to/source",     // what the SAST scans
  "vcs": {
    "type": "git|archive",
    "commit": "<sha-or-null>",
    "checked_out": true                     // is source materialized locally?
  },
  "ground_truth": {
    "cwe": "CWE-089",                        // canonical via normalize_cwe()
    "cwe_raw": "89",                         // original string from the benchmark
    "cve": "CVE-2024-1234",                  // or null
    "vulnerable_files": ["path/relative/to/source_root"],
    "vulnerable_methods": [],               // [] if file-level only
    "vulnerable_regions": [],               // [] unless region-level (SASTbench)
    "fp_trap": false,                        // true => zero findings expected
    "notes": "benchmark-specific context"
  },
  "weights": {},                            // severity, bounty, etc.
  "meta": {}                                 // benchmark-specific metadata
}
```

Key rules:
- **`task_id`** must be `<benchmark>/<id>` and unique across all benchmarks.
- **`cwe`** must be canonical (`CWE-<int>` zero-padded to 3). Use
  `adapters.common.normalize_cwe()` — it handles `"CWE-22: Path Traversal"`,
  `"400: Denial of Service"`, `"22"`, `""` → `CWE-UNKNOWN`.
- **`source_root`** is an absolute path to what the SAST should scan.
- **`fp_trap`** = `true` means the ground truth is *zero findings*; any finding
  is a false positive (OWASP's `real=false` rows; SASTbench's capability_safe
  cases).
- **`vulnerable_regions`** (SASTbench only) — region-level ground truth: each
  region has `id`, `path`, `start`, `end`, `label` (`vulnerable` or
  `capability_safe`), `accepted_kinds` (vulnerable), `capability` +
  `required_guards` (capability_safe). When present, the matcher uses
  region-level overlap instead of file-level matching.
- **`vcs.checked_out`** = `false` + `meta.source_missing` = `true` when the
  source isn't materialized locally yet (the fetch step fixes this).

### Per-benchmark ground-truth granularity

| Benchmark | Ground-truth granularity | CWE? | FP traps? |
|---|---|---|---|
| OWASP | file-level + FP traps (`real=false` rows) | yes (per-row `cwe` column) | **yes** (unique) |
| bountytasks | file-level (`patch` dict) | yes | no |
| CWE-Bench | method-level (`fix_info.csv`) | yes | no |
| CyberGym | file-level (`patch.diff`) | **no** (`CWE-UNKNOWN`) | no |
| SASTbench | region-level (`vulnerable_regions`) | yes (canonical kind → primary CWE) | **yes** (capability-safe regions) |

OWASP and SASTbench have FP traps, so FPR / Capability FP Rate are defined for
them. For the other benchmarks, precision is reported instead and FPR is `n/a`.

## The matching rules (§5)

For each task, `sast_eval/matching/matcher.py` classifies every SARIF finding:

```
location_hit(f)  := normalize(f.file) in task.vulnerable_files
                    (or, if vulnerable_methods exist:
                     f.file == m.file AND (method-identity or line-range overlap))
                    (or, if vulnerable_regions exist:
                     f.file matches region.path AND line-range overlap)
category_hit(f) := cwe_matches(f.cwe, task.cwe)
                   (or, for regions: finding CWE maps to region.accepted_kinds)

TP  := location_hit AND category_hit
FP  := NOT (location_hit AND category_hit)   # includes right-file-wrong-CWE
FN  := ground-truth vuln with no TP finding against it
```

Special cases:
- **FP traps** (OWASP `real=false`; SASTbench capability_safe cases): any
  finding in the test-case file / capability-safe region is a FP, regardless of
  CWE. SASTbench tracks these as `capability_fp` separately from generic FPs.
- **ground_truth_incomplete** (bountytasks, empty patch dict): excluded from
  TP/FP/FN; reported separately.
- **CWE-UNKNOWN ground truth** (CyberGym): no CWE to match against, so
  `category_hit` is vacuously true — scoring is location-only. A finding in a
  file touched by `patch.diff` is a TP; any other finding is a FP. This is a
  static-analysis proxy, not CyberGym's canonical PoC-crash metric.
- **Region-level matching** (SASTbench): when `vulnerable_regions` is present,
  `location_hit` uses file match + line-range overlap against each region, and
  `category_hit` checks the finding's CWE against the region's `accepted_kinds`
  (via the canonical-kind → CWE map). FN is counted per vulnerable region with
  no TP finding. Findings overlapping a `capability_safe` region are counted as
  `capability_fp` (a SASTbench-specific FP bucket).
- **Path suffix matching**: SARIF paths may carry the tarball's top-level dir
  prefix (e.g. CyberGym reports `file/src/funcs.c` for ground-truth
  `src/funcs.c`; SASTbench tarballs package under `sastbench__<id>/`). The
  matcher tries exact match first, then suffix match.

CWE equivalence is symmetric via `sast_eval/matching/cwe_map.json` (§2.2):
`cwe_matches(a, b)` is true if `a == b`, or `b` is in `a`'s equivalence class,
or `a` is in `b`'s class. For example, `CWE-22 ↔ {23, 36, 29, 73}`.

## The scorecard (§6)

`sast_eval/scoring/metrics.py` renders `reports/scorecard.md` with these sections per
tool:

1. **Headline table** — per benchmark + combined (common CWE core): tasks, TP,
   FP, FN, recall, precision, F1, FPR, score (TPR−FPR).
2. **Per-CWE breakdown** — common core (CWE-022, 078, 079, 094) + any other CWEs
   present. `CWE-UNKNOWN` is excluded so CyberGym doesn't pollute this table.
3. **Benchmark-specific metrics**:
   - OWASP: per-category TPR/FPR scorecard (comparable with published OWASP
     scorecards).
   - bountytasks: $-weighted recall (sum bounty found / sum bounty all).
   - CWE-Bench: method-level vs file-level recall (localization delta).
   - CyberGym: per-project recall/precision/solved (location-only).
   - SASTbench: Target Hit Rate (region-level recall), Capability FP Rate,
     Mixed-Intent Accuracy, Agentic Score (geometric mean).
4. **Efficiency metrics** — findings per task per benchmark.
5. **Excluded-tasks audit** — incomplete ground truth, source-missing,
  unvalidated bounties (always reported, never silently dropped).
6. **Imported metrics** — science-team runner results, verbatim, under their
   own names with `source: science-team-runner`.
7. **Caveats** (§8) — FP measurement asymmetry, patch-derived ground truth,
   line drift, synthetic data, CyberGym location-only, SASTbench region-level +
   capability-safe semantics, language coverage.

### The common CWE core (§6.5)

The combined row in the headline table is computed **only** over CWE classes
present in all CWE-bearing benchmarks: `CWE-022, CWE-078, CWE-079, CWE-094`.
This avoids mixing incomparable task populations. CyberGym's `CWE-UNKNOWN`
tasks are excluded from the combined number (they appear only in the CyberGym
row and the per-project breakdown). SASTbench's six canonical kinds map to
CWE-078, 022, 918, 287, 862, 089 — only CWE-022 and CWE-078 overlap the common
core, so SASTbench contributes to the combined number only via those two CWEs.

## Provenance and unit labels (§9.5)

Every table in the scorecard carries a `unit:` label:
`unit: system | model:<harness-version> | harness:<tool>`. Numbers without a
unit label are invalid. Imported metrics carry `source: science-team-runner`
and are never blended with this harness's metrics.

Cross-benchmark claims are blocked until `reports/equivalence_report.md`
exists and is co-signed (§12.3).
