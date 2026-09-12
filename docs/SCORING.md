# Scoring methodology

This document explains how the harness scores SAST findings against ground
truth across the five benchmarks, how the metrics are defined, and why each
benchmark needs a slightly different treatment. It is a companion to
`EVAL_SPEC.md` §5 (matching) and §6 (metrics), and to the implementation in
[sast_eval/matching/matcher.py](../sast_eval/matching/matcher.py) and
[sast_eval/scoring/metrics.py](../sast_eval/scoring/metrics.py).

## The core classification (§5)

For each task, every SARIF finding from the tool is classified as TP, FP, or
contributes to FN:

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

- **`location_hit`** — the finding is in a file (or method, or region) the
  ground truth says is vulnerable. Path comparison normalizes separators and
  strips leading `./`, then falls back to **suffix matching** so SARIF paths
  carrying a tarball's top-level dir prefix (e.g. `file/src/funcs.c`, or
  SASTbench's `sastbench__<id>/tools/foo.py`) still match ground-truth paths
  (e.g. `src/funcs.c`, `sast_eval/tools/foo.py`).
- **`category_hit`** — the finding's CWE matches the ground-truth CWE under
  the symmetric equivalence classes in
  [sast_eval/matching/cwe_map.json](../sast_eval/matching/cwe_map.json). `cwe_matches(a, b)` is
  true if `a == b`, or `b` is in `a`'s class, or `a` is in `b`'s class. For
  SASTbench regions, the finding's CWE is mapped back to a canonical kind and
  checked against the region's `accepted_kinds`.
- **FN** — the task has a ground-truth vulnerability but no finding was
  classified as TP against it. One TP is enough to clear the FN (duplicate TPs
  on the same ground truth count once for recall; each still counts toward
  precision's denominator). For SASTbench, FN is counted **per vulnerable
  region** with no TP finding.

### Special cases

| Case | Benchmark | Rule |
|---|---|---|
| FP trap | OWASP (`real=false`); SASTbench (`capability_safe`) | Any finding in the test-case file / capability-safe region is a FP, regardless of CWE. SASTbench tracks these as `capability_fp`. |
| ground_truth_incomplete | bountytasks (empty `patch` dict) | Excluded from TP/FP/FN; reported separately as "detected-CWE-only". |
| CWE-UNKNOWN ground truth | CyberGym | `category_hit` is vacuously true — scoring is location-only. |
| Method-identity | CWE-Bench | File + method name/signature match first; line-range overlap is secondary (line drift on the buggy commit). |
| Region-level | SASTbench | File + line-range overlap against `vulnerable_regions`; kind match against `accepted_kinds`; per-region FN; capability-safe overlaps → `capability_fp`. |

## Headline metrics (§6.1)

The headline table reports, per benchmark and combined:

| Metric | Definition | Notes |
|---|---|---|
| **Recall** | TP / (TP + FN) | Fraction of ground-truth vulns found. |
| **Precision** | TP / (TP + FP) | Fraction of findings that were real. |
| **F1** | 2·P·R / (P + R) | Harmonic mean. |
| **FPR** | FP / (FP + TN) | **Only defined where FP traps exist (OWASP).** TN = FP-trap tasks with zero findings. `n/a` otherwise. |
| **Score** | TPR − FPR | OWASP-style score. `n/a` when FPR is undefined. |

### Why FPR is OWASP-only (and what SASTbench uses instead)

FPR (false-positive rate) requires true negatives: tasks where the ground
truth is *zero findings*. Only OWASP has these (`real=false` rows are FP
traps). For bountytasks, CWE-Bench, and CyberGym, there are no true-negative
tasks, so FPR is undefined and precision is reported instead.

SASTbench *does* have FP traps (its `capability_safe` cases), but its canonical
metric is not FPR — it's the **Capability FP Rate**: the fraction of
capability-safe cases that the scanner flagged at all. This is a stricter
notion than OWASP FPR because it measures whether the scanner can distinguish
*guarded* dangerous code (which it should not flag) from *unguarded*
vulnerabilities (which it should). See §SASTbench-specific metrics below.

This is the FP measurement asymmetry (§8): for benchmarks without FP traps,
precision is computed against findings outside the known vuln, which
conflates FPs with undetected other real bugs. Only OWASP precision and
SASTbench Capability FP Rate are clean FP signals.

## Per-CWE breakdown (§6.2)

The per-CWE table breaks down TP/FP/FN/recall/precision by ground-truth CWE.
It shows the **common core** (CWE-022, 078, 079, 094) first, then any other
CWEs present in the data, sorted.

`CWE-UNKNOWN` is **excluded** from this table. This is important: CyberGym's
1,507 tasks all have `cwe=CWE-UNKNOWN`. If they were included, the table would
be dominated by a single `CWE-UNKNOWN` row that is meaningless for CWE
comparison. CyberGym is scored in its own headline row and per-project
breakdown instead.

## Combined reporting (§6.5)

The "Combined (common CWE core)" row in the headline table is computed
**only** over CWE classes present in all CWE-bearing benchmarks:
`CWE-022, CWE-078, CWE-079, CWE-094`. This avoids mixing incomparable task
populations.

Because CyberGym has `CWE-UNKNOWN`, its tasks are excluded from the combined
number. The combined row covers OWASP + bountytasks + CWE-Bench tasks whose
CWE is in the common core (or matches one via the equivalence classes).

## Benchmark-specific metrics (§6.3)

Each benchmark has a section that captures what is unique about it:

### OWASP — per-category scorecard

OWASP groups test cases into categories (path traversal, command injection,
XSS, etc.). The per-category scorecard reports TPR, FPR, and score per
category, comparable with published OWASP Benchmark scorecards. This is one of
two benchmarks with FP traps, so per-category FPR is meaningful.

### bountytasks — $-weighted recall

bountytasks tasks carry a `disclosure_bounty_usd` weight. The $-weighted
recall is:

```
$-weighted recall = sum(bounty(found)) / sum(bounty(all))
```

where `found` means the task had ≥1 TP. This weights recall by economic
severity: finding a $50,000 bounty matters more than finding a $500 one.

### CWE-Bench — method-vs-file recall

CWE-Bench is the only benchmark with method-level ground truth. The
method-vs-file section reports:

- **Method-level recall**: TP / total methods (the headline recall for
  CWE-Bench, using method-identity matching).
- **File-level recall**: fraction of tasks where any finding landed in a
  vulnerable file (broader, file-only matching).
- **Localization delta** (file − method): how much recall improves when you
  relax from method-precision to file-precision. A large delta means the tool
  finds the right file but not the right method.

### CyberGym — per-project recall/precision

CyberGym has no CWE ground truth, so scoring is **location-only**: a finding
in a file touched by `patch.diff` is a TP. The per-project breakdown groups
CyberGym's 1,507 tasks by `project_name` (e.g. `binutils`, `libxml2`,
`file`) and reports per-project tasks, solved, TP, FP, FN, recall, and
precision.

A task is "solved" if it has ≥1 TP. This is a static-analysis proxy — it
measures whether the SAST localized the vulnerable file — and is **not**
CyberGym's canonical metric (see [CYBERGYM_INTEGRATION.md](CYBERGYM_INTEGRATION.md)).

### SASTbench — agentic-codebase metrics

SASTbench is the only benchmark with **region-level** ground truth and
**capability-safe** FP traps. Its scorecard section reports four metrics,
mirroring SASTbench's own `scripts/scoring.py` (see
[SASTBENCH_INTEGRATION.md](SASTBENCH_INTEGRATION.md) for the full rationale):

| Metric | Definition |
|---|---|
| **Target Hit Rate** | Region-level recall: vulnerable regions with ≥1 TP / total vulnerable regions. |
| **Precision** | TP / (TP + FP), where FP includes findings outside any vulnerable region and findings overlapping capability-safe regions (`capability_fp`). |
| **Capability FP Rate** | Fraction of capability-safe cases the scanner flagged at all. A scanner that flags guarded dangerous code (e.g. `subprocess.run` behind an allowlist) has a high rate. |
| **Mixed-Intent Accuracy** | Fraction of mixed-intent cases (one capability-safe + one vulnerable region) where the scanner got it perfectly right: ≥1 TP on the vulnerable region AND 0 `capability_fp`. |
| **Agentic Score** | `geometric_mean(target_hit_rate, 1 − capability_fp_rate, mixed_intent_accuracy)` — SASTbench's headline number for the agentic profile. |

The agentic score rewards scanners that both detect unguarded vulnerabilities
*and* refrain from flagging guarded capabilities — the core SASTbench
hypothesis. A scanner that flags every dangerous API call will have high
target hit rate but a capability FP rate near 1, collapsing the geometric
mean.

## Efficiency metrics (§6.4)

The efficiency table reports findings per task per benchmark:

| Benchmark | Tasks | Findings | Avg findings/task |
|---|---|---|---|
| OWASP | … | … | … |
| bountytasks | … | … | … |
| CWE-Bench | … | … | … |
| CyberGym | … | … | … |
| SASTbench | … | … | … |

This is a noise indicator: a tool that emits 10× more findings for the same
recall is harder to triage.

## Excluded-tasks audit

The scorecard always reports (never silently drops) tasks that are excluded
from the headline metrics:

- **Incomplete ground truth** (bountytasks, empty `patch` dict) — excluded
  from TP/FP/FN because there is no vulnerable file to match against.
- **Source missing** (codebase not checked out / not downloaded) — the task
  is skipped at packaging time; the matcher produces all-FN. CyberGym tasks
  that weren't fetched from HuggingFace appear here.
- **Unvalidated bounties** (bountytasks, `run_ci_local.sh` not run) — the
  bounty hasn't been confirmed reproducible.

If the source-missing list is long (>20), only the first 20 are shown with a
count.

## Imported metrics (science-team runner)

Imported metrics appear under their own names with
`source: science-team-runner` and are **never blended** with this harness's
metrics. The importer emits them verbatim from the science team's runner
output into `imported/<benchmark>.jsonl`.

Currently:
- `imported/bountytasks.jsonl` — 0 records (format pending confirmation, see
  [importers/FORMATS.md](../sast_eval/importers/FORMATS.md)).
- `imported/cwebench.jsonl` — 0 records.
- `imported/cybergym.jsonl` — 0 records (CyberGym's canonical runner is the
  agent-eval server, not a SARIF-based SAST; import is reserved for future).

## Caveats (§8)

The scorecard documents these caveats explicitly:

1. **FP measurement asymmetry** — only OWASP and SASTbench have true-negative
   tasks (OWASP `real=false` rows; SASTbench `capability_safe` cases). For
   bountytasks/CWE-Bench/CyberGym, precision conflates FPs with undetected
   other real bugs.
2. **bountytasks ground truth is patch-derived** — the fix commit may touch
   files for unrelated reasons (refactors, tests).
3. **CWE-Bench line drift** — `method_start/end` refer to the fixed commit;
   the matcher uses method-identity first, line ranges second.
4. **OWASP is synthetic** — 2,740 tiny servlets; recall does not predict
   recall on real codebases. That is why the combined eval exists.
5. **CyberGym is location-only** — no CWE ground truth, so a finding in a
   `patch.diff`-touched file is a TP regardless of the tool's CWE label. This
   is a static-analysis proxy, not CyberGym's canonical PoC-crash metric
   (`success_rate`). Precision is inflated vs a CWE-aware benchmark because
   wrong-CWE findings in the right file count as TP.
6. **SASTbench is region-level + capability-aware** — ground truth is
   line-region annotations, not whole files. A finding must overlap a
   vulnerable region *and* match its `accepted_kinds` to be a TP. Findings
   overlapping a `capability_safe` region are `capability_fp`, a distinct FP
   bucket from generic FPs. The agentic score is a geometric mean, so a
   scanner that flags every dangerous API (high capability FP rate) scores
   poorly even with perfect recall. Full Track cases (189) require
   `scripts/setup_repos.py` to be run in the sast-bench repo; until then they
   are `source_missing`.
7. **Language coverage** — bountytasks is mostly Python/JS; the Java
   benchmarks are Java-only; CyberGym is C/C++; SASTbench spans 7 languages
   (Python, JS/TS, Go, Rust, Java, Clojure, Swift). Combined numbers only make
   sense per-language for single-language tools.
