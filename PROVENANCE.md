# PROVENANCE

Every reported number must be labeled with its provenance. Historical numbers
remain valid under their original provenance; the unified scorecard labels
which provenance each column carries (§12.5).

## Harness

- **Harness version:** 0.1.0
- **Spec:** `EVAL_SPEC.md` (Unified SAST Evaluation Specification)
- **Last differential test:** _pending — blocked until science-team sign-off
  on `importers/FORMATS.md` (§12.3). Cross-benchmark claims are blocked until
  `reports/equivalence_report.md` exists and is co-signed._

## Corpus (cloned benchmark repos)

The repos are symlinked into `corpus/` from the workspace root (not
re-cloned). Per §11 Step 1, nothing inside `corpus/` is ever modified.

| Benchmark | Path | Commit | Tag/describe |
|-----------|------|--------|--------------|
| bountytasks | `corpus/bountytasks` | `1956e5fd4eff12034a5fbe0544482d2cf52bb5b0` | `1956e5fd` |
| OWASP BenchmarkJava v1.2 | `corpus/BenchmarkJava` | `20cbf3d11123347e47ed89541e6942836def53f7` | `1.2beta-865-g20cbf3d11` |
| CWE-Bench-Java | `corpus/cwe-bench-java` | `afe0ebd0adc237abb46255f9cd479b1d71819136` | `archive-2025-07-09-3-gafe0ebd` |
| CyberGym | `corpus/cybergym` | _HuggingFace dataset `sunblaze-ucb/cybergym`_ | 1,507 tasks (1,368 ARVO + 139 OSS-Fuzz) |
| SASTbench | `corpus/sast-bench` | `b390f275d650bf5db674aeea59ad6dc32beae50d` | `b390f275` (no tags) |

## Task corpus (generated)

| File | Records | Source |
|------|--------|--------|
| `tasks/owasp.jsonl` | 2740 | `expectedresults-1.2.csv` (1415 real + 1325 FP-trap) |
| `tasks/bountytasks.jsonl` | 46 | `bounty_metadata.json` glob (2 incomplete ground truth, 46 source_missing) |
| `tasks/cwebench.jsonl` | 120 | `data/project_info.csv` ⋈ `data/fix_info.csv` (984 methods across 113 tasks; 7 tasks file-level only) |
| `tasks/cybergym.jsonl` | 1507 | `tasks.json` (HuggingFace `sunblaze-ucb/cybergym`); `cwe=CWE-UNKNOWN`, vulnerable files from `patch.diff` |
| `tasks/sastbench.jsonl` | 206 | `cases/*/case.json` (17 Core Track self-contained + 189 Full Track real-world; region-level ground truth) |

## Science-team runner versions (canonical for their benchmarks)

- **bountytasks runner:** `corpus/bountytasks/run_ci_local.sh` — version not
  pinned in repo; result-file format pending confirmation (see
  `importers/FORMATS.md` §1a).
- **CWE-Bench runner:** `corpus/cwe-bench-java/baselines/run_*.py` +
  `output_*_result.py` — emits `baselines/results/<tool>_result.csv`.
- **CyberGym runner:** `src/cybergym/server/` (agent-eval server,
  `verify_agent_result.py`) — PoC-crash verification, not a SAST. Result
  import reserved for future (see `importers/FORMATS.md`).
- **SASTbench runner:** `corpus/sast-bench/scripts/run.py` + `scripts/scoring.py`
  — region-level overlap matching with capability-FP classification. We mirror
  its scoring in `matching/matcher.py` and `scoring/metrics.py` rather than
  importing results, because the cases are self-contained JSON with annotated
  regions (adapter pattern, like OWASP).

## Importer / adapter versions

- `importers/bountytasks_importer.py` — v0.1.0 (task records stable; result
  import pending format confirmation).
- `importers/cwebench_importer.py` — v0.1.0 (task records stable; result
  import handles `*_result.csv` per-tool CSVs).
- `importers/cybergym_importer.py` — v0.1.0 (task records stable; `cwe=CWE-UNKNOWN`,
  location-only scoring; result import reserved — canonical runner is agent-eval).
- `adapters/sastbench_adapter.py` — v0.1.0 (task records stable; region-level
  ground truth with `vulnerable_regions`, `fp_trap` for capability_safe cases;
  no result import — we run SAST end-to-end and score with our own matcher).

## Metric definitions

- **This harness's metrics** (computed by `scoring/metrics.py`): recall, precision,
  F1, FPR (OWASP only), OWASP score (TPR−FPR), $-weighted recall, method-vs-file
  recall, CyberGym per-project recall/precision (location-only), SASTbench
  region-level metrics (Target Hit Rate, Capability FP Rate, Mixed-Intent
  Accuracy, Agentic Score), exploit-validation metrics (confirmed precision,
  §10). Definitions in `EVAL_SPEC.md` §6. Matching rules in §5, implemented in
  `matching/matcher.py`. CWE equivalence classes in `matching/cwe_map.json`
  (§2.2). Exploit-validation oracle in `exploit/oracle.py` (§10, 4-tier).
- **Imported metrics** (science team, verbatim): `detect_success_rate`
  (bountytasks, primary), raw findings (CWE-Bench), `success_rate` (CyberGym,
  reserved). Carried with `source: science-team-runner`; never blended with
  this harness's metrics.

## Unit-of-comparison labels (§9.5)

Every table in `reports/scorecard.md` carries a `unit:` field:
`unit: system | model:<harness-version> | harness:<tool>`. Numbers without a
unit label are invalid.
