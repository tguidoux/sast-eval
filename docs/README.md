# sast-eval documentation

| Document | What it covers |
|---|---|
| [QUICKSTART.md](QUICKSTART.md) | End-to-end walkthrough with runnable examples — install, build, run the example tool, plug in your own SAST. Start here. |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Pipeline, module ownership, the unified task schema, matching rules, scorecard structure. |
| [SCORING.md](SCORING.md) | How findings are classified (TP/FP/FN), metric definitions (recall, precision, F1, FPR, score), per-benchmark metrics, caveats. |
| [EXPLOIT_VALIDATION.md](EXPLOIT_VALIDATION.md) | The 4-tier exploit-validation oracle (§10): Tier 0 static → Tier 1 reachability → Tier 2 canary → Tier 3 full exploit, outcome buckets, per-benchmark oracle availability, confirmed-precision metric. |
| [CYBERGYM_INTEGRATION.md](CYBERGYM_INTEGRATION.md) | How CyberGym — a non-SAST, fuzzer-based benchmark — was made compatible with the SAST scoring pipeline as a location-only proxy. |
| [SASTBENCH_INTEGRATION.md](SASTBENCH_INTEGRATION.md) | How SASTbench — region-level ground truth with capability-safe FP traps — was integrated as the second end-to-end adapter. |
| [ADDING_A_BENCHMARK.md](ADDING_A_BENCHMARK.md) | Step-by-step guide to adding a new benchmark: registering the corpus, writing an adapter/importer, materializing source, packaging. |

## Also relevant

- [../EVAL_SPEC.md](../EVAL_SPEC.md) — the full specification (§0–§12).
- [../README.md](../README.md) — quick-start, layout, usage, and per-benchmark notes.
- [../PROVENANCE.md](../PROVENANCE.md) — harness version, corpus hashes, metric definitions.
- [../importers/FORMATS.md](../sast_eval/importers/FORMATS.md) — science-team runner output inventory.

## Quick orientation

The harness normalizes five vulnerability benchmarks into a single task
schema, matches SARIF tool output against ground truth, and renders a
scorecard:

```
benchmark repos ──adapters/importers──▶ tasks/*.jsonl
                                            │
              OWASP + SASTbench + delegated runs ──your SAST (SARIF)──▶ results/raw/<tool>/
                                            │
                              sast_eval/matching/matcher.py ◀── cwe_map.json
                                            │
                                     results/matched/<tool>/
                                            │
                              sast_eval/exploit/oracle.py (§10 — 4-tier oracle)
                                            │
                                     results/exploits/<tool>/
                                            │
                       sast_eval/scoring/metrics.py + imported/*.jsonl ──▶ reports/scorecard.md
```

The five benchmarks differ in what ground truth they provide:

| Benchmark | Ground truth | CWE? | FP traps? | Language |
|---|---|---|---|---|
| OWASP | file-level + FP traps | yes | **yes** | Java |
| bountytasks | file-level (patch) | yes | no | Python/JS |
| CWE-Bench | method-level | yes | no | Java |
| CyberGym | file-level (patch.diff) | **no** | no | C/C++ |
| SASTbench | region-level + capability-safe FP traps | yes | **yes** (region-level) | 7 langs |

OWASP and SASTbench have FP traps (so FPR / Capability FP Rate are defined for
them). CyberGym has no CWE ground truth (so scoring is location-only — see
[CYBERGYM_INTEGRATION.md](CYBERGYM_INTEGRATION.md)). SASTbench's FP traps are
region-level (capability-safe regions) — see
[SASTBENCH_INTEGRATION.md](SASTBENCH_INTEGRATION.md).
