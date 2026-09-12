# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
