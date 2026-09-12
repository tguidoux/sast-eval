# Importer formats — science team runner output inventory (§12.1, Step 2)

> **Status: DRAFT — pending science-team confirmation.** Per §12.1 rule 4,
> matching rules, CWE equivalence classes, and metric names in this spec are a
> proposal until co-signed. No importer is trusted until this document is
> confirmed and the differential test (§12.3) passes.

This document inventories the science team's existing runner output formats
for the two benchmarks they own (bountytasks, CWE-Bench-Java). The importers in
`importers/` consume these formats **read-only** and map them into the unified
matched-results format (§2) without re-running, re-matching, or re-scoring.

## 1. bountytasks (bountybench)

### 1a. Result file format and location

- **Task metadata** (used to build unified task records): `bounty_metadata.json`
  per bounty, at `<root>/<project>/bounties/bounty_<N>/bounty_metadata.json`.
  Schema: `corpus/bountytasks/bounty_metadata_schema.json`. 46 files found in
  the current corpus.
  - Fields consumed: `CWE` (normalize per §2.1), `CVE`, `vulnerable_commit`,
    `disclosure_bounty` / `patch_bounty` (parse per
    `corpus/bountytasks/calculate_bounties.py`), `patch` (dict →
    `vulnerable_files`; empty → `ground_truth_incomplete`).
  - `source_root` = `<project>/codebase` (the buggy snapshot). The `codebase/`
    submodule is frequently private/unchecked-out → `source_missing: true`.

- **Runner results** (the science team's canonical runner output): the runner
  is `corpus/bountytasks/run_ci_local.sh`. It executes the Detect / Exploit /
  Patch legs and `verify.sh` per bounty. **The exact on-disk result-file
  format the runner emits is not yet pinned in the public repo** — it prints a
  colored transcript and exits with a status code; a structured per-bounty
  result JSON (Detect/Exploit/Patch outcomes, verify.sh exit codes, timing,
  token usage) is expected but its path/schema must be confirmed by the science
  team before the importer trusts it.

### 1b. Metric names and definitions (theirs, primary)

- `detect_success_rate` — the science team's exploit-verified Detect-leg
  success rate. **Primary metric for bountytasks.** Never recomputed by this
  harness; carried verbatim with `source: science-team-runner`.
- This harness's static SARIF matching on bountytasks (if ever run) is a
  **separately-labeled** metric `static_recall` — never a replacement.

### 1c. Task identifiers

- Unified `task_id` = `bountytasks/<project>/bounty_<N>` (derived from the
  `bounty_metadata.json` path).

### 1d. Provenance already recorded

- `bounty_metadata.json` carries `bounty_link` (huntr URL), `CVE`,
  `vulnerable_commit`. The importer adds `source: science-team-runner`,
  `runner_version`, and `result_file_hash` to every imported record.

### 1e. Importer behavior until confirmed

- `importers/bountytasks_importer.py` emits task records now (metadata is
  public and stable). It emits **zero** imported result records until the
  science team provides result files and confirms the format. It fails loudly
  (not silently) on unrecognized fields per §12.2.

## 2. CWE-Bench-Java

### 2a. Result file format and location

- **Task metadata**: `data/project_info.csv` (one row per CVE, 120 rows) joined
  with `data/fix_info.csv` (one row per fixed method, 1143 rows) on
  `project_slug`. Columns:
  - `project_info.csv`: `id, project_slug, cve_id, cwe_id, cwe_name,
    github_username, github_repository_name, github_tag, github_url,
    advisory_id, buggy_commit_id, fix_commit_ids`.
  - `fix_info.csv`: `project_slug, cve_id, github_username,
    github_repository_name, commit, file, class, class_start, class_end,
    method, method_start, method_end, signature`.
  - `source_root` = `project-sources/<slug>` at `buggy_commit_id` (sources are
    fetched by `scripts/fetch_one.py`; not present in the repo by default).

- **Runner results**: the science team's baselines emit a per-tool CSV at
  `baselines/results/<tool>_result.csv` with rows
  `[project_slug, cwe, kind, message]` (see
  `corpus/cwe-bench-java/baselines/output_spotbugs_result.py`,
  `output_infer_result.py`, `output_snyk_result.py`). The runner scripts are
  `run_codeql.py`, `run_infer.py`, `run_snyk.py`, `run_spotbugs.py`.

### 2b. Metric names and definitions (theirs, primary)

- The baselines emit raw findings (not pre-computed recall/precision). The
  science team's published metric is **method-level detection** (did the tool
  report a finding inside the fixed method?). This harness's matcher computes
  method-level vs file-level recall (§6.3) from the same raw findings using
  the unified matching rules (§5) — this is the differential-test surface
  (§12.3): if our matcher reproduces their published detection numbers from
  the same raw findings, the layer is certified.

### 2c. Task identifiers

- Unified `task_id` = `cwebench/<project_slug>`.

### 2d. Provenance already recorded

- `project_info.csv` carries `buggy_commit_id`, `fix_commit_ids`, `advisory_id`,
  `github_url`. The importer adds `source: science-team-runner`,
  `runner_version`, `result_file_hash` (sha256 of the result CSV) to every
  imported record.

## 3. Round-trip / no-recompute guarantee (acceptance criterion 3)

Each importer's output must round-trip:
- Importing their result file twice yields byte-identical unified records
  (deterministic, sorted keys — modulo timestamps).
- Every metric value in the unified record equals the value in their source
  file (no recomputation). The importer carries values verbatim; it does not
  re-derive recall/precision from raw findings for imported metrics.

## 4. Open questions for the science team

1. **bountytasks runner result file**: what is the exact path and JSON schema
   of the per-bounty structured result the runner emits (Detect/Exploit/Patch
   outcomes, verify.sh exit codes, timing, token usage)?
2. **CWE-Bench metric definition**: is method-level detection defined as
   "finding inside the fixed method's line range" or "finding whose reported
   location overlaps the method signature"? (Affects line-drift handling.)
3. **CWE equivalence classes (§2.2)**: confirm the proposed classes, especially
   `CWE-22 ↔ {23,36,29,73}` and `CWE-78 ↔ {77}`, which span all three
   benchmarks.
4. **Differential-test benchmark choice (§12.3)**: which overlapping benchmark
   (bountytasks or CWE-Bench) and which shared tool should the equivalence
   proof use?
