# SASTbench integration

SASTbench is the fifth benchmark added to the harness, and the second
end-to-end adapter (after OWASP). It evaluates SAST tools on **agentic
codebases** — code where an agent intentionally calls dangerous APIs
(`subprocess.run`, `fs.writeFile`, `requests.get`) as part of its legitimate
capability. A good scanner flags these only when guards are missing; a scanner
that flags properly guarded code is penalized. This document explains what
SASTbench is, how its canonical scoring works, and how the harness integrates
it with region-level matching.

## What SASTbench is

SASTbench ([cloned at `../sast-bench`](https://github.com/sunblaze-ucb/sast-bench))
is a SAST benchmark for agentic code. It has **206 cases** across two tracks:

- **Core Track** (17 cases) — synthetic, self-contained vendored projects.
  Three case types:
  - `synthetic_vulnerable` (11) — a vulnerable region with missing guards.
  - `capability_safe` (3) — a properly guarded dangerous region; flagging it is
    a capability false positive.
  - `mixed_intent` (3) — both a capability-safe region and a vulnerable region
    in the same file; the scanner must distinguish them.
- **Full Track** (189 cases) — real-world repo snapshots at vulnerable commits.
  Two case types:
  - `real_world_disclosed` (156) — disclosed via GHSA/CVE, with knowledge-cutoff
    dates for LLM-contamination gating.
  - `real_world_generic` (33) — generic (non-agentic) real-world vulnerabilities.

Cases span 7 languages (Python, TypeScript, Rust, Clojure, Swift, Go, Java)
and 6 canonical vulnerability kinds: `command_injection`, `path_traversal`,
`ssrf`, `auth_bypass`, `authz_bypass`, `sql_injection` (see
`taxonomy/canonical_kinds.json` for CWE mappings).

Each case lives in `cases/{core,full}/<type>/<id>/case.json` and contains:

- `id`, `track`, `caseType`, `language`, `canonicalKind`.
- `files.root` — the source root relative to the case dir (Core Track:
  `project/`; Full Track: `../../../../.repos/<owner_repo>__<shortsha>/`).
- `regions` — the ground truth. Each region has:
  - `id` (e.g. `R1`), `path`, `startLine`, `endLine`.
  - `label` — `vulnerable` or `capability_safe`.
  - `acceptedKinds` (vulnerable regions) — canonical kinds that count as a match.
  - `capability` + `requiredGuards` (capability_safe regions) — the capability
    being exercised and the guards that make it safe.
- `expectedOutcome.mustDetectRegionIds` / `mustNotFlagRegionIds` — explicit
  ground truth (which vulnerable regions must be found, which capability_safe
  regions must not be flagged).
- `realWorld` (Full Track only) — `repo`, `vulnerableCommit`, `fixCommit`,
  `ghsa`, `cve`, `disclosure` (dates for knowledge-cutoff gating).

## How SASTbench is canonically scored

SASTbench's canonical scoring (`scripts/scoring.py`) is **region-level overlap
matching**:

1. A finding is a **true positive** if it overlaps a vulnerable region (file
   match + line-range overlap) AND its kind matches the region's
   `acceptedKinds`.
2. A finding is a **capability false positive** if it overlaps a capability_safe
   region with kind/capability agreement (via the `KIND_TO_CAPABILITY` map:
   `command_injection→code_execution`, `path_traversal→filesystem`,
   `ssrf→network`, `auth_bypass→authentication`, `authz_bypass→authorization`,
   `sql_injection→data_store`).
3. A finding is a **false positive** otherwise (unmatched).

Metrics (`compute_summary`):

- **recall** (Target Hit Rate) = TP / (TP + FN), region-level.
- **precision** = TP / (TP + FP).
- **capability_fp_rate** = capability_safe cases flagged / total capability_safe
  cases. A capability_safe case is "flagged" if it produced any finding that
  overlaps a capability_safe region.
- **mixed_intent_accuracy** = mixed_intent cases with 0 FN and 0 capability FP.
- **agentic_score** = geometric_mean(recall, 1 − capability_fp_rate,
  mixed_intent_accuracy) — the headline metric for agentic code.

SASTbench ships its own runner (`scripts/run.py`) and adapters for semgrep and
bandit, but the cases are self-contained JSON with annotated regions — the
ground truth is the cases, not the runner's output.

## How the harness integrates SASTbench

We integrate SASTbench as an **adapter** (like OWASP), not an importer. We own
the matching and scoring end-to-end because the cases are canonical ground
truth and we run the SAST tool ourselves.

### Adapter (`sast_eval/adapters/sastbench_adapter.py`)

Reads `cases/*/case.json` and emits one task per case. Key transformations:

- **`vulnerable_regions`** (new ground-truth field) — the regions array,
  normalized to snake_case (`accepted_kinds`, `start`, `end`, `required_guards`)
  with `label` preserved. This is the signal the matcher keys on for
  region-level matching.
- **`cwe`** — the primary CWE for the case's `canonicalKind` (first entry in
  the kind's `cweMappings`), e.g. `command_injection→CWE-078`,
  `ssrf→CWE-918`. Used for the per-CWE table and common-CWE-core filter.
- **`fp_trap`** — `true` for `capability_safe` cases (no vulnerable regions;
  any finding is a FP). `false` for `mixed_intent` (has vulnerable regions, but
  also capability_safe regions that are FP traps at the region level).
- **`source_root`** — resolved absolute path to the case's `files.root`. Core
  Track: `cases/.../project/`. Full Track: `.repos/<owner_repo>__<shortsha>/`.
- **`source_missing`** — `true` for Full Track cases until `make fetch` runs
  `scripts/setup_repos.py` to clone the real-world repos.
- **`meta`** — `track`, `case_type`, `canonical_kind`, `agentic`, `profile`,
  `repo`, `cve`, `ghsa`, disclosure dates (`ghsa_published`, `fix_commit_date`,
  `cve_published`). The scorecard uses `case_type` to compute capability_fp_rate
  and mixed_intent_accuracy.

### Matching (`sast_eval/matching/matcher.py`)

Region-level matching is the fourth matching mode, keyed on `vulnerable_regions`
presence in ground truth (alongside file-level, method-level, and CWE-UNKNOWN
vacuous). The matcher:

- **`_region_overlap_hit(finding, regions, label)`** — returns the first region
  the finding overlaps (file match: exact-then-suffix for tarball top-level dir
  prefix tolerance; line-range overlap: `finding_start <= region_end and
  finding_end >= region_start`), filtered by `label` (`vulnerable` or
  `capability_safe`).
- **`_finding_kind_matches_region(finding_cwe, region)`** — maps the finding's
  CWE to SASTbench canonical kinds (via the reverse of `KIND_TO_PRIMARY_CWE`
  plus `cwe_map` equivalence) and checks against the region's `accepted_kinds`.
  Empty `accepted_kinds` means any kind matches (location-only).
- **`classify_task`** for region-level tasks:
  - A finding is a **TP** if it overlaps a vulnerable region AND kind-matches.
  - A finding is a **FP** otherwise. If it overlaps a capability_safe region,
    it's counted as a `capability_fp` (tracked separately in `counts`).
  - **FN** = vulnerable regions with no TP finding against them (per-region,
    not per-file).
  - `counts.capability_fp` is the number of findings that hit capability_safe
    regions — used by the scorecard's Capability FP Rate.

### Scoring (`sast_eval/scoring/metrics.py`)

`_sastbench_metrics` mirrors SASTbench's `compute_summary`:

- **Target Hit Rate (recall)** — region-level TP / (TP + FN).
- **Capability FP Rate** — capability_safe cases flagged / total
  capability_safe cases (a case is "flagged" if it produced any FP).
- **Mixed-Intent Accuracy** — mixed_intent cases with 0 FN and 0 capability FP.
- **Agentic Score** — geometric mean of recall, (1 − capability_fp_rate), and
  mixed_intent_accuracy. Zero components collapse the score to 0 (matches
  SASTbench's behavior).

The SASTbench section appears in the scorecard under "Benchmark-specific
metrics" with a table of the four metrics plus the underlying counts.

### Fetching (`sast_eval/tools/fetch_sources.py`)

`fetch_sastbench` delegates to SASTbench's `scripts/setup_repos.py`, which
clones each Full Track real-world repo at its vulnerable commit into
`.repos/<owner_repo>__<shortsha>/`. Core Track cases are self-contained
(`project/` ships with the repo) and need no fetching.

### Packaging (`sast_eval/tools/package_codebases.py`)

SASTbench packages the `source_root` tree (Core Track `project/` or Full Track
`.repos/<snapshot>/`) with `SOURCE_EXTS`, which includes `.clj`/`.cljs`/`.cljc`/`.edn`
(Clojure) and `.swift` for SASTbench's 7 languages. Region paths are relative
to the source root, so the tarball's top-level dir prefix (`<task_id>/`) is
tolerated by the matcher's suffix-match.

## Why an adapter, not an importer

SASTbench has its own runner (`scripts/run.py`) and scoring (`scripts/scoring.py`),
but the cases are self-contained JSON with annotated regions. The ground truth
is the cases themselves, not the runner's output. We run the SAST tool
end-to-end (like OWASP) and score with our own matcher, because:

1. The cases are the canonical ground truth — there's no "science-team runner
   output" to import.
2. Region-level matching is a new mode the harness needs to own (the other
   benchmarks use file-level or method-level).
3. The capability-FP concept (flagging guarded code) is unique to SASTbench and
   requires `counts.capability_fp` in the matcher, which an importer couldn't
   provide without reimplementing the same logic.

## Knowledge-cutoff gating (not implemented)

SASTbench gates real-world cases by LLM knowledge cutoff to avoid contamination:
a case counts for a model only if its disclosure horizon (min of
`ghsa_published`, `fix_commit_date`, `cve_published`) is after the model's
training cutoff. The adapter carries these dates in `meta.disclosure_*`, but
the harness does not implement gating — that's SASTbench's runner concern.
The scorecard reports over all cases regardless of cutoff; a model-specific
view would filter by `meta.disclosure_*` against the model's cutoff date.

## OWASP Agentic Top 10 crosswalk

SASTbench's canonical kinds map to the OWASP Agentic Top 10 (see the SASTbench
README). The harness does not render this crosswalk; it's informational for
interpreting SASTbench results in the context of agentic-security guidance.
