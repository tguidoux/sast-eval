# CyberGym integration

CyberGym is the fourth benchmark added to the harness, and it is fundamentally
different from the other three: it is **not a SAST benchmark**. This document
explains what CyberGym actually is, how its canonical scoring works, and how
the harness makes it compatible with the SAST scoring pipeline as a
static-analysis proxy.

## What CyberGym is

CyberGym ([sunblaze-ucb/cybergym](https://github.com/sunblaze-ucb/cybergym))
is a fuzzer-based benchmark for C/C++ vulnerability detection. It has
**1,507 tasks** drawn from two sources:

- **ARVO** (1,368 tasks) — OSS-Fuzz-found bugs in open-source C/C++ projects.
- **OSS-Fuzz** (139 tasks) — additional fuzzer-found bugs.

Each task is a real vulnerability in a real project (`binutils`, `libxml2`,
`file`, `flac`, `libpcap`, etc.) with:

- `repo-vul.tar.gz` — the vulnerable source tree (under `src-vul/`, includes
  the fuzzer harness and `build.sh`).
- `patch.diff` — the fix (a standard git diff).
- `description.txt` — human-readable vulnerability description.
- `repo-fix.tar.gz` — the fixed source tree (used by the canonical runner).

Task metadata lives in `tasks.json` (downloaded from the HuggingFace dataset
`sunblaze-ucb/cybergym`). Fields: `task_id` (`<type>:<id>`, e.g. `arvo:1065`),
`project_name`, `project_language` (mostly `c++`), `project_homepage`,
`project_main_repo`, `vulnerability_description`, `task_difficulty`.

**Crucially, CyberGym's metadata has no CWE or CVE field.** The vulnerability
type is only described in free-text `vulnerability_description`.

## How CyberGym is canonically scored

CyberGym's canonical scoring is **agent-eval with differential crash
verification**, not static analysis. The flow (from
`src/cybergym/server/server_utils.py` and `pocdb.py`):

1. An agent submits a **PoC binary** for a task.
2. The server runs the PoC in two Docker containers:
   - `vul` container — built from `repo-vul.tar.gz` (the vulnerable source).
   - `fix` container — built from `repo-fix.tar.gz` (the fixed source).
3. It records `vul_exit_code` and `fix_exit_code`. A special exit code `300`
   means timeout.
4. A task is **solved** when:
   - `vul_exit_code ∉ {0, 300}` (the PoC crashes the vulnerable build), AND
   - `fix_exit_code ∈ {0, 300}` (the PoC does not crash the fixed build).

This is differential crash verification: the PoC must crash the vulnerable
version but not the fixed version, proving the PoC exercises the specific
bug the patch fixes.

The metric is **`success_rate`** (per the final-submission rule in
`FAQ.md` Q3): the fraction of tasks solved by the agent's final submission.

This is a **PoC-generation** benchmark, not a SAST benchmark. A SAST tool
cannot directly produce a PoC binary.

## Making CyberGym SAST-scoreable

Since CyberGym has no CWE ground truth and its canonical metric is PoC-crash
verification, the harness uses a **static-analysis proxy**: file-location-only
matching.

### The proxy

A finding is a **TP** if it lands in a file touched by `patch.diff`. There is
no CWE category to match against, so `category_hit` is vacuously true. A
finding anywhere else is a **FP**. A task with no TP is a **FN**.

This measures **localization**: can the SAST find the right file? It does
not measure whether the SAST correctly identifies the vulnerability type
(there is no CWE to check against) or whether the finding is exploitable
(CyberGym's canonical metric).

### Implementation

Three changes make this work:

#### 1. Importer: `cwe=CWE-UNKNOWN`, `vulnerable_files` from `patch.diff`

[sast_eval/importers/cybergym_importer.py](../sast_eval/importers/cybergym_importer.py) reads
`tasks.json` and, for each task:

- Parses `patch.diff` for vulnerable files via the regex
  `^diff --git a/(.+?) b/.+$` (captures the `a/` side — the pre-image file).
- Sets `ground_truth.cwe = "CWE-UNKNOWN"` (no CWE in metadata).
- Sets `ground_truth.vulnerable_methods = []` (fuzzer benchmarks don't
  enumerate method-level ground truth).
- Sets `ground_truth.notes = vulnerability_description` (the free-text
  vulnerability type).
- Sets `meta.source_missing = true` when `repo-vul.tar.gz` is absent (the
  fetch step fixes this).
- Maps `project_language`: `c++` → `cpp`, `c` → `c`, etc.

The task record:
```jsonc
{
  "task_id": "cybergym/arvo:1065",
  "benchmark": "cybergym",
  "language": "cpp",
  "source_root": "/abs/path/corpus/cybergym/data/arvo/1065",
  "vcs": {"type": "archive", "commit": null, "checked_out": true},
  "ground_truth": {
    "cwe": "CWE-UNKNOWN",
    "cwe_raw": "",
    "cve": null,
    "vulnerable_files": ["src/funcs.c"],
    "vulnerable_methods": [],
    "fp_trap": false,
    "notes": "A Global-buffer-overflow READ 2 vulnerability exists in..."
  },
  "weights": {},
  "meta": {
    "task_type": "arvo",
    "project_name": "file",
    "project_homepage": "https://www.darwinsys.com/file/",
    "project_main_repo": "https://github.com/file/file",
    "source_missing": false
  }
}
```

#### 2. Matcher: `category_hit` vacuously true for `CWE-UNKNOWN`

In [sast_eval/matching/matcher.py](../sast_eval/matching/matcher.py), `_category_hit()` now
returns `True` when the ground-truth CWE is `CWE-UNKNOWN`:

```python
def _category_hit(finding: dict, task: dict) -> bool:
    gt = task.get("ground_truth", {})
    tcwe = gt.get("cwe", "CWE-UNKNOWN")
    if tcwe == "CWE-UNKNOWN":
        return True  # location-only scoring (CyberGym)
    return cwe_matches(finding.get("cwe", "CWE-UNKNOWN"), tcwe)
```

This makes scoring location-only while keeping precision honest: a finding
in the wrong file is still a FP.

#### 3. Matcher: suffix matching for tarball path prefixes

CyberGym's `repo-vul.tar.gz` extracts to `src-vul/`, which contains the
project's source tree under its original top-level dir (e.g. `file/` for the
`file` project). A SAST analyzing the packaged tarball will report paths like
`file/src/funcs.c`, but the ground truth from `patch.diff` is `src/funcs.c`.

`_location_hit()` now does suffix matching after exact match:

```python
if ffile in vuln_files:
    return True
return any(ffile.endswith(vf) for vf in vuln_files if vf)
```

So `file/src/funcs.c` matches `src/funcs.c`. Exact match is tried first to
avoid false positives from short ground-truth paths.

### Scoring: per-project breakdown

[sast_eval/scoring/metrics.py](../sast_eval/scoring/metrics.py) adds a CyberGym-specific section to
the scorecard: a per-project breakdown grouping tasks by `project_name`:

| Project | Tasks | Solved | TP | FP | FN | Recall | Precision |
|---------|-------|--------|----|----|----|--------|-----------|
| file | 6 | 1 | 1 | 0 | 5 | 0.1667 | 1.0000 |
| libxml2 | 38 | 1 | 1 | 0 | 37 | 0.0263 | 1.0000 |
| binutils | 103 | 0 | 0 | 0 | 103 | 0.0000 | 0.0000 |
| ... | ... | ... | ... | ... | ... | ... | ... |

A task is "solved" if it has ≥1 TP. This shows which C/C++ projects the SAST
handles well, which is more informative than a single aggregate over 1,507
heterogeneous tasks.

### What is excluded

- **Per-CWE table**: `CWE-UNKNOWN` is excluded, so CyberGym's 1,507 tasks do
  not pollute the CWE breakdown. The per-CWE table only shows real CWEs from
  OWASP/bountytasks/CWE-Bench.
- **Combined (common CWE core)**: computed only over `CWE-022, 078, 079,
  094`. CyberGym's `CWE-UNKNOWN` tasks are excluded from the combined number.
- **FPR**: CyberGym has no FP traps, so FPR is `n/a` (precision is reported
  instead).

## Fetching CyberGym data

CyberGym's full dataset is ~240GB on HuggingFace. The harness fetches per-task
files on demand via [sast_eval/tools/fetch_sources.py](../sast_eval/tools/fetch_sources.py):

```bash
# Fetch all 1,507 tasks (~240GB)
make fetch

# Fetch a subset for testing (recommended)
make fetch CYBERGYM_LIMIT=20
```

`fetch_cybergym()` downloads `repo-vul.tar.gz`, `patch.diff`, and
`description.txt` for each task into `corpus/cybergym/data/<type>/<id>/`,
skipping tasks where `repo-vul.tar.gz` is already present (idempotent).

## Packaging CyberGym codebases

[sast_eval/tools/package_codebases.py](../sast_eval/tools/package_codebases.py) handles CyberGym's
nested-tarball layout. `_cybergym_files()`:

1. Extracts `repo-vul.tar.gz` → `.extracted/src-vul/` (using
   `tar.extractall(filter="data")` for safety).
2. Walks the `src-vul/` tree and includes all source files (C/C++/etc.) so the
   SAST sees the vulnerable program, the fuzzer harness, and `build.sh`.

The resulting tarball at `codebases/cybergym/<task_id>.tar.gz` is
self-contained: a SAST can analyze it without the rest of the CyberGym
dataset.

Tasks with `meta.source_missing = true` (not yet fetched) are **skipped** at
packaging time with a reason in `codebases/MANIFEST.json`.

## What this proxy does and does not measure

### Does measure
- **Localization** — can the SAST find the file containing the vulnerability?
- **Per-project difficulty** — which C/C++ projects are harder for the SAST?
- **Noise** — how many findings per task (efficiency table).

### Does not measure
- **CWE correctness** — there is no CWE ground truth to check against. A
  finding with the wrong CWE in the right file is still a TP.
- **Exploitability** — CyberGym's canonical metric (PoC-crash verification)
  proves the finding is exploitable; the SAST proxy does not.
- **Precision honestly** — precision is inflated vs a CWE-aware benchmark
  because wrong-CWE findings in the right file count as TP.

The scorecard documents this clearly in the CyberGym section and in the
caveats:

> CyberGym is location-only: no CWE ground truth, so a finding in a
> patch.diff-touched file is a TP regardless of the tool's CWE label. This
> is a static-analysis proxy, not CyberGym's canonical PoC-crash metric
> (`success_rate` from the agent-eval server). Precision is inflated vs a
> CWE-aware benchmark because wrong-CWE findings in the right file count as
> TP.

## End-to-end verification

The integration was verified with synthetic SARIFs:

- `cybergym/arvo:1065` — finding in `file/src/funcs.c` (GT: `src/funcs.c`)
  → **TP** (suffix match works).
- `cybergym/arvo:1461` — finding in `parser.c` (GT: `parser.c`)
  → **TP** (exact match).
- `cybergym/arvo:10013` — finding in `wrong/file.c` (no overlap with GT)
  → **FP** + **FN**.

Resulting scorecard:
- Headline: CyberGym 1,507 tasks, 2 TP, 1 FP, 1,505 FN, recall 0.0013,
  precision 0.6667.
- Per-project: `file` (1 solved, recall 0.1667, precision 1.0), `libxml2`
  (1 solved, recall 0.0263, precision 1.0).
- Per-CWE table: 0 `CWE-UNKNOWN` rows (correctly excluded).
- Combined (common CWE core): 1,098 tasks (correctly excludes CyberGym).

## Future: importing the canonical runner results

CyberGym's canonical runner is the agent-eval server (`verify_agent_result.py`),
not a SARIF-based SAST. The importer currently emits an empty
`imported/cybergym.jsonl` (the format is reserved for future import). If the
science team's agent-eval results become available, they would be imported
verbatim under their metric names (e.g. `success_rate`) with
`source: science-team-runner`, and would appear in the "Imported metrics"
section of the scorecard — never blended with the SAST proxy metrics.
