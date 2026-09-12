# Adding a New Benchmark

This guide shows how to add a new vulnerability benchmark to the harness:
register the corpus, generate task records in the common format (§2), and
materialize per-task `.tar.gz` codebases for SAST analysis.

The harness distinguishes two kinds of connectors (§0):

| Connector | When to use | Owns matching/scoring? |
|---|---|---|
| **Adapter** (`adapters/`) | You run the SAST end-to-end yourself | **Yes** — this repo |
| **Importer** (`importers/`) | A science team's runner is canonical; you only ingest their results | **No** — their runner |

OWASP and SASTbench are adapters. bountytasks, CWE-Bench, and CyberGym are
importers. Pick the row that matches your new benchmark.

---

## 1. Register the corpus

Clone the benchmark repo at the workspace root (sibling of `sast-eval/`) and
symlink it into `corpus/`:

```bash
# 1a. Clone at workspace root
cd /Users/theoguidoux/ws
git clone <your-benchmark-repo> MyBenchmark

# 1b. Symlink into the harness corpus
cd sast-eval
ln -s /Users/theoguidoux/ws/MyBenchmark corpus/MyBenchmark
```

The symlink keeps the repo out of git (it's in `.gitignore`) while letting the
harness reference it by a stable relative path.

---

## 2. Write the connector

Create one module under `adapters/` (end-to-end) or `importers/` (ingest-only).
Either way it must emit **one JSONL line per task** matching the §2 schema.

### 2.1 The task schema (§2)

Every task record has this shape (required fields in **bold**):

```jsonc
{
  "task_id": "mybench/MyTask-001",          // unique, "<benchmark>/<id>"
  "benchmark": "mybench",                   // short lowercase id
  "language": "java",                       // java|python|javascript|...
  "source_root": "/abs/path/to/source",     // what the SAST scans
  "vcs": {
    "type": "git",
    "commit": "<sha-or-empty>",             // the buggy/vulnerable commit
    "checked_out": true                     // is source materialized locally?
  },
  "ground_truth": {
    "cwe": "CWE-089",                        // canonical, via normalize_cwe()
    "cwe_raw": "89",                         // original string from the benchmark
    "cve": "CVE-2024-1234",                  // or null
    "vulnerable_files": ["path/relative/to/source_root"],
    "vulnerable_methods": [],               // [] if file-level only
    "vulnerable_regions": [],               // [] unless region-level (SASTbench)
    "fp_trap": false,                        // true => zero findings expected
    "notes": "anything benchmark-specific"
  },
  "weights": {},                            // severity, bounty, etc. (or {})
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
  is a false positive (OWASP's `real=false` rows; SASTbench's `capability_safe`
  cases).
- **`vulnerable_regions`** (SASTbench only) — region-level ground truth. Each
  region has `id`, `path`, `start`, `end`, `label` (`vulnerable` or
  `capability_safe`), `accepted_kinds` (vulnerable), `capability` +
  `required_guards` (capability_safe). When present, the matcher uses
  region-level overlap instead of file-level matching.
- **`vcs.checked_out`** = `false` + `meta.source_missing` = `true` when the
  source isn't materialized locally yet (the fetch step fixes this).

### 2.2 Adapter example (end-to-end)

Model your adapter on [sast_eval/adapters/owasp_adapter.py](../sast_eval/adapters/owasp_adapter.py).
Minimal skeleton:

```python
"""MyBenchmark adapter — end-to-end (this repo owns matching/scoring)."""
from __future__ import annotations
import argparse, json, os
from pathlib import Path
from adapters.common import normalize_cwe

def build_tasks(root: str) -> list[dict]:
    root_path = Path(root).resolve()
    tasks: list[dict] = []
    # ... iterate your benchmark's metadata (CSV, JSON, DB, ...) ...
    for row in my_metadata_rows:
        cwe_raw = row["cwe"]
        task = {
            "task_id": f"mybench/{row['id']}",
            "benchmark": "mybench",
            "language": "java",
            "source_root": str(root_path),
            "vcs": {"type": "git", "commit": "", "checked_out": True},
            "ground_truth": {
                "cwe": normalize_cwe(cwe_raw),
                "cwe_raw": cwe_raw,
                "cve": row.get("cve"),
                "vulnerable_files": [row["file"]],
                "vulnerable_methods": [],
                "fp_trap": row.get("is_fp_trap", False),
                "notes": "",
            },
            "weights": {},
            "meta": {},
        }
        tasks.append(task)
    return tasks

def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    tasks = build_tasks(args.root)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        for t in tasks:
            f.write(json.dumps(t, ensure_ascii=False, sort_keys=True) + "\n")
    print(f"Wrote {len(tasks)} mybench task records to {args.out}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
```

#### Region-level adapter (SASTbench pattern)

If your benchmark annotates ground truth as **line regions** (not whole files),
populate `ground_truth.vulnerable_regions` instead of (or alongside)
`vulnerable_files`. Model your adapter on
[sast_eval/adapters/sastbench_adapter.py](../sast_eval/adapters/sastbench_adapter.py). Each region:

```jsonc
{
  "id": "R1",
  "path": "sast_eval/tools/clinical_fetcher.py",   // relative to source_root
  "start": 12, "end": 34,                 // 1-based, inclusive
  "label": "vulnerable",                  // or "capability_safe"
  "accepted_kinds": ["command_injection"],// vulnerable regions only
  "capability": "code_execution",         // capability_safe regions only
  "required_guards": ["allowlist"]         // capability_safe regions only
}
```

When `vulnerable_regions` is present, the matcher automatically switches to
region-level overlap (file match + line-range overlap, kind match against
`accepted_kinds`) — no matcher code changes needed. Set `fp_trap=true` for
cases that are entirely capability-safe (no vulnerable regions). See
[SASTBENCH_INTEGRATION.md](SASTBENCH_INTEGRATION.md) for the full design.

### 2.3 Importer example (ingest-only)

Model your importer on [sast_eval/importers/bountytasks_importer.py](../sast_eval/importers/bountytasks_importer.py)
or [sast_eval/importers/cwebench_importer.py](../sast_eval/importers/cwebench_importer.py). An
importer does two things:

1. **Builds task records** from the benchmark's metadata (same schema as above).
2. **Imports the science team's runner results verbatim** into
   `imported/<benchmark>.jsonl` — never recomputed. Each imported record
   carries provenance: `source: "science-team-runner"`, `runner_version`,
   `result_file_hash`.

The importer takes `--tasks-out` and `--imported-out`. If the science team's
result files aren't available yet, emit an empty `imported/*.jsonl` and flag
the format in [importers/FORMATS.md](../sast_eval/importers/FORMATS.md) (§12.1 inventory,
pending sign-off).

### 2.4 Conventions

- **Determinism**: write with `json.dumps(..., sort_keys=True)` so re-runs are
  byte-identical (acceptance #8).
- **CWE equivalence**: if your benchmark uses CWE aliases, add them to
  [sast_eval/matching/cwe_map.json](../sast_eval/matching/cwe_map.json) (§2.2).
- **Provenance**: add your corpus commit hash to [PROVENANCE.md](../PROVENANCE.md).

---

## 3. Wire the connector into the Makefile

Add a `build-<benchmark>` target and hook it into `build`:

```makefile
build-mybench:
	@mkdir -p $(TASKS)
	$(PY) -m adapters.mybench_adapter \
		--root $(CORPUS)/MyBenchmark \
		--out $(TASKS)/mybench.jsonl

# add to the build dependency list:
build: build-owasp build-bountytasks build-cwebench build-mybench
```

For an importer, also wire `--imported-out`:

```makefile
build-mybench:
	@mkdir -p $(TASKS) $(IMPORTED)
	$(PY) -m importers.mybench_importer \
		--root $(CORPUS)/MyBenchmark \
		--tasks-out $(TASKS)/mybench.jsonl \
		--imported-out $(IMPORTED)/mybench.jsonl
```

---

## 4. Materialize the source (if needed)

If your benchmark's source isn't fully checked out (private submodules, fetched
at scan time, etc.), add a fetch function to
[sast_eval/tools/fetch_sources.py](../sast_eval/tools/fetch_sources.py) so `make fetch` materializes
it. Two patterns exist:

### 4.1 Clone a mirror at a specific commit (bountytasks pattern)

When each task's metadata carries a `vulnerable_commit` and the repo is a
submodule pointing at a public mirror:

```python
def fetch_mybench(root: Path) -> dict:
    # for each task: git clone --depth 1 <mirror_url> <codebase_dir>
    #               git fetch --depth 1 origin <commit>
    #               git checkout <commit>
```

### 4.2 Delegate to the benchmark's own fetch script (cwebench pattern)

When the benchmark repo already has a fetch script:

```python
def fetch_mybench(root: Path) -> dict:
    # for each project slug: python <root>/scripts/fetch_one.py <slug>
```

Then add your benchmark to the `fetch` target in the Makefile:

```makefile
fetch:
	$(PY) -m tools.fetch_sources \
		--bountytasks $(CORPUS)/bountytasks \
		--cwebench $(CORPUS)/cwe-bench-java \
		--mybench $(CORPUS)/MyBenchmark
```

If your source is already fully checked out (like OWASP), skip this step —
`make fetch` isn't needed.

---

## 5. Package the codebases

`make package` builds a `.tar.gz` per task at
`codebases/<benchmark>/<task_id>.tar.gz`. The packaging logic in
[sast_eval/tools/package_codebases.py](../sast_eval/tools/package_codebases.py) already handles any
benchmark that sets `source_root` correctly:

- If `meta.source_missing` is `true` or `source_root` doesn't exist → the task
  is **skipped** with a reason in `codebases/MANIFEST.json`.
- Otherwise the source tree is packaged (filtered by file extension; VCS/build
  noise excluded).

**Special case — minimal packaging**: OWASP packages only the vulnerable test
file + the shared `helpers/` package (not the whole repo) because 2056/2740 test
files reference helpers. If your benchmark needs a custom packaging strategy
(minimal subset, specific dirs, etc.), add a branch in
`package_task()` keyed on `benchmark`.

After fetch + build, re-run packaging and check the manifest:

```bash
make package
python3 -c "import json; m=json.load(open('codebases/MANIFEST.json')); print(m['summary'])"
# {'ok': 2906, 'skipped': 0, 'empty': 0}
```

---

## 6. Verify

Run the full pipeline and check the acceptance criteria:

```bash
# Single command: build tasks + fetch source + package tarballs
make

# Verify counts
wc -l tasks/*.jsonl
# 46 tasks/bountytasks.jsonl
# 120 tasks/cwebench.jsonl
# 2740 tasks/owasp.jsonl
# N tasks/mybench.jsonl

# Verify schema (all required fields present)
python3 -c "
import json
required = {'task_id','benchmark','language','source_root','vcs','ground_truth','weights','meta'}
bad = 0
for fn in ['tasks/mybench.jsonl']:
    for line in open(fn):
        t = json.loads(line)
        if required - set(t.keys()): bad += 1
print(f'bad: {bad}')
"

# Verify idempotency (byte-identical re-run)
cp tasks/mybench.jsonl /tmp/m1.jsonl
make build-mybench >/dev/null
diff -q /tmp/m1.jsonl tasks/mybench.jsonl && echo "idempotent: OK"

# Verify packaging
ls codebases/mybench/*.tar.gz | wc -l
```

---

## 7. Checklist

- [ ] Repo cloned at workspace root, symlinked into `corpus/`
- [ ] Connector written under `adapters/` or `importers/` (§2 schema, `normalize_cwe`)
- [ ] `build-<benchmark>` target added to [Makefile](../Makefile); hooked into `build`
- [ ] Fetch function added to [sast_eval/tools/fetch_sources.py](../sast_eval/tools/fetch_sources.py) if source isn't pre-checked-out
- [ ] `make` produces the right task count, 0 schema errors, idempotent output
- [ ] `make package` produces tarballs (0 skipped) with a `codebases/MANIFEST.json` entry
- [ ] CWE equivalence classes added to [sast_eval/matching/cwe_map.json](../sast_eval/matching/cwe_map.json) if needed
- [ ] Corpus commit hash recorded in [PROVENANCE.md](../PROVENANCE.md)
- [ ] If region-level: `vulnerable_regions` populated, matcher branch auto-engages; if benchmark-specific metrics needed, add a section to [sast_eval/scoring/metrics.py](../sast_eval/scoring/metrics.py) and document in [docs/SCORING.md](SCORING.md)
- [ ] Integration doc written under `docs/` (e.g. [SASTBENCH_INTEGRATION.md](SASTBENCH_INTEGRATION.md)) if the benchmark needs non-obvious scoring rationale
- [ ] Science-team result format documented in [importers/FORMATS.md](../sast_eval/importers/FORMATS.md) (importers only)
