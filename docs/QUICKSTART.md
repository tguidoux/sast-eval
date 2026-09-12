# Quickstart

End-to-end walkthrough with runnable examples. In ~5 minutes you'll have the
full pipeline running against a fake tool (`exampletool`), then learn the
two-file contract to plug in your own real SAST tool.

> **Prerequisites:** Python 3.10+, `uv` (or `pip`), and the five benchmark
> repos cloned and symlinked into `corpus/`. See the [main README](../README.md)
> for corpus setup.

---

## 1. Install

```bash
# from this repo (editable, with uv)
uv sync

# or with pip
pip install -e .

# or from PyPI (when published)
pip install sast-eval
```

Verify the CLI is available. With `uv`, prefix commands with `uv run`:

```bash
uv run sast-eval --help
```

With a plain `pip install` (no `uv`), `sast-eval` is on your PATH directly:

```bash
sast-eval --help
```

You should see seven subcommands: `build`, `fetch`, `package`, `match`,
`exploit`, `score`, `all`. (The examples below use the bare `sast-eval` form —
add `uv run ` in front if you installed with `uv`.)

---

## 2. Build the ground-truth tasks

This normalizes all five benchmarks into a single task schema (`tasks/*.jsonl`):

```bash
sast-eval build
```

Expected output:

```
Wrote 2740 OWASP task records to tasks/owasp.jsonl
Wrote 46 bountytasks task records to tasks/bountytasks.jsonl
Wrote 120 CWE-Bench task records to tasks/cwebench.jsonl
Wrote 1507 CyberGym task records to tasks/cybergym.jsonl
Wrote 206 SASTbench task records to tasks/sastbench.jsonl
```

Each line in `tasks/<bench>.jsonl` is one task. A task record tells you **what
to analyze** (`source_root`) and **what the ground truth is** (`ground_truth`).
For example, an OWASP task:

```json
{
  "task_id": "owasp/BenchmarkTest00001",
  "benchmark": "owasp",
  "language": "java",
  "source_root": "/path/to/BenchmarkJava",
  "ground_truth": {
    "cwe": "CWE-022",
    "vulnerable_files": [
      "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00001.java"
    ],
    "vulnerable_methods": [],
    "fp_trap": false
  }
}
```

---

## 3. (Optional) Materialize per-task source tarballs

If your SAST tool analyzes self-contained source trees rather than a full repo,
build one `.tar.gz` per task:

```bash
sast-eval fetch --cybergym-limit 20   # fetch/checkout source for packaging
sast-eval package                      # → codebases/<bench>/<task_id>.tar.gz
```

This produces `codebases/<benchmark>/<task_id with / → __>.tar.gz` plus a
`codebases/MANIFEST.json` listing every tarball, its file count, and byte size.
Point your tool at each tarball (or at `source_root` directly — either works).

---

## 4. Run the example tool (no real SAST needed)

`tools/exampletool/` ships a fake SAST tool with hand-crafted SARIF for one
task per benchmark. It exercises every branch of the matcher (TP, plain FP,
capability FP) so you can see the full pipeline run without installing a real
tool.

The example tool consists of exactly two things:

**A. A rule→CWE map** — [`tools/exampletool/rules.json`](../tools/exampletool/rules.json):

```json
{
  "EXAMPLE-CMD-INJECTION": "CWE-078",
  "EXAMPLE-PATH-TRAVERSAL": "CWE-022",
  "EXAMPLE-SSRF": "CWE-918",
  "EXAMPLE-SQL-INJECTION": "CWE-089",
  "EXAMPLE-XSS": "CWE-079",
  "EXAMPLE-INPUT-VALIDATION": "CWE-020",
  "EXAMPLE-DESERIALIZATION": "CWE-502",
  "EXAMPLE-BAD-CWE": "CWE-999"
}
```

**B. One SARIF file per task** in `results/raw/exampletool/`. For example,
[`results/raw/exampletool/owasp__BenchmarkTest00001.sarif`](../results/raw/exampletool/owasp__BenchmarkTest00001.sarif)
contains three findings — one true positive and two deliberate false positives:

```json
{
  "version": "2.1.0",
  "runs": [{
    "tool": { "driver": { "name": "exampletool", "rules": [
      {"id": "EXAMPLE-PATH-TRAVERSAL"},
      {"id": "EXAMPLE-XSS"}
    ]}},
    "results": [
      {
        "ruleId": "EXAMPLE-PATH-TRAVERSAL",
        "locations": [{
          "physicalLocation": {
            "artifactLocation": {"uri": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00001.java"},
            "region": {"startLine": 45}
          }
        }]
      },
      {
        "ruleId": "EXAMPLE-XSS",
        "locations": [{
          "physicalLocation": {
            "artifactLocation": {"uri": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00001.java"},
            "region": {"startLine": 50}
          }
        }]
      },
      {
        "ruleId": "EXAMPLE-PATH-TRAVERSAL",
        "locations": [{
          "physicalLocation": {
            "artifactLocation": {"uri": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00002.java"},
            "region": {"startLine": 12}
          }
        }]
      }
    ]
  }]
}
```

Against the OWASP ground truth (CWE-022 in `BenchmarkTest00001.java`):
- Finding 1 → **TP** (right file + right CWE via `EXAMPLE-PATH-TRAVERSAL` → CWE-022)
- Finding 2 → **FP** (right file, wrong CWE: XSS ≠ CWE-022)
- Finding 3 → **FP** (right CWE, wrong file)

Now run the three scoring stages:

```bash
sast-eval match   --tool exampletool
sast-eval exploit --tool exampletool
sast-eval score   --tool exampletool
```

Output:

```
Matched 4619 tasks for tool 'exampletool' -> results/matched/exampletool
Wrote 4619 exploit-validation reports to results/exploits/exampletool
Wrote scorecard to reports/scorecard.md
```

Open [`reports/scorecard.md`](../reports/scorecard.md). The headline table:

| Benchmark | Tasks | TP | FP | FN | Recall | Precision | F1 | FPR | Score |
|-----------|-------|----|----|----|--------|-----------|----|-----|-------|
| OWASP | 2740 | 1 | 2 | 1414 | 0.0007 | 0.3333 | 0.0014 | 0.0015 | -0.0008 |
| bountytasks | 44 | 1 | 1 | 43 | 0.0227 | 0.5000 | 0.0435 | 1.0000 | -0.9773 |
| CWE-Bench | 120 | 1 | 1 | 990 | 0.0010 | 0.5000 | 0.0020 | 1.0000 | -0.9990 |
| CyberGym | 1507 | 1 | 1 | 1506 | 0.0007 | 0.5000 | 0.0013 | 1.0000 | -0.9993 |
| SASTbench | 206 | 1 | 2 | 213 | 0.0047 | 0.3333 | 0.0092 | 0.4000 | -0.3953 |

The low recall is expected — only one task per benchmark has SARIF; the rest
count as false negatives. This is a **format demonstration**, not a real
evaluation. See [`tools/exampletool/README.md`](../tools/exampletool/README.md)
for the expected TP/FP breakdown per benchmark.

---

## 5. Plug in your own SAST tool

The integration surface is exactly **two files**:

### File 1 — `tools/<yourtool>/rules.json`

Maps your tool's `ruleId`s to CWEs. The matcher auto-discovers this file when
you run `sast-eval match --tool <yourtool>`.

```json
{
  "MY-RULE-001": "CWE-078",
  "MY-RULE-002": "CWE-022",
  "MY-RULE-003": "CWE-089"
}
```

> If your SARIF `run.tool.driver.rules[].id` already embeds the CWE (e.g.
> `"CWE-078: Command Injection"`), you can skip this file — the matcher reads
> CWE directly from the SARIF rules metadata.

### File 2 — `results/raw/<yourtool>/<task_id with / → __>.sarif`

One SARIF v2.1.0 file per task. The **filename** is the task ID with `/`
replaced by `__`:

| Task ID | SARIF filename |
|---|---|
| `owasp/BenchmarkTest00001` | `owasp__BenchmarkTest00001.sarif` |
| `bountytasks/InvokeAI/bounty_0` | `bountytasks__InvokeAI__bounty_0.sarif` |
| `cwebench/DSpace/DSpace_CVE-2016-10726_4.4` | `cwebench__DSpace__DSpace_CVE-2016-10726_4.4.sarif` |
| `cybergym/arvo:1065` | `cybergym__arvo:1065.sarif` |
| `sastbench/SB-PY-MI-001` | `sastbench__SB-PY-MI-001.sarif` |

The matcher reads three fields from each result:
- `ruleId` → looked up in `rules.json` (or in SARIF `tool.driver.rules`) to get the CWE
- `locations[0].physicalLocation.artifactLocation.uri` → the file path
- `locations[0].physicalLocation.region.startLine` → the line number

A minimal valid SARIF for your tool:

```json
{
  "version": "2.1.0",
  "runs": [{
    "tool": { "driver": { "name": "yourtool" }},
    "results": [
      {
        "ruleId": "MY-RULE-002",
        "level": "error",
        "message": {"text": "Path traversal: user input flows into file read"},
        "locations": [{
          "physicalLocation": {
            "artifactLocation": {"uri": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00001.java"},
            "region": {"startLine": 45}
          }
        }]
      }
    ]
  }]
}
```

### Run it

```bash
sast-eval match   --tool yourtool
sast-eval exploit --tool yourtool
sast-eval score   --tool yourtool
cat reports/scorecard.md
```

That's it. Everything downstream (match → exploit → score) is
benchmark-agnostic and runs unchanged.

---

## 6. One-shot: the whole pipeline

```bash
sast-eval all --tool yourtool
```

This runs `build → fetch → package → match → exploit → score` in sequence.
Use it once your SARIF is already in place; for a first run, do the steps
individually so you can inspect each stage's output.

---

## 7. Use as a Python library

Every CLI subcommand maps to a module `main(argv)` you can call directly:

```python
from sast_eval.matching.matcher import main as match_main
from sast_eval.scoring.metrics import main as score_main

# classify findings against ground truth
match_main([
    "--tasks", "tasks/",
    "--results", "results/raw/yourtool/",
    "--out", "results/matched/yourtool/",
    "--tool", "yourtool",
])

# render the scorecard
score_main([
    "--matched", "results/matched/yourtool/",
    "--imported", "imported",
    "--tasks", "tasks/",
    "--out", "reports/scorecard.md",
])
```

For finer control, import the classifier functions directly from
[`sast_eval.matching.matcher`](../sast_eval/matching/matcher.py) (e.g. `cwe_matches`)
or the per-benchmark oracles from [`sast_eval.exploit.oracles`](../sast_eval/exploit/oracles/).

---

## Where to go next

- [ARCHITECTURE.md](ARCHITECTURE.md) — pipeline, module ownership, unified task schema.
- [SCORING.md](SCORING.md) — TP/FP/FN classification rules, metric definitions, per-benchmark caveats.
- [EXPLOIT_VALIDATION.md](EXPLOIT_VALIDATION.md) — the 4-tier exploit-validation oracle.
- [ADDING_A_BENCHMARK.md](ADDING_A_BENCHMARK.md) — add a 6th benchmark (adapter or importer).
- [`tools/exampletool/README.md`](../tools/exampletool/README.md) — the example tool's expected results.
