# llm-sast-e2e — toy LLM SAST benchmarked with sast-eval

A minimal, self-contained example of what a developer would build to verify an
LLM-based SAST tool against the [sast-eval](https://github.com/theoguidoux/sast-eval)
harness. It demonstrates the full contract from
[docs/CONTRACT.md](../../docs/CONTRACT.md):

1. **Detect leg** — the tool emits SARIF v2.1.0 (4 fields per finding)
2. **Exploit leg** — the tool emits PoC specs (executor + invoke + success)
3. The harness matches, runs the PoCs in a sandbox, judges, and scores

The "LLM" here is a toy: a few regex heuristics that simulate what a real LLM
SAST would produce. The point is the **plumbing**, not the detector quality.

## Layout

```
llm-sast-e2e/
├── pyproject.toml   # standalone uv project, depends on sast-eval
├── llm_sast.py      # the toy tool + eval pipeline
└── README.md        # this file
```

## Quick start

```bash
cd examples/llm-sast-e2e

# 1. Install (creates a .venv, pulls sast-eval from PyPI)
uv sync

# 2. Build codebases (one-time; downloads OWASP + packages 3 tarballs)
uv run llm_sast.py prepare

# 3. Run the tool + full eval pipeline
uv run llm_sast.py run
```

`run` does, for each codebase:

```python
with sast.results("toy-llm-sast") as run:
    for cb in sast.codebases():
        src = cb.download("/tmp/...", extract=True)
        sarif, pocs = analyze(src)          # the tool: emit SARIF + PoC specs
        run.save_sarif(sarif, cb.task_id)   # detect leg
        run.save_poc(poc, cb.task_id)       # exploit leg
    run.match()    # harness: SARIF vs ground truth → TP/FP/FN
    run.exploit()  # harness: run PoCs in sandbox → confirmed/unconfirmed
    run.score()    # harness: render scorecard
```

## What you'll see

The `run` command prints:

1. Per codebase: download → analyze → N findings, M PoCs saved
2. The **scorecard** (detect metrics: precision, recall, F1)
3. Per-finding **exploit verdicts** showing the tier ladder:

```
owasp/BenchmarkTest00001  (benchmark: owasp)
  confirmed     tier=3 (PoC)  CWE-022  BenchmarkTest00001.java:72
               tier 2 (canary): PASS
               tier 3 (PoC):    PASS  [owasp__BenchmarkTest00001.poc] POC-CONFIRMED
```

Each finding shows which tiers ran and their verdict. The outcome is the
**highest tier that ran**:

- **tier 2 (canary)** — the harness's own static taint check (bespoke per benchmark)
- **tier 3 (PoC)** — the tool's PoC spec run in the sandbox (the tool's recipe, judged by the harness)

Both can pass (as above), or the canary can pass while the PoC fails (the
tool's proof was wrong), or only the canary runs (no PoC spec for that finding).

## The contract, in code

| the tool does | the harness does |
|---|---|
| `analyze(src) → sarif, pocs` | — |
| `run.save_sarif(sarif, task_id)` | matches `(file, cwe)` vs ground truth → TP/FP |
| `run.save_poc(poc, task_id)` | runs the PoC in a sandbox, judges `success` |
| — | `confirmed` (PoC passed) / `unconfirmed` (PoC failed) / `matched-static-only` (no PoC) |

The tool **claims** (SARIF) and provides a **recipe** (PoC spec). The harness
**proves** (runs the PoC, judges). The tool never self-certifies.

### What the PoC spec looks like

The toy tool emits one PoC per finding using the `custom-script` executor.
The script does a static taint check (find the file by basename, grep for a
source and a sink, confirm the source precedes the sink) and prints
`POC-CONFIRMED` or `POC-FAIL`:

```json
{
  "executor": "custom-script",
  "invoke": {
    "script": "fname=$(basename \"...\"); f=$(find \"${CODEBASE}\" ...); ...; echo POC-CONFIRMED",
    "language": "bash",
    "timeout_s": 30
  },
  "success": {"kind": "response-body-contains", "pattern": "POC-CONFIRMED"}
}
```

The harness expands `${CODEBASE}` to the codebase dir, runs the script in a
sandbox, and checks whether `POC-CONFIRMED` appears in stdout. The pattern
`POC-CONFIRMED` (not just `CONFIRMED`) avoids false-positives from
`NOT-CONFIRMED` — a subtle but important detail for tool authors.

## Using your own tool

Replace `analyze()` in [llm_sast.py](llm_sast.py) with your real LLM call. As
long as it returns `(sarif_dict, poc_specs_dict)` in the same shape, the rest
of the pipeline works unchanged.
