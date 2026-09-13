# SAST Tool Contract

This document defines exactly what a SAST tool must produce to be benchmarked
on sast-eval. It consolidates both legs — **detect** and **exploit** — in one
place so tool authors can self-check before running the full eval.

If you read only one doc as a tool author, read this one.

---

## TL;DR

A SAST tool produces **two artifacts**:

| leg | artifact | format | per | mandatory | scored as |
|-----|----------|--------|-----|-----------|-----------|
| detect | SARIF | SARIF v2.1.0 (4 fields) | codebase | **yes** | TP/FP/FN → precision, recall, F1 |
| exploit | PoC spec | JSON (executor + invoke + success) | finding | no | confirmed / unconfirmed / matched-static-only |

**The one-line contract:** emit SARIF to be scored on detection; emit PoC
specs to be scored on exploitability. The harness does the matching, the
running, and the judging — you just produce the two artifacts.

---

## What the tool outputs, what the harness does

This is the core decision the AI SAST tool makes for each finding, and the
exact division of labor with the harness. Everything else in this doc is
detail on *how* to fill these in.

### Per finding, the tool outputs exactly two things

```
For each vulnerability the tool claims to find in a codebase:

  1. A DETECTION entry  →  one row in the SARIF results[] array
     "I found a vulnerability of class <CWE> at <file>:<line>."

  2. (optional) An EXPLOIT entry  →  one PoC spec JSON file
     "Here is how to prove it: run <executor> with <invoke>;
      it succeeds when <success>."
```

That's it. The tool **does not** output a verdict (`confirmed`/`unconfirmed`),
a confidence score, a severity, or a self-assessment. It outputs a *claim*
(detection) and optionally a *recipe to reproduce* (exploit). The harness turns
those into a verdict.

### What the harness does with each

| tool outputs | harness does | result |
|---|---|---|
| SARIF finding `(file, cwe)` | matches against ground truth | **TP** or **FP** |
| (no PoC spec) | runs Tier 0/1 only | outcome capped at `matched-static-only` |
| PoC spec | runs it in a sandbox, judges `success` | **`confirmed`** (passed) or **`unconfirmed`** (failed) |
| PoC spec with bad schema | `validate-poc` rejects it | spec ignored, falls back to Tier 0/1 |

### The decision tree for one finding

```
tool emits SARIF finding
        │
        ▼
harness matches (file, cwe) against ground truth?
        │
   ┌────┴────┐
   FP        TP
   │         │
   ▼         ▼
done    tool emits PoC spec for this finding?
              │
         ┌────┴────┐
         no        yes
         │         │
         ▼         ▼
   matched-static   harness runs PoC in sandbox
   -only            │
              ┌─────┴─────┐
              pass        fail
              │           │
              ▼           ▼
          confirmed   unconfirmed
```

So the tool's job per finding is:

1. **Always**: emit the SARIF row (the claim).
2. **If you want credit for exploitability**: also emit a PoC spec (the recipe).
   The harness runs it and decides `confirmed` vs `unconfirmed`. You never
   decide that yourself.

### What the tool must NOT output

- A verdict (`confirmed`, `exploitable`, `true positive`) — the harness decides.
- A self-assessed confidence — not used by the matcher or oracle.
- A severity — not used for scoring (may be present in SARIF, ignored).
- A "proof" narrative — only the executable PoC spec counts.

The trust boundary is strict: **the tool claims, the harness proves.** This
is why `success` is a declarative criterion the harness evaluates, not a field
the tool fills in with `true`.

---

## Leg 1 — Detect (mandatory): SARIF v2.1.0

The tool emits one SARIF file per codebase (task). The harness reads exactly
**4 fields per finding** — nothing else.

### What the harness reads

```
runs[].results[].ruleId                                           → ruleId
runs[].tool.driver.rules[].properties.tags[]  (first "CWE-<n>")   → cwe
runs[].results[].locations[0].physicalLocation.artifactLocation.uri → file
runs[].results[].locations[0].physicalLocation.region.startLine      → line
```

### Minimal valid example

```json
{
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "my-sast",
        "rules": [{
          "id": "java/path-traversal",
          "properties": { "tags": ["CWE-022"] }
        }]
      }
    },
    "results": [{
      "ruleId": "java/path-traversal",
      "locations": [{
        "physicalLocation": {
          "artifactLocation": { "uri": "src/main/java/.../BenchmarkTest00001.java" },
          "region": { "startLine": 29 }
        }
      }]
    }]
  }]
}
```

### Field rules

| field | required | missing → |
|-------|----------|-----------|
| `ruleId` | yes | finding dropped |
| `cwe` (in rule `tags`) | yes | `CWE-UNKNOWN` (won't match ground truth) |
| `file` (artifact `uri`) | yes | finding dropped (cannot match) |
| `line` (`region.startLine`) | recommended | `None` (matching still works on file + rule) |

### Where the file goes

```
results/raw/<tool>/<task_id with / → __>.sarif
```

e.g. `results/raw/mytool/owasp__BenchmarkTest00001.sarif`

### How it's scored (detect leg)

The matcher compares each finding's `(file, cwe)` against the task's ground
truth:

- **TP** — finding matches a real vulnerability
- **FP** — finding doesn't match ground truth
- **FN** — real vulnerability the tool missed

This gives you precision, recall, and F1 — the **detection score**.

### Validate before submitting

```bash
sast-eval validate-sarif --reference > ref.sarif     # see the contract
sast-eval validate-sarif results/raw/mytool/          # check your output
```

```python
from sast_eval import validate_sarif
report = validate_sarif(my_sarif_dict)
print(report.valid, report.finding_count, report.issues)
```

---

## Leg 2 — Exploit (optional, raises your score ceiling): PoC spec

SARIF alone caps you at `matched-static-only` — "you found the sink, but
didn't prove it's exploitable." To reach `confirmed`, the tool emits a **PoC
spec** per finding. The harness runs it in a sandbox and judges success.

### What the tool emits

One PoC spec file per finding (or per task):

```json
{
  "poc_version": "1.0",
  "task_id": "owasp__BenchmarkTest00001",
  "finding": {
    "rule_id": "java/path-traversal",
    "cwe": "CWE-022",
    "file": "src/main/java/.../BenchmarkTest00001.java",
    "line": 29
  },
  "executor": "http-request",
  "setup": {
    "build": "mvn -q compile jetty:run -Djetty.port=${PORT}",
    "ready_pattern": "Started Jetty Server",
    "ready_timeout_s": 120
  },
  "invoke": {
    "method": "GET",
    "path": "/benchmark/BenchmarkTest00001",
    "params": { "filename": "../../../../etc/passwd" }
  },
  "success": {
    "kind": "response-body-contains",
    "pattern": "root:"
  },
  "cleanup": "kill ${SERVER_PID}"
}
```

### The 3 required blocks

| block | what it declares |
|-------|-----------------|
| `executor` | which executor runs it: `http-request`, `cli-stdin`, `file-read`, `grpc-call`, `custom-script` |
| `invoke` | what to run (HTTP method/path/params, or binary+args+stdin, or script) |
| `success` | how the **harness** judges it (the tool does not self-certify) |

### Executors

| executor | use for | invoke keys |
|----------|---------|-------------|
| `http-request` | web apps (OWASP, bountytasks web) | `method`, `path`, `params`, `headers` |
| `cli-stdin` | CLI tools / binaries | `binary`, `args`, `stdin` |
| `file-read` | path traversal (no server) | `path` (relative to codebase) |
| `grpc-call` | gRPC services | `service`, `method`, `request` (placeholder) |
| `custom-script` | escape hatch | `script` (bash), `language` |

### Success criteria (the harness judges, not you)

| kind | passes when |
|------|-------------|
| `response-body-contains` | stdout/response contains `pattern` |
| `response-body-regex` | stdout/response matches `pattern` (regex) |
| `exit-code` | exit code equals `value` |
| `file-exists` | file at `path` exists after the run |
| `file-contains` | file at `path` contains `pattern` |
| `stderr-contains` | stderr contains `pattern` (crash detection) |

### Where the file goes

```
results/pocs/<tool>/<task_id with / → __>.poc.json
```

### How it's scored (exploit leg)

The harness runs your PoC in a sandbox and applies the 4-tier ladder:

| tier | what runs | outcome if passed | outcome if failed |
|------|----------|------------------|-------------------|
| 0 | static match (from SARIF) | `matched-static-only` | — |
| 1 | reachability (static) | `matched-static-only` | `unreachable` |
| 2 | canary (static, bespoke) | `confirmed` | `unconfirmed` |
| 3 | **your PoC** (dynamic) | `confirmed` | `unconfirmed` |

Your final outcome is the **highest tier that ran**. So:

- **No PoC** → max `matched-static-only` (you found it but didn't prove it)
- **PoC passes** → `confirmed` (you proved it's exploitable)
- **PoC fails** → `unconfirmed` (you tried but couldn't prove it)

### Validate before submitting

```bash
sast-eval validate-poc --reference > ref.poc.json                       # see the contract
sast-eval validate-poc results/pocs/mytool/                              # check your specs
sast-eval run-poc poc.json codebases/owasp__BenchmarkTest00001/          # test one
```

```python
from sast_eval import run_poc, LocalSandbox, validate_poc
valid, issues = validate_poc(my_poc_dict)
result = run_poc(my_poc_dict, "/path/to/codebase", LocalSandbox())
print(result.passed, result.exit_code, result.output)
```

---

## The full picture

```
┌─────────────────────────────────────────────────────────┐
│  SAST TOOL                                               │
│                                                          │
│  analyze(codebase_tar) → SARIF          [detect leg]     │
│  poc(codebase_tar, finding) → PoC spec  [exploit leg]    │
└─────────────────────────────────────────────────────────┘
              │                              │
              ▼                              ▼
    results/raw/<tool>/            results/pocs/<tool>/
      <task>.sarif                   <task>.poc.json
              │                              │
              ▼                              ▼
    ┌─────────────────┐           ┌──────────────────────┐
    │   match (Tier 0) │           │  run PoC (Tier 3)   │
    │   TP / FP / FN   │           │  harness judges      │
    └─────────────────┘           └──────────────────────┘
              │                              │
              ▼                              ▼
        precision, recall            confirmed / unconfirmed
              │                              │
              └──────────┬───────────────────┘
                         ▼
                    scorecard.md
              (detect + exploit sections)
```

### Minimal tool (detect only)

```python
from sast_eval import SastEval

sast_eval = SastEval()

with sast_eval.results("my-tool") as run:
    for codebase in sast_eval.codebases():
        tar = codebase.download("/tmp/sandbox")
        sarif = my_tool.analyze(tar)
        run.save_sarif(sarif, codebase.task_id)
    run.match()
    run.exploit()
    run.score()
# → gets precision/recall/F1, exploit outcomes capped at matched-static-only
```

### Full tool (detect + exploit)

```python
from sast_eval import SastEval

sast_eval = SastEval()

with sast_eval.results("my-tool") as run:
    for codebase in sast_eval.codebases():
        tar = codebase.download("/tmp/sandbox")
        sarif = my_tool.analyze(tar)
        run.save_sarif(sarif, codebase.task_id)
        for finding in sarif["runs"][0]["results"]:
            poc = my_tool.poc(tar, finding)
            run.save_poc(poc, codebase.task_id, finding)
    run.match()
    run.exploit()
    run.score()
# → gets precision/recall/F1 + confirmed/unconfirmed per finding
```

---

## Sandbox contract

The same sandbox can run both the SAST tool and the PoC. The harness provides
a `Sandbox` protocol:

| method | purpose |
|--------|---------|
| `run(cmd, cwd, env, timeout_s)` | execute a command, return `RunResult` |
| `port(host_port)` | allocate/forward a port for the PoC to hit |
| `put_file(local_path)` | stage a file into the sandbox |
| `teardown()` | clean up |

`LocalSandbox` is used for tests. Production uses Docker/gVisor (see
`docs/EXPLOIT_VALIDATION.md`).

---

## Reference fixtures

The harness ships reference fixtures so you can see the exact contract:

```bash
sast-eval validate-sarif --reference    # prints a valid SARIF doc
sast-eval validate-poc --reference       # prints a valid PoC spec
```

Or in Python:

```python
from sast_eval import REFERENCE_POC
from sast_eval.sarif_contract import REFERENCE_SARIF
```

---

## See also

- [EXPLOIT_VALIDATION.md](./EXPLOIT_VALIDATION.md) — the 4-tier oracle ladder, sandbox details, per-benchmark coverage
- [SCORING.md](./SCORING.md) — how detect + exploit scores combine into the final scorecard
- [QUICKSTART.md](QUICKSTART.md) — getting started running the eval
- [ARCHITECTURE.md](./ARCHITECTURE.md) — harness internals
