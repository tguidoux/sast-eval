# exampletool — sample SARIF for trying the scoring pipeline

This is a **fake** SAST tool (`exampletool`) with hand-crafted SARIF output for
one task per benchmark, designed to exercise every branch of the matcher and
the exploit-validation oracle. Use it to try `make match && make exploit &&
make score` without running a real SAST tool.

## Files

- `tools/exampletool/rules.json` — ruleId → CWE map (§4)
- `results/raw/exampletool/<task_id with / → __>.sarif` — one SARIF per task

## What each SARIF demonstrates

### OWASP — `owasp__BenchmarkTest00001.sarif`
Ground truth: CWE-022, file `BenchmarkTest00001.java`.
- Finding 1: CWE-022 in the right file → **TP** (location + category hit)
- Finding 2: CWE-079 in the right file → **FP** (wrong CWE)
- Finding 3: CWE-022 in the wrong file → **FP** (wrong location)

### bountytasks — `bountytasks__InvokeAI__bounty_0.sarif`
Ground truth: CWE-020, file `image_files_disk.py`.
- Finding 1: CWE-020 in the right file → **TP**
- Finding 2: CWE-918 in the right file → **FP** (wrong CWE)

### CWE-Bench — `cwebench__DSpace__DSpace_CVE-2016-10726_4.4.sarif`
Ground truth: CWE-022, method `SafeResourceReader.setup` (lines 34–65).
- Finding 1: CWE-022 at line 40 (inside method range) → **TP** (method-identity hit)
- Finding 2: CWE-089 at line 42 → **FP** (wrong CWE)

### CyberGym — `cybergym__arvo:1065.sarif`
Ground truth: CWE-UNKNOWN (location-only scoring), file `src/funcs.c`.
- Finding 1: CWE-078 in `src/funcs.c` → **TP** (location hit; CWE ignored)
- Finding 2: CWE-999 in `src/main.c` → **FP** (wrong file)

### SASTbench — `sastbench__SB-PY-MI-001.sarif`
Ground truth: vulnerable region R2 (SSRF, `preview_fetcher.py:15–48`) +
capability_safe region R1 (`clinical_fetcher.py:14–51`).
- Finding 1: CWE-918 at `preview_fetcher.py:30` → **TP** (overlaps vulnerable R2 + kind-matches `ssrf`)
- Finding 2: CWE-078 at `clinical_fetcher.py:20` → **capability FP** (overlaps capability_safe R1)
- Finding 3: CWE-918 at `other_fetcher.py:5` → **plain FP** (no region overlap)

## Running the pipeline

```bash
# via the sast-eval CLI (installed by `uv sync` / `pip install -e .`)
sast-eval match   --tool exampletool
sast-eval exploit --tool exampletool
sast-eval score   --tool exampletool

# or equivalently via make
make match TOOL=exampletool
make exploit TOOL=exampletool
make score TOOL=exampletool
```

Then inspect:
- `results/matched/exampletool/*.json` — TP/FP/FN per task (§5)
- `results/exploits/exampletool/*.json` — Tier 1 reachability verdicts (§10)
- `reports/scorecard.md` — headline + per-CWE + exploit-validation sections (§6)

## Expected scorecard (exampletool, 1 task per benchmark)

| Benchmark | TP | FP | FN | Notes |
|-----------|----|----|----|-------|
| OWASP | 1 | 2 | 1414 | FPR defined (FP traps) |
| bountytasks | 1 | 1 | 43 | precision reported, FPR n/a |
| CWE-Bench | 1 | 1 | 990 | method-identity matching |
| CyberGym | 1 | 1 | 1506 | location-only (no CWE) |
| SASTbench | 1 | 2 | 213 | 1 capability FP tracked |

The low recall is expected — only 1 task per benchmark has SARIF; the other
4615 tasks have no SARIF and count as FN. This is a format demonstration, not a
real tool evaluation.

## Exploit-validation note (Tier 1 reachability)

The generic Tier 1 heuristic flags files in `test/`/`example/`/`doc`/`sample`
paths as dead code (`unreachable`). OWASP's vulnerable files live under
`.../testcode/` — so they get marked `unreachable`. This is a known limitation
of the generic heuristic; a bespoke OWASP Tier 1 oracle would override it. See
[docs/EXPLOIT_VALIDATION.md](../../docs/EXPLOIT_VALIDATION.md).
