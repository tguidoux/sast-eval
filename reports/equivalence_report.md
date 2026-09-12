# Equivalence Report (§12.3 — differential-testing protocol)

> **Status: BLOCKED — pending science-team sign-off on `importers/FORMATS.md`.**
> Per `EVAL_SPEC.md` §12.3 and acceptance criterion 7, cross-benchmark claims
> are blocked until this report shows per-metric agreement and is co-signed by
> the science team. This file is a placeholder describing the protocol and the
> required output shape.

## Purpose

Prove the import/aggregation layer does not distort the science team's
numbers, so all future cross-benchmark comparisons are legitimate.

## Protocol

1. Pick one overlapping benchmark (their choice: bountytasks or CWE-Bench) and
   one shared tool run: the same tool, same model version, same inputs, run
   through their runner.
2. Import their results; independently compute the same metrics from raw
   artifacts where possible.
3. Produce the per-metric agreement table below (their value, our value,
   delta, explanation for any nonzero delta).
4. Outcomes:
   - **Agreement** → the layer is certified; numbers are comparable.
   - **Disagreement** → a spec bug (duplicate counting, different CWE
     equivalence, etc.) — resolve jointly, record the resolution in
     `EVAL_SPEC.md`, re-run. Either outcome builds trust.
5. Re-run whenever: their runner version changes, this harness's matcher
   changes, or the task corpus is re-generated.

## Per-metric agreement table

unit: system | model:0.1.0 | harness:<tool>

| Metric | Their value | Our value | Delta | Explanation |
|--------|-------------|-----------|-------|-------------|
| _to be filled after the shared tool run_ | — | — | — | — |

## Sign-off

- [ ] Science team confirmed `importers/FORMATS.md`
- [ ] Shared tool run completed on the chosen overlapping benchmark
- [ ] Per-metric agreement table filled; all deltas explained
- [ ] Science team co-signed this report

_Cross-benchmark claims in `reports/scorecard.md` remain blocked until all
boxes above are checked._
