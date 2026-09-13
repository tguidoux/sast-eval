"""SARIF contract validator — what a SAST tool must emit for sast-eval.

The harness consumes **SARIF v2.1.0** (https://sarifweb.azurewebsites.net/).
A SAST tool's only output is one SARIF file per task, saved via
``ResultRun.save_sarif(sarif, task_id)``. This module checks that a SARIF doc
conforms to the minimal contract the harness actually relies on, so tool
authors can validate their output *before* running the full eval.

The contract (what the harness reads, per finding):
    - runs[].results[].ruleId            — string, must match a rule id
    - runs[].tool.driver.rules[].id      — rule id
    - runs[].tool.driver.rules[].properties.tags[]  — includes "CWE-<n>"
    - runs[].results[].locations[0].physicalLocation.artifactLocation.uri  — file path
    - runs[].results[].locations[0].physicalLocation.region.startLine     — line (optional but recommended)

Everything else in SARIF is ignored by the harness. This validator checks the
above and nothing more — it is intentionally permissive about the rest.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SarifIssue:
    """One problem found during validation (not a SARIF finding)."""
    code: str  # short machine code, e.g. "missing-cwe"
    message: str
    path: str = ""  # JSON path into the doc, e.g. "runs[0].results[2]"


@dataclass
class SarifReport:
    valid: bool
    issues: list[SarifIssue] = field(default_factory=list)
    finding_count: int = 0
    rule_count: int = 0

    def __bool__(self) -> bool:
        return self.valid


def validate_sarif(sarif: dict) -> SarifReport:
    """Validate a SARIF dict against the sast-eval contract.

    Returns a :class:`SarifReport`. ``report.valid`` is True iff the doc has
    the minimal structure the harness needs (runs[].results[] with resolvable
    CWE + file). Findings that violate the contract are reported as issues
    but do not by themselves make the doc invalid — the doc is invalid only if
    it cannot be parsed at all or has no runs.
    """
    issues: list[SarifIssue] = []

    if not isinstance(sarif, dict):
        return SarifReport(valid=False, issues=[SarifIssue("not-object", "SARIF root is not a JSON object")])

    runs = sarif.get("runs")
    if not isinstance(runs, list) or not runs:
        return SarifReport(valid=False, issues=[SarifIssue("no-runs", "SARIF has no runs[] array")])

    total_findings = 0
    total_rules = 0

    for ri, run in enumerate(runs):
        if not isinstance(run, dict):
            issues.append(SarifIssue("run-not-object", f"runs[{ri}] is not an object", f"runs[{ri}]"))
            continue

        # Build ruleId -> CWE map from this run's rules.
        run_rules: dict[str, str | None] = {}
        rules = run.get("tool", {}).get("driver", {}).get("rules", [])
        if isinstance(rules, list):
            for rule in rules:
                if not isinstance(rule, dict):
                    continue
                rid = rule.get("id")
                if not rid:
                    continue
                total_rules += 1
                cwe = _rule_cwe(rule)
                run_rules[rid] = cwe
                if cwe is None:
                    issues.append(SarifIssue(
                        "rule-missing-cwe",
                        f"rule {rid!r} has no CWE tag; findings using it will be CWE-UNKNOWN",
                        f"runs[{ri}].tool.driver.rules[{rid}]",
                    ))

        results = run.get("results", [])
        if not isinstance(results, list):
            issues.append(SarifIssue("results-not-list", f"runs[{ri}].results is not an array", f"runs[{ri}].results"))
            continue

        for fi, res in enumerate(results):
            if not isinstance(res, dict):
                issues.append(SarifIssue("result-not-object", f"runs[{ri}].results[{fi}] is not an object", f"runs[{ri}].results[{fi}]"))
                continue
            total_findings += 1
            base = f"runs[{ri}].results[{fi}]"

            rid = res.get("ruleId")
            if not rid:
                issues.append(SarifIssue("missing-ruleId", "finding has no ruleId", base))
            elif rid in run_rules and run_rules[rid] is None:
                # Already reported on the rule; don't double-report.
                pass
            elif rid not in run_rules:
                # ruleId not declared in rules[] — harness falls back to the
                # tool's rules.json, so this is a warning, not an error.
                issues.append(SarifIssue(
                    "undeclared-rule",
                    f"finding uses ruleId {rid!r} not declared in runs[{ri}].tool.driver.rules",
                    base,
                ))

            locs = res.get("locations")
            if not isinstance(locs, list) or not locs:
                issues.append(SarifIssue("no-location", "finding has no locations[]", base))
                continue
            loc = locs[0] or {}
            phys = loc.get("physicalLocation", {}) if isinstance(loc, dict) else {}
            uri = phys.get("artifactLocation", {}).get("uri", "") if isinstance(phys, dict) else ""
            if not uri:
                issues.append(SarifIssue("no-uri", "finding has no artifactLocation.uri", base + ".locations[0].physicalLocation"))
            region = phys.get("region", {}) if isinstance(phys, dict) else {}
            if not (isinstance(region, dict) and region.get("startLine")):
                issues.append(SarifIssue(
                    "no-line",
                    "finding has no region.startLine (recommended; harness uses it for method/region overlap)",
                    base + ".locations[0].physicalLocation.region",
                ))

    return SarifReport(
        valid=True,  # structure is parseable; per-finding issues are warnings
        issues=issues,
        finding_count=total_findings,
        rule_count=total_rules,
    )


def _rule_cwe(rule: dict) -> str | None:
    """Extract a CWE-<n> tag from a rule's properties.tags."""
    tags = rule.get("properties", {}).get("tags", [])
    if not isinstance(tags, list):
        return None
    for t in tags:
        if isinstance(t, str) and t.upper().startswith("CWE-"):
            return t.upper()
    return None


def validate_file(path: str | Path) -> SarifReport:
    """Validate a SARIF file on disk."""
    p = Path(path)
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        return SarifReport(valid=False, issues=[SarifIssue("invalid-json", f"not valid JSON: {e}", str(p))])
    except OSError as e:
        return SarifReport(valid=False, issues=[SarifIssue("unreadable", f"cannot read file: {e}", str(p))])
    return validate_sarif(doc)


# --- reference fixture ---------------------------------------------------

REFERENCE_SARIF: dict = {
    "version": "2.1.0",
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "runs": [{
        "tool": {
            "driver": {
                "name": "example-sast",
                "rules": [
                    {
                        "id": "java/path-traversal",
                        "properties": {"tags": ["CWE-022"]},
                    },
                    {
                        "id": "java/sql-injection",
                        "properties": {"tags": ["CWE-089"]},
                    },
                ],
            },
        },
        "results": [
            {
                "ruleId": "java/path-traversal",
                "level": "error",
                "message": {"text": "User-controlled input flows into a file path."},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00001.java",
                        },
                        "region": {"startLine": 42},
                    },
                }],
            },
            {
                "ruleId": "java/sql-injection",
                "level": "error",
                "message": {"text": "User input concatenated into SQL query."},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00026.java",
                        },
                        "region": {"startLine": 88},
                    },
                }],
            },
        ],
    }],
}
