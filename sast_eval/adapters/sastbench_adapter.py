"""SASTbench adapter — end-to-end (this repo owns matching/scoring).

SASTbench evaluates SAST tools on agentic codebases. Its cases are
self-contained JSON files (``cases/<track>/<caseType>/<id>/case.json``) with
region-level ground truth: each case annotates one or more regions in the
source, labelled ``vulnerable`` (scanners must detect) or ``capability_safe``
(scanners must NOT flag — guarded dangerous code is an FP trap).

Per the SASTbench case schema (``schema/case.schema.json``):
- ``canonicalKind`` is one of 6 SASTbench kinds (command_injection,
  path_traversal, ssrf, auth_bypass, authz_bypass, sql_injection). We map each
  to its primary CWE via ``taxonomy/canonical_kinds.json`` (``cweMappings[0]``).
- ``regions`` carry ``path``, ``startLine``/``endLine``, ``label``,
  ``acceptedKinds`` (for vulnerable regions) and ``requiredGuards``/``capability``
  (for capability_safe regions).
- ``expectedOutcome.mustDetectRegionIds`` / ``mustNotFlagRegionIds`` state the
  ground truth explicitly.
- ``files.root`` is the scannable project root (``project/`` for core,
  ``../../../../.repos/<snapshot>/`` for full track).

Mapping to the unified task schema (§2):
- ``task_id`` = ``sastbench/<case-id>`` (e.g. ``sastbench/SB-PY-SV-001``).
- ``source_root`` = absolute path to ``<case_dir>/<files.root>``.
- ``ground_truth.cwe`` = primary CWE for ``canonicalKind``.
- ``ground_truth.vulnerable_files`` = paths of ``vulnerable`` regions.
- ``ground_truth.vulnerable_regions`` = full region list (NEW field; the
  matcher uses this for region-level overlap matching — see
  ``matching/matcher.py``).
- ``ground_truth.fp_trap`` = ``True`` for ``capability_safe`` cases (no
  vulnerable regions; any finding is a FP). For ``mixed_intent`` cases this is
  ``False`` (they have vulnerable regions), but their ``capability_safe``
  regions are still FP traps at the region level — handled by the matcher.
- ``meta`` carries ``track``, ``case_type``, ``canonical_kind``, ``agentic``,
  ``profile``, and (for real-world cases) ``repo``, ``cve``, ``ghsa``,
  disclosure dates for knowledge-cutoff gating.
- ``vcs.checked_out`` = ``False`` + ``meta.source_missing`` = ``True`` when
  ``source_root`` doesn't exist on disk (Full Track snapshots live under
  ``.repos/`` and must be fetched via ``scripts/setup_repos.py`` — see
  ``tools/fetch_sources.py``).
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from sast_eval.adapters.common import normalize_cwe

# SASTbench canonical kind -> primary CWE (first entry in
# taxonomy/canonical_kinds.json ``cweMappings``). Used for the unified
# ``ground_truth.cwe`` field. Region-level ``acceptedKinds`` are matched
# against the finding's CWE via the same map in the matcher.
KIND_TO_PRIMARY_CWE: dict[str, str] = {
    "command_injection": "CWE-078",
    "path_traversal": "CWE-022",
    "ssrf": "CWE-918",
    "auth_bypass": "CWE-287",
    "authz_bypass": "CWE-862",
    "sql_injection": "CWE-089",
}

# Reverse: CWE -> SASTbench kind, for matching a finding's CWE against a
# region's acceptedKinds. A finding counts as matching a region if its CWE
# maps to any of the region's acceptedKinds. Built from the full
# cweMappings in taxonomy/canonical_kinds.json at load time (see below).
_CWE_TO_KINDS: dict[str, list[str]] = {}


def _load_kind_cwe_map(taxonomy_dir: Path) -> None:
    """Populate ``_CWE_TO_KINDS`` from taxonomy/canonical_kinds.json."""
    global _CWE_TO_KINDS
    if _CWE_TO_KINDS:
        return
    kinds_file = taxonomy_dir / "canonical_kinds.json"
    if not kinds_file.is_file():
        return
    data = json.loads(kinds_file.read_text(encoding="utf-8"))
    for kind in data.get("canonicalKinds", []):
        kid = kind.get("id", "")
        for cwe in kind.get("cweMappings", []):
            _CWE_TO_KINDS.setdefault(normalize_cwe(cwe), []).append(kid)


def cwe_to_kinds(cwe: str) -> list[str]:
    """Return the SASTbench kinds that a CWE maps to (for region matching)."""
    return _CWE_TO_KINDS.get(cwe, [])


def _language_map(raw: str) -> str:
    """Map SASTbench language labels to our language field."""
    m = {
        "python": "python",
        "typescript": "typescript",
        "rust": "rust",
        "swift": "swift",
        "go": "go",
        "java": "java",
        "clojure": "clojure",
    }
    return m.get((raw or "").strip().lower(), (raw or "").strip().lower() or "unknown")


def _profile_for(case: dict) -> str:
    """Return the SASTbench profile: 'agentic', 'generic', or 'all'."""
    if case.get("caseType") == "real_world_generic":
        return "generic"
    return "agentic" if case.get("agentic", True) else "generic"


def _build_region(r: dict) -> dict:
    """Normalize one SASTbench region into our ground-truth region record."""
    return {
        "id": r.get("id", ""),
        "path": r.get("path", ""),
        "start": r.get("startLine", 0),
        "end": r.get("endLine", 0),
        "label": r.get("label", ""),  # "vulnerable" | "capability_safe"
        "accepted_kinds": r.get("acceptedKinds", []),
        "capability": r.get("capability", ""),
        "required_guards": r.get("requiredGuards", []),
    }


def build_tasks(root: str) -> list[dict]:
    """Build unified task records from SASTbench case definitions.

    ``root`` is the sast-bench repo root (containing ``cases/`` and
    ``taxonomy/``).
    """
    root_path = Path(root).resolve()
    cases_dir = root_path / "cases"
    if not cases_dir.is_dir():
        raise FileNotFoundError(f"cases/ not found at {cases_dir}")

    _load_kind_cwe_map(root_path / "taxonomy")

    tasks: list[dict] = []
    for case_json in sorted(cases_dir.rglob("case.json")):
        case = json.loads(case_json.read_text(encoding="utf-8"))
        case_dir = case_json.parent
        case_id = case.get("id", "")
        if not case_id:
            continue

        kind = case.get("canonicalKind", "")
        cwe = KIND_TO_PRIMARY_CWE.get(kind, "CWE-UNKNOWN")

        regions = [_build_region(r) for r in case.get("regions", [])]
        vuln_regions = [r for r in regions if r["label"] == "vulnerable"]
        cap_safe_regions = [r for r in regions if r["label"] == "capability_safe"]
        vuln_files = sorted({r["path"] for r in vuln_regions if r["path"]})

        # capability_safe cases have no vulnerable regions — any finding is a FP.
        # mixed_intent cases have both; they are NOT fp_trap at the task level
        # (they have real vulns to find), but their capability_safe regions are
        # FP traps at the region level (handled by the matcher).
        fp_trap = (case.get("caseType") == "capability_safe")

        files_root = case.get("files", {}).get("root", "")
        source_root = (case_dir / files_root).resolve() if files_root else case_dir
        source_missing = not source_root.is_dir()

        real_world = case.get("realWorld") or {}
        disclosure = real_world.get("disclosure") or {}

        meta = {
            "track": case.get("track", ""),
            "case_type": case.get("caseType", ""),
            "canonical_kind": kind,
            "agentic": case.get("agentic", True),
            "profile": _profile_for(case),
            "title": case.get("title", ""),
            "source_missing": source_missing,
        }
        if real_world:
            meta["repo"] = real_world.get("repo", "")
            meta["cve"] = real_world.get("cve")
            meta["ghsa"] = real_world.get("ghsa")
            meta["vulnerable_commit"] = real_world.get("vulnerableCommit", "")
            meta["fix_commit"] = real_world.get("fixCommit", "")
            meta["disclosure_ghsa_published"] = disclosure.get("ghsaPublished")
            meta["disclosure_fix_commit_date"] = disclosure.get("fixCommitDate")
            meta["disclosure_cve_published"] = disclosure.get("cvePublished")

        task = {
            "task_id": f"sastbench/{case_id}",
            "benchmark": "sastbench",
            "language": _language_map(case.get("language", "")),
            "source_root": str(source_root),
            "vcs": {
                "type": "git",
                "commit": real_world.get("vulnerableCommit", ""),
                "checked_out": not source_missing,
            },
            "ground_truth": {
                "cwe": cwe,
                "cwe_raw": kind,
                "cve": real_world.get("cve"),
                "vulnerable_files": vuln_files,
                "vulnerable_methods": [],
                "vulnerable_regions": regions,
                "fp_trap": fp_trap,
                "notes": case.get("description", ""),
            },
            "weights": {},
            "meta": meta,
        }
        tasks.append(task)
    return tasks


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build SASTbench task records from case definitions")
    parser.add_argument("--root", required=True, help="Path to sast-bench repo root (contains cases/ and taxonomy/)")
    parser.add_argument("--out", required=True, help="Output JSONL path (tasks/sastbench.jsonl)")
    args = parser.parse_args(argv)

    tasks = build_tasks(args.root)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        for t in tasks:
            f.write(json.dumps(t, ensure_ascii=False, sort_keys=True) + "\n")

    # Idempotency note: deterministic output (sorted keys, rglob case order).
    print(f"Wrote {len(tasks)} SASTbench task records to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
