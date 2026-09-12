"""OWASP BenchmarkJava adapter — the only end-to-end adapter in this repo (§3.2).

Parses ``expectedresults-1.2.csv`` and emits one unified task record (§2) per row
to ``tasks/owasp.jsonl``.

Per §3.2 / Step 3b:
- One task per CSV row. Columns: test name, category, real vulnerability, cwe.
- ``source_root`` = the benchmark repo root (tools scan the whole repo; matching
  is per test-case file).
- ``vulnerable_files`` = ``src/main/java/org/owasp/benchmark/testcode/<TestName>.java``
  (directory is ``testcode``, not ``testcases``).
- ``real=false`` -> ``fp_trap: true`` (~1,000 of 2,740 rows are FP traps).
- Category code -> CWE via the fixed OWASP mapping; the CSV's own ``cwe``
  column is preferred when present (it is authoritative per-row).
- No weights (all tasks equal).
"""
from __future__ import annotations

import argparse
import csv
import json
import os
from pathlib import Path

from sast_eval.adapters.common import normalize_cwe

# Fixed OWASP category -> CWE mapping (§3.2). Used as a fallback when the CSV's
# per-row ``cwe`` column is absent/empty. Values are zero-padded to 3 for display.
OWASP_CATEGORY_TO_CWE = {
    "sqli": "CWE-089",
    "xss": "CWE-079",
    "cmdi": "CWE-078",
    "pathtraver": "CWE-022",
    "ldapi": "CWE-090",
    "hash": "CWE-328",
    "weakrand": "CWE-330",
    "trustbound": "CWE-501",
    "securecookie": "CWE-614",
    "crypto": "CWE-327",
    "xpathi": "CWE-643",
}

TESTCODE_REL = "src/main/java/org/owasp/benchmark/testcode"


def _category_to_cwe(category: str) -> str:
    return OWASP_CATEGORY_TO_CWE.get(category, "CWE-UNKNOWN")


def build_tasks(root: str) -> list[dict]:
    root_path = Path(root).resolve()
    csv_path = root_path / "expectedresults-1.2.csv"
    if not csv_path.exists():
        raise FileNotFoundError(f"expectedresults-1.2.csv not found at {csv_path}")

    tasks: list[dict] = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader, None)  # the '#' comment line
        if not header or not header[0].lstrip().startswith("#"):
            # Defensive: if the comment line is missing, the first row is data.
            # Re-open and treat all rows as data. (The known file always has it.)
            f.seek(0)
            reader = csv.reader(f)

        for row in reader:
            if not row or all(not c.strip() for c in row):
                continue
            # Columns: # test name, category, real vulnerability, cwe
            test_name = row[0].strip()
            category = row[1].strip() if len(row) > 1 else ""
            real = row[2].strip().lower() if len(row) > 2 else "true"
            cwe_raw = row[3].strip() if len(row) > 3 else ""

            # Prefer the CSV's per-row cwe column (authoritative); fall back to
            # the fixed category mapping.
            cwe = normalize_cwe(cwe_raw) if cwe_raw else _category_to_cwe(category)

            fp_trap = (real == "false")
            vuln_file = f"{TESTCODE_REL}/{test_name}.java"

            task = {
                "task_id": f"owasp/{test_name}",
                "benchmark": "owasp",
                "language": "java",
                "source_root": str(root_path),
                "vcs": {
                    "type": "git",
                    "commit": "",  # filled by PROVENANCE from corpus hash
                    "checked_out": True,
                },
                "ground_truth": {
                    "cwe": cwe,
                    "cwe_raw": cwe_raw or category,
                    "cve": None,
                    "vulnerable_files": [vuln_file],
                    "vulnerable_methods": [],
                    "fp_trap": fp_trap,
                    "notes": "OWASP BenchmarkJava v1.2; category=%s" % category,
                },
                "weights": {},
                "meta": {
                    "category": category,
                    "real_vulnerability": not fp_trap,
                },
            }
            tasks.append(task)
    return tasks


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build OWASP BenchmarkJava task records")
    parser.add_argument("--root", required=True, help="Path to BenchmarkJava repo root")
    parser.add_argument("--out", required=True, help="Output JSONL path (tasks/owasp.jsonl)")
    args = parser.parse_args(argv)

    tasks = build_tasks(args.root)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        for t in tasks:
            f.write(json.dumps(t, ensure_ascii=False, sort_keys=True) + "\n")

    # Idempotency note: deterministic output (sorted keys, CSV order preserved).
    print(f"Wrote {len(tasks)} OWASP task records to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
