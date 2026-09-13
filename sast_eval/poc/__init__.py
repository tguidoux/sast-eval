"""PoC (proof-of-concept) contract for Tier 3 exploit validation.

Public surface:

    from sast_eval.poc import (
        PoCSpec, PoCResult, PoCIssue,
        validate_poc, validate_file, run_poc,
        Sandbox, LocalSandbox, REFERENCE_POC,
    )

A PoC is a declarative spec (executor + invoke + success) that the harness
runs in a sandbox and judges. The tool emits the spec; the harness verifies
it — the tool never self-certifies. See :mod:`sast_eval.poc.spec` for the
schema and :mod:`sast_eval.poc.runner` for the entry point.
"""
from sast_eval.poc.spec import (
    PoCSpec,
    PoCResult,
    PoCIssue,
    validate_poc,
    validate_file,
    from_dict,
    REFERENCE_POC,
    POC_VERSION,
    ALL_EXECUTORS,
    ALL_SUCCESS_KINDS,
)
from sast_eval.poc.sandbox import Sandbox, LocalSandbox, RunResult
from sast_eval.poc.runner import run_poc

__all__ = [
    "PoCSpec",
    "PoCResult",
    "PoCIssue",
    "validate_poc",
    "validate_file",
    "from_dict",
    "run_poc",
    "Sandbox",
    "LocalSandbox",
    "RunResult",
    "REFERENCE_POC",
    "POC_VERSION",
    "ALL_EXECUTORS",
    "ALL_SUCCESS_KINDS",
]
