"""sast-eval — unified SAST evaluation harness across 5 vulnerability benchmarks.

Public entry point: ``sast_eval.cli:main`` (the ``sast-eval`` console script).

For programmatic use, ``sast_eval.api:SastEval`` provides a typed wrapper over
the same code paths the CLI uses::

    from sast_eval import SastEval
    sast = SastEval(benchmark="owasp", limit=20)
    sast.prepare()
    with sast.results("mytool") as run:
        for cb in sast.codebases():
            tar = cb.download("/tmp/sandbox")
            run.save_sarif(my_sast(tar), cb.task_id)
        run.match(); run.exploit(); run.score()
"""
from sast_eval.api import SastEval, Codebase, ResultRun
from sast_eval.sarif_contract import validate_sarif, validate_file, SarifReport
from sast_eval.poc import (
    PoCSpec, PoCResult, PoCIssue, run_poc,
    validate_poc, validate_file as validate_poc_file,
    Sandbox, LocalSandbox, REFERENCE_POC,
)

__version__ = "0.2.0"

__all__ = [
    "SastEval", "Codebase", "ResultRun",
    "validate_sarif", "validate_file", "SarifReport",
    "PoCSpec", "PoCResult", "PoCIssue", "run_poc",
    "validate_poc", "validate_poc_file", "Sandbox", "LocalSandbox",
    "REFERENCE_POC",
    "__version__",
]
