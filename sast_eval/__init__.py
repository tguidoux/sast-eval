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

__version__ = "0.1.4"

__all__ = ["SastEval", "Codebase", "ResultRun", "__version__"]
