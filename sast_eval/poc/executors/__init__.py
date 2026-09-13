"""PoC executors — one per ``executor`` type in the contract.

Each executor implements::

    run(spec: PoCSpec, codebase_dir: Path, sandbox: Sandbox) -> PoCResult

The runner (:mod:`sast_eval.poc.runner`) dispatches to the right executor by
``spec.executor`` and then judges success via :mod:`sast_eval.poc.judge`.
Executors only *produce output* (stdout/stderr/exit code/files); they do not
decide pass/fail — that's the judge's job, and it lives in the harness, not
the tool.
"""
from __future__ import annotations

from sast_eval.poc.spec import (
    EXECUTOR_HTTP_REQUEST,
    EXECUTOR_CLI_STDIN,
    EXECUTOR_FILE_READ,
    EXECUTOR_GRPC_CALL,
    EXECUTOR_CUSTOM_SCRIPT,
    PoCResult,
    PoCSpec,
)
from sast_eval.poc.sandbox import Sandbox, expand_template

from . import http_request, cli_stdin, file_read, custom_script

REGISTRY = {
    EXECUTOR_HTTP_REQUEST: http_request.run,
    EXECUTOR_CLI_STDIN: cli_stdin.run,
    EXECUTOR_FILE_READ: file_read.run,
    EXECUTOR_CUSTOM_SCRIPT: custom_script.run,
    # grpc-call is a placeholder — implement when a benchmark needs it.
    # EXECUTOR_GRPC_CALL: grpc_call.run,
}


def get_executor(name: str):
    return REGISTRY.get(name)
