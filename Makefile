# Makefile for the unified SAST evaluation harness.
# Usage:
#   make           - prepare all codebases (download + build + fetch + package)
#   make setup     - create/refresh the uv venv
#   make prepare   - ONE command: download missing corpora + build tasks + fetch
#                   source + package per-task tarballs. Default cap 20/benchmark.
#                   filters: BENCHMARK=..., LIMIT=N, ALL=1
#   make fetch     - fetch source for bountytasks + CWE-Bench + CyberGym + SASTbench
#                   filters: BENCHMARK=..., LIMIT=N, CYBERGYM_LIMIT=N
#   make build     - build all codebases into the common task format (tasks/*.jsonl)
#                   filters: BENCHMARK=...
#   make package   - build per-task .tar.gz codebases for SAST analysis (codebases/)
#                   filters: BENCHMARK=..., LIMIT=N
#   make match     - match SARIF results against ground truth (needs results/raw/<tool>/)
#   make exploit   - run exploit-validation oracles on matched results (§10)
#   make score     - render the scorecard from matched + exploit results
#   make all       - prepare + match (empty) + exploit + score
#   make clean     - remove generated task/imported/results/reports/codebases artifacts
#
# The same operations are available as a pip-installed CLI:
#   pip install sast-eval
#   sast-eval prepare
#   sast-eval match --tool mytool && sast-eval exploit --tool mytool && sast-eval score --tool mytool

PY := uv run python
CLI := uv run sast-eval
CORPUS := corpus
TASKS := tasks
IMPORTED := imported
RESULTS := results
REPORTS := reports

# Tool name for match/score (override: make match TOOL=mytool)
TOOL ?= testtool

# Fetch/package filters (override on the command line):
#   make fetch BENCHMARK=bountytasks LIMIT=5
#   make package BENCHMARK=owasp LIMIT=10
# fetch always passes --tasks $(TASKS) so only codebases referenced by the
# built task records are fetched (the fast path).
BENCHMARK ?=
LIMIT ?=

# Cap CyberGym tasks fetched from HuggingFace (full dataset is ~240GB).
# Override: make fetch CYBERGYM_LIMIT=20  (empty = fetch all)
CYBERGYM_LIMIT ?=

# prepare: ALL=1 removes the default 20/benchmark cap (fetch everything).
ALL ?=

# Default: prepare all codebases (download + build + fetch + package).
.DEFAULT_GOAL := prepare

.PHONY: setup prepare fetch build build-owasp build-bountytasks build-cwebench build-cybergym build-sastbench package dist test match exploit score all clean

setup:
	uv sync

test:
	$(PY) test/test_api.py

prepare:
	$(CLI) prepare \
		$(if $(BENCHMARK),--benchmark $(BENCHMARK)) \
		$(if $(ALL),--all,$(if $(LIMIT),--limit $(LIMIT)))

fetch:
	$(PY) -m sast_eval.tools.fetch_sources \
		--bountytasks $(CORPUS)/bountytasks \
		--cwebench $(CORPUS)/cwe-bench-java \
		--cybergym $(CORPUS)/cybergym \
		--sastbench $(CORPUS)/sast-bench \
		--tasks $(TASKS) \
		$(if $(BENCHMARK),--benchmark $(BENCHMARK)) \
		$(if $(LIMIT),--limit $(LIMIT)) \
		$(if $(CYBERGYM_LIMIT),--cybergym-limit $(CYBERGYM_LIMIT))
	@echo "=== Fetched source trees (idempotent: skips already-fetched) ==="

build: build-owasp build-bountytasks build-cwebench build-cybergym build-sastbench
	@echo "=== Built all codebases into common format ==="
	@wc -l $(TASKS)/*.jsonl

package:
	@mkdir -p codebases
	$(PY) -m sast_eval.tools.package_codebases --tasks $(TASKS) --out codebases \
		$(if $(BENCHMARK),--benchmark $(BENCHMARK)) \
		$(if $(LIMIT),--limit $(LIMIT))
	@echo "=== Per-task tarballs in codebases/<benchmark>/<task_id>.tar.gz ==="

# Build the 5 benchmarks' tasks and materialize all codebases as tar.gz files.
build-owasp:
	@mkdir -p $(TASKS)
	$(PY) -m sast_eval.adapters.owasp_adapter --root $(CORPUS)/BenchmarkJava --out $(TASKS)/owasp.jsonl

build-bountytasks:
	@mkdir -p $(TASKS) $(IMPORTED)
	$(PY) -m sast_eval.importers.bountytasks_importer \
		--metadata-root $(CORPUS)/bountytasks \
		--tasks-out $(TASKS)/bountytasks.jsonl \
		--imported-out $(IMPORTED)/bountytasks.jsonl

build-cwebench:
	@mkdir -p $(TASKS) $(IMPORTED)
	$(PY) -m sast_eval.importers.cwebench_importer \
		--root $(CORPUS)/cwe-bench-java \
		--tasks-out $(TASKS)/cwebench.jsonl \
		--imported-out $(IMPORTED)/cwebench.jsonl

build-cybergym:
	@mkdir -p $(TASKS) $(IMPORTED)
	$(PY) -m sast_eval.importers.cybergym_importer \
		--root $(CORPUS)/cybergym \
		--tasks-out $(TASKS)/cybergym.jsonl \
		--imported-out $(IMPORTED)/cybergym.jsonl

build-sastbench:
	@mkdir -p $(TASKS)
	$(PY) -m sast_eval.adapters.sastbench_adapter --root $(CORPUS)/sast-bench --out $(TASKS)/sastbench.jsonl

match:
	@mkdir -p $(RESULTS)/matched/$(TOOL)
	$(PY) -m sast_eval.matching.matcher \
		--tasks $(TASKS) \
		--results $(RESULTS)/raw/$(TOOL) \
		--out $(RESULTS)/matched/$(TOOL) \
		--tool $(TOOL)

exploit:
	@mkdir -p $(RESULTS)/exploits/$(TOOL)
	$(PY) -m sast_eval.exploit.oracle \
		--matched $(RESULTS)/matched/$(TOOL) \
		--tasks $(TASKS) \
		--out $(RESULTS)/exploits/$(TOOL) \
		--codebases codebases

score:
	@mkdir -p $(REPORTS)
	$(PY) -m sast_eval.scoring.metrics \
		--matched $(RESULTS)/matched/$(TOOL) \
		--imported $(IMPORTED) \
		--tasks $(TASKS) \
		--exploits $(RESULTS)/exploits \
		--out $(REPORTS)/scorecard.md

all: prepare
	@mkdir -p $(RESULTS)/raw/$(TOOL)
	$(MAKE) match TOOL=$(TOOL)
	$(MAKE) exploit TOOL=$(TOOL)
	$(MAKE) score TOOL=$(TOOL)

clean:
	rm -f $(TASKS)/*.jsonl $(IMPORTED)/*.jsonl
	rm -rf $(RESULTS)/matched codebases
	rm -f $(REPORTS)/scorecard.md
