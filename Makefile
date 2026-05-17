SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help
.DELETE_ON_ERROR:
MAKEFLAGS += --no-builtin-rules
MAKEFLAGS += --warn-undefined-variables

UV ?= uv
PYTEST ?= $(UV) run pytest
PYTEST_COV_ARGS ?= --cov=src --cov-report=term-missing:skip-covered --cov-report=xml --cov-report=html --junitxml=junit.xml
PYTHON_VERSIONS ?= 3.10 3.11 3.12 3.13 3.14
XENON_ARGS ?= --max-absolute B --max-modules A --ignore tests

.PHONY: all
.PHONY: install dev-setup
.PHONY: format fix check type-check lint check-all pre-commit
.PHONY: security security-full bandit pip-audit trivy zizmor
.PHONY: requirements-export requirements-check
.PHONY: test test-cov test-e2e
.PHONY: docs docs-serve docs-linkcheck docs-format docs-format-check
.PHONY: build ci clean help

all: ci ## Run CI-equivalent checks locally.

install: ## Install all dependency groups via uv.
	$(UV) sync --all-groups

dev-setup: install ## Install Python versions and pre-commit hooks.
	$(UV) python install $(PYTHON_VERSIONS)
	$(UV) run pre-commit install

format: ## Format code with Ruff.
	$(UV) run ruff format

fix: ## Apply Ruff autofixes and format code.
	$(UV) run ruff check --fix
	$(UV) run ruff format

check: ## Run non-mutating style and lint checks.
	$(UV) run ruff format --check
	$(UV) run ruff check
	$(UV) run --group=docs docstrfmt --check docs

type-check: ## Run static type checks.
	$(UV) run basedpyright

lint: check type-check ## Run all lint/quality checks.
	$(UV) run pylint ./src
	$(UV) run xenon $(XENON_ARGS) .

check-all: ## Run lint + tests across all supported Python versions.
	@for version in $(PYTHON_VERSIONS); do \
		echo "=== Python $$version ==="; \
		$(UV) run --python $$version --group lint ruff format --check; \
		$(UV) run --python $$version --group lint ruff check; \
		$(UV) run --python $$version --group lint pylint ./src; \
		$(UV) run --python $$version --group lint basedpyright; \
		$(UV) run --python $$version --group test pytest -q; \
		$(UV) run --python $$version --group lint xenon $(XENON_ARGS) .; \
	done

pre-commit: ## Run all pre-commit hooks.
	$(UV) run pre-commit run --all-files

security: bandit pip-audit zizmor ## Run core security scans.

security-full: security trivy ## Run all security scans, including Trivy.

requirements-export: ## Regenerate requirements.txt from lock data.
	$(UV) export --frozen --format requirements-txt --no-hashes --no-default-groups --output-file=requirements.txt

requirements-check: ## Verify requirements.txt is up to date without changing files.
	@tmp_file="$$(mktemp)"; \
	trap 'rm -f "$$tmp_file"' EXIT; \
	$(UV) export --frozen --format requirements-txt --no-hashes --no-default-groups --output-file="$$tmp_file" >/dev/null; \
	diff -u \
		<(sed -E 's|^(#    uv export .*--output-file=).*|\1requirements.txt|' requirements.txt) \
		<(sed -E 's|^(#    uv export .*--output-file=).*|\1requirements.txt|' "$$tmp_file")

bandit: ## Run Bandit and emit SARIF.
	$(UV) run bandit -r src/ -f sarif -o bandit.sarif

zizmor: ## Run Zizmor and emit SARIF.
	$(UV) run zizmor --format=sarif . > zizmor.sarif

pip-audit: ## Audit dependencies against known vulnerabilities.
	$(UV) run --group=security pip-audit -r requirements.txt

trivy: ## Run Trivy vulnerability and config scans.
	@command -v trivy >/dev/null 2>&1 || { \
		echo "Trivy not found. Install: https://trivy.dev/docs/latest/getting-started/installation/"; \
		exit 1; \
	}
	trivy fs --severity HIGH,CRITICAL --include-dev-deps --scanners vuln --format table .
	trivy config --severity HIGH,CRITICAL --format table .

test: ## Run test suite.
	$(PYTEST)

test-cov: ## Run tests with coverage and JUnit output.
	$(PYTEST) $(PYTEST_COV_ARGS)

test-e2e: ## Run end-to-end tests only.
	$(PYTEST) -m e2e

docs: ## Build documentation.
	rm -rf docs/_build docs/api
	$(UV) run sphinx-build -E -b html docs docs/_build/html

docs-serve: docs ## Build docs and serve locally on port 8000.
	@echo "Serving documentation at http://localhost:8000 (Ctrl+C to stop)"
	$(UV) run python -m http.server 8000 -d docs/_build/html

docs-linkcheck: ## Validate docs links.
	$(UV) run sphinx-build -b linkcheck docs docs/_build/linkcheck

docs-format: ## Format reStructuredText docs files.
	$(UV) run --group=docs docstrfmt docs

docs-format-check: ## Check reStructuredText docs formatting.
	$(UV) run --group=docs docstrfmt --check docs

build: ## Build source and wheel distributions.
	$(UV) build

ci: requirements-check lint security test-cov ## Run CI target locally.

clean: ## Remove caches, artifacts, and generated reports.
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -name "*.py[co]" -delete
	rm -rf .pytest_cache/ .ruff_cache/ .pyright/ .coverage
	rm -rf coverage.xml junit.xml htmlcov/ dist/ build/
	rm -rf *.sarif docs/_build/ docs/api/

help: ## Show available targets.
	@awk 'BEGIN {FS = ":.*##"; printf "\nAvailable targets:\n\n"} /^[a-zA-Z0-9_.-]+:.*##/ {printf "  %-18s %s\n", $$1, $$2} END {print ""}' $(MAKEFILE_LIST)
