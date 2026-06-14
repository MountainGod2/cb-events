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
XENON_ARGS ?= --max-absolute C --max-modules A --ignore tests

.PHONY: setup format fix lint check-all pre-commit
.PHONY: security security-full bandit audit trivy zizmor
.PHONY: test test-cov test-cov-lowest-direct test-e2e test-live
.PHONY: docs docs-serve docs-linkcheck docs-format docs-format-check
.PHONY: build ci ci-lower-bounds clean help

# Public targets are intended for day-to-day contributor workflows.
# Advanced targets are occasional utility tasks.
# Internal targets are mostly CI plumbing and low-level building blocks.

# --- Public targets ---

setup: ## Public: Bootstrap local development tooling (dependencies, Python versions, pre-commit hooks).
	$(UV) sync --all-groups
	$(UV) python install $(PYTHON_VERSIONS)
	$(UV) run pre-commit install

format: ## Public: Format code with Ruff.
	$(UV) run ruff format

fix: ## Public: Apply Ruff autofixes and format code.
	$(UV) run ruff check --fix
	$(UV) run ruff format

lint: ## Public: Run linting, static checks, docs formatting checks, and complexity checks.
	$(UV) run ruff format --check
	$(UV) run ruff check
	$(UV) run --group=docs mdformat --check docs README.md
	$(UV) run --group=docs zensical build --strict
	$(UV) run basedpyright
	$(UV) run --group=lint --group=test pyrefly check
	$(UV) run pylint ./src
	$(UV) run xenon $(XENON_ARGS) .

test: ## Public: Run test suite (excluding live tests).
	$(PYTEST) -m "not live"

security: bandit audit zizmor ## Public: Run core security scans.

docs: ## Public: Build documentation.
	rm -rf site docs/html_local_check
	$(UV) run --group=docs zensical build --strict

ci: lint security test-cov ## Public: Run CI-equivalent checks locally.

clean: ## Public: Remove caches, artifacts, and generated reports.
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -name "*.py[co]" -delete
	rm -rf .pytest_cache/ .ruff_cache/ .pyright/ .cache/ .coverage
	rm -rf coverage.xml junit.xml htmlcov/ dist/ build/
	rm -rf *.sarif site/ docs/html_local_check/

help: ## Public: Show available public and advanced targets.
	@awk 'BEGIN {printf "\nPublic targets:\n\n"} /^[a-zA-Z0-9_.-]+:.*## Public:/ {split($$0, parts, ":.*## Public: "); printf "  %-18s %s\n", parts[1], parts[2]} END {print ""}' $(MAKEFILE_LIST)
	@awk 'BEGIN {printf "Advanced targets:\n\n"} /^[a-zA-Z0-9_.-]+:.*## Advanced:/ {split($$0, parts, ":.*## Advanced: "); printf "  %-18s %s\n", parts[1], parts[2]} END {print ""}' $(MAKEFILE_LIST)

# --- Advanced targets ---

check-all: ## Advanced: Run lint + tests across supported Python versions in isolated temp envs.
	@tmp_root="$$(mktemp -d)"; \
	trap 'rm -rf "$$tmp_root"' EXIT INT TERM; \
	for version in $(PYTHON_VERSIONS); do \
		echo "=== Python $$version ==="; \
		env_dir="$$tmp_root/py$$version"; \
		VIRTUAL_ENV= UV_LINK_MODE=copy UV_PROJECT_ENVIRONMENT="$$env_dir" $(UV) sync --python "$$version" --group lint --group test --frozen; \
		VIRTUAL_ENV= UV_LINK_MODE=copy UV_PROJECT_ENVIRONMENT="$$env_dir" $(UV) run --python "$$version" --no-sync --group lint ruff format --check; \
		VIRTUAL_ENV= UV_LINK_MODE=copy UV_PROJECT_ENVIRONMENT="$$env_dir" $(UV) run --python "$$version" --no-sync --group lint ruff check; \
		VIRTUAL_ENV= UV_LINK_MODE=copy UV_PROJECT_ENVIRONMENT="$$env_dir" $(UV) run --python "$$version" --no-sync --group lint pylint ./src; \
		VIRTUAL_ENV= UV_LINK_MODE=copy UV_PROJECT_ENVIRONMENT="$$env_dir" $(UV) run --python "$$version" --no-sync --group lint basedpyright; \
		VIRTUAL_ENV= UV_LINK_MODE=copy UV_PROJECT_ENVIRONMENT="$$env_dir" $(UV) run --python "$$version" --no-sync --group lint --group test pyrefly check; \
		VIRTUAL_ENV= UV_LINK_MODE=copy UV_PROJECT_ENVIRONMENT="$$env_dir" $(UV) run --python "$$version" --no-sync --group test pytest -q -m "not live"; \
		VIRTUAL_ENV= UV_LINK_MODE=copy UV_PROJECT_ENVIRONMENT="$$env_dir" $(UV) run --python "$$version" --no-sync --group lint xenon $(XENON_ARGS) .; \
	done

pre-commit: ## Public: Run all pre-commit hooks.
	$(UV) run pre-commit run --all-files

security-full: security trivy ## Advanced: Run all security scans, including Trivy.

docs-serve: docs ## Advanced: Build docs and serve locally on port 8000.
	@echo "Serving documentation at http://localhost:8000 (Ctrl+C to stop)"
	$(UV) run --group=docs zensical serve --dev-addr 127.0.0.1:8000

docs-linkcheck: ## Advanced: Validate docs links.
	$(UV) run --group=docs zensical build --strict

docs-format: ## Advanced: Format Markdown docs files.
	$(UV) run --group=docs mdformat docs README.md

docs-format-check: ## Advanced: Check Markdown docs formatting.
	$(UV) run --group=docs mdformat --check docs README.md

build: ## Advanced: Build source and wheel distributions.
	$(UV) build

ci-lower-bounds: lint security test-cov-lowest-direct ## Advanced: Run CI checks with lowest direct dependency bounds.

# --- Internal targets ---

bandit: ## Internal: Run Bandit and emit SARIF.
	$(UV) run bandit -r src/ -f sarif -o bandit.sarif

zizmor: ## Internal: Run Zizmor and emit SARIF.
	$(UV) run zizmor --format=sarif . > zizmor.sarif

audit: ## Internal: Audit dependencies against known vulnerabilities.
	$(UV) audit --preview-features audit-command

trivy: ## Internal: Run Trivy vulnerability and config scans.
	@command -v trivy >/dev/null 2>&1 || { \
		echo "Trivy not found. Install: https://trivy.dev/docs/latest/getting-started/installation/"; \
		exit 1; \
	}
	trivy fs --severity HIGH,CRITICAL --include-dev-deps --scanners vuln --format table .
	trivy config --severity HIGH,CRITICAL --format table .

test-cov: ## Internal: Run tests with coverage and JUnit output (excluding live tests).
	$(PYTEST) -m "not live" $(PYTEST_COV_ARGS)

test-cov-lowest-direct: ## Internal: Resolve lowest direct dependency bounds, then run tests with coverage.
	$(UV) sync --group=test --resolution lowest-direct --upgrade
	$(PYTEST) -m "not live" $(PYTEST_COV_ARGS)
	$(UV) sync --frozen --all-groups

test-e2e: ## Internal: Run mocked end-to-end tests.
	$(PYTEST) -m "e2e and not live"

test-live: ## Internal: Run live end-to-end tests (requires CB_RUN_LIVE_TESTS=1 and CB_EVENTS_URL).
	$(PYTEST) -m "live and e2e"
