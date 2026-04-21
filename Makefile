.PHONY: all install dev-setup \
        format fix check type-check lint check-all pre-commit bandit trivy \
        test test-cov test-e2e \
        build ci clean \
        docs docs-serve docs-linkcheck \
        help

PYTHON_VERSIONS ?= 3.10 3.11 3.12 3.13 3.14

all: fix format lint test

install:
	uv sync --all-groups

dev-setup: install
	uv python install $(PYTHON_VERSIONS)
	uv run pre-commit install

format:
	uv run ruff format

fix:
	uv run ruff check --fix

check:
	uv run ruff format --check
	uv run ruff check

type-check:
	uv run basedpyright

lint: check type-check
	uv run pylint ./src

check-all:
	@for version in $(PYTHON_VERSIONS); do \
		echo "=== Python $$version ==="; \
		uv run --python $$version --group lint ruff format --check || exit 1; \
		uv run --python $$version --group lint ruff check || exit 1; \
		uv run --python $$version --group lint pylint ./src || exit 1; \
		uv run --python $$version --group typecheck basedpyright || exit 1; \
		uv run --python $$version --group test pytest -q --no-cov || exit 1; \
	done

pre-commit:
	uv run pre-commit run --all-files

bandit:
	uv run bandit -r src/ -f sarif -o bandit.sarif

trivy:
	@command -v trivy >/dev/null 2>&1 || { \
		echo "Trivy not found. Install: https://aquasecurity.github.io/trivy/latest/getting-started/installation/"; \
		exit 1; \
	}
	trivy fs --severity HIGH,CRITICAL --format table .
	trivy config --severity HIGH,CRITICAL --format table .

test:
	uv run pytest

test-cov:
	uv run pytest --cov=src --cov-report=xml --cov-report=term --cov-report=html --junitxml=junit.xml

test-e2e:
	uv run pytest -m e2e --no-cov

docs:
	rm -rf docs/_build docs/api
	uv run sphinx-build -E -b html docs docs/_build/html

docs-serve: docs
	@echo "Serving documentation at http://localhost:8000 (Ctrl+C to stop)"
	uv run python -m http.server 8000 -d docs/_build/html

docs-linkcheck:
	uv run sphinx-build -b linkcheck docs docs/_build/linkcheck

build:
	uv build

ci: check type-check lint bandit test-cov

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -name "*.py[co]" -delete
	rm -rf .pytest_cache/ .ruff_cache/ .pyright/ .coverage
	rm -rf coverage.xml junit.xml htmlcov/ dist/ build/
	rm -rf *.sarif docs/_build/ docs/api/

help:
	@echo "Setup:        install       dev-setup"
	@echo "Quality:      fix           format        check"
	@echo "              type-check    lint          check-all     pre-commit"
	@echo "Security:     bandit        trivy"
	@echo "Testing:      test          test-cov      test-e2e"
	@echo "Docs:         docs          docs-serve    docs-linkcheck"
	@echo "Release:      build         ci            clean"
