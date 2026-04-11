.PHONY: install sync format check fix type-check lint test test-cov check-all pre-commit build dev-setup ci clean docs docs-clean docs-serve docs-linkcheck trivy help all

PYTHON_VERSIONS ?= 3.10 3.11 3.12 3.13 3.14

all: format fix lint test

install:
	uv sync --all-groups

sync: install

dev-setup: install
	uv python install $(PYTHON_VERSIONS)
	uv run pre-commit install

format:
	uv run ruff format

check:
	uv run ruff check

fix:
	uv run ruff check --fix

type-check:
	uv run pyrefly check
	uv run pyright
	uv run ty check src

lint: check type-check
	uv run pylint ./src

bandit:
	uv run bandit -r src/ -f sarif -o bandit.sarif

trivy:
	@command -v trivy >/dev/null 2>&1 || { \
		echo "Trivy not found. Install it from https://aquasecurity.github.io/trivy/latest/getting-started/installation/"; \
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

check-all:
	@for version in $(PYTHON_VERSIONS); do \
		uv run --python $$version --group test pytest -q --no-cov || exit 1; \
		uv run --python $$version --group lint pyrefly check || exit 1; \
		uv run --python $$version --group lint pyright || exit 1; \
		uv run --python $$version --group lint ty check src || exit 1; \
	done

pre-commit:
	uv run pre-commit run --all-files

build:
	uv build

docs: FORCE
	rm -rf docs/_build && rm -rf docs/api
	uv run sphinx-build -E -b html docs docs/_build/html

docs-serve: docs
	@echo "Serving documentation at http://localhost:8000"
	@echo "Press Ctrl+C to stop the server"
	uv run python -m http.server 8000 -d docs/_build/html

docs-linkcheck:
	uv run sphinx-build -b linkcheck docs docs/_build/linkcheck

FORCE:

ci: format fix lint bandit trivy test-cov

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -name "*.py[co]" -delete
	rm -rf *.sarif
	rm -rf .pytest_cache/
	rm -rf coverage.xml
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf .ruff_cache/
	rm -rf .pyright/
	rm -rf dist/
	rm -rf build/
	rm -rf junit.xml
	rm -rf docs/_build/
	rm -rf docs/api/

help:
	@echo "Setup:"
	@echo "  install    sync    dev-setup"
	@echo ""
	@echo "Development:"
	@echo "  format     check     fix       type-check"
	@echo "  lint       bandit    trivy     pre-commit"
	@echo "  check-all"
	@echo ""
	@echo "Testing:"
	@echo "  test       test-cov  test-e2e"
	@echo ""
	@echo "Documentation:"
	@echo "  docs       docs-serve docs-linkcheck"
	@echo ""
	@echo "Release:"
	@echo "  build      ci       clean"
