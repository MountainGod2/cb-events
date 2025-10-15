.PHONY: install sync format check fix type-check lint test test-cov pre-commit build dev-setup ci clean docs docs-clean docs-serve docs-linkcheck trivy help all

all: format fix lint test

install:
	uv sync --all-groups

sync: install

# First-time setup for contributors
dev-setup: install
	uv run pre-commit install

format:
	uv run ruff format

check:
	uv run ruff check

fix:
	uv run ruff check --fix

type-check:
	uv run mypy ./
	uv run pyright

# Full static analysis pipeline
lint: check type-check
	uv run pylint ./src

# Security scanning
bandit:
	uv run bandit -r src/ -f sarif -o bandit.sarif

# Trivy security scanning
trivy:
	@command -v trivy >/dev/null 2>&1 || { \
		echo "Installing Trivy..."; \
		curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin; \
	}
	trivy fs --severity HIGH,CRITICAL --format table .
	trivy config --severity HIGH,CRITICAL --format table .

test:
	uv run pytest

# Coverage reports for CI and local development
test-cov:
	uv run pytest --cov=src --cov-report=xml --cov-report=term --cov-report=html --junitxml=junit.xml

test-e2e:
	uv run pytest -m e2e

# Validate changes before commit
pre-commit:
	uv run pre-commit run --all-files

build:
	uv build

# Build documentation
docs: FORCE
	rm -rf docs/_build && rm -rf docs/api
	uv run --group docs sphinx-build -E -T -a -b html -D language=en docs docs/_build/html

# Serve documentation locally for development
docs-serve: docs
	@echo "Serving documentation at http://localhost:8000"
	@echo "Press Ctrl+C to stop the server"
	uv run python -m http.server 8000 -d docs/_build/html

# Check documentation links
docs-linkcheck:
	uv run --group docs sphinx-build -b linkcheck docs docs/_build/linkcheck

FORCE:

# Mirror the CI pipeline locally
ci: format fix lint bandit trivy test-cov

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -name "*.py[co]" -delete
	rm -rf *.sarif
	rm -rf .pytest_cache/
	rm -rf coverage.xml
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf .mypy_cache/
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
	@echo ""
	@echo "Testing:"
	@echo "  test       test-cov  test-e2e"
	@echo ""
	@echo "Documentation:"
	@echo "  docs       docs-serve docs-linkcheck"
	@echo ""
	@echo "Release:"
	@echo "  build      ci       clean"
