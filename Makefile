.PHONY: install sync format check fix type-check lint test test-cov pre-commit build dev-setup ci clean help all

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

test:
	uv run pytest

# Coverage reports for CI and local development
test-cov:
	uv run pytest --cov=src --cov-report=xml --cov-report=term --cov-report=html

test-e2e:
	uv run pytest tests/e2e/

# Validate changes before commit
pre-commit:
	uv run pre-commit run --all-files

build:
	uv build

# Mirror the CI pipeline locally
ci: format fix lint test-cov

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -name "*.py[co]" -delete
	rm -rf .pytest_cache/
	rm -rf coverage.xml
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf .mypy_cache/
	rm -rf .ruff_cache/
	rm -rf .pyright/
	rm -rf dist/
	rm -rf build/

help:
	@echo "Setup:"
	@echo "  install    sync    dev-setup"
	@echo ""
	@echo "Development:"
	@echo "  format     check     fix       type-check"
	@echo "  lint       pre-commit"
	@echo ""
	@echo "Testing:"
	@echo "  test       test-cov  test-e2e"
	@echo ""
	@echo "Release:"
	@echo "  build      ci       clean"
