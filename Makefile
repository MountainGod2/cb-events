.PHONY: format check fix mypy pylint pyright ty-check lint test all clean help

# Default target
all: format fix lint

# Format code using ruff
format:
	uv run ruff format

# Check code using ruff (without fixing)
check:
	uv run ruff check

# Fix code issues using ruff
fix:
	uv run ruff check --fix

# Run mypy type checker
mypy:
	uv run mypy ./

# Run pylint
pylint:
	uv run pylint ./src

# Run pyright type checker
pyright:
	uv run pyright

# Run ty type checker
ty-check:
	uv run ty check

# Run all linting tools
lint: mypy pylint pyright ty-check

# Run tests
test:
	uv run pytest

# Run tests with coverage
test-cov:
	uv run pytest --cov=src --cov-report=xml --cov-report=term

# Clean up generated files
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

# Show help
help:
	@echo "Available targets:"
	@echo "  format     - Format code using ruff"
	@echo "  check      - Check code using ruff (without fixing)"
	@echo "  fix        - Fix code issues using ruff"
	@echo "  mypy       - Run mypy type checker"
	@echo "  pylint     - Run pylint"
	@echo "  pyright    - Run pyright type checker"
	@echo "  ty-check   - Run ty type checker"
	@echo "  lint       - Run all linting tools (mypy, pylint, pyright, ty-check)"
	@echo "  test       - Run tests"
	@echo "  test-cov   - Run tests with coverage"
	@echo "  all        - Run format, fix, and lint (default)"
	@echo "  clean      - Clean up generated files"
	@echo "  help       - Show this help message"
