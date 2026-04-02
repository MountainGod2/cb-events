# Contributing to cb-events

Thanks for pitching in. Here’s how to help:

## Ways to Contribute

- **Bug?**
  - Describe your OS, Python version, and how to trigger it.
- **Feature idea?**
  - Open an issue or PR.
- **Docs unclear?**
  - PRs for docs, comments, or examples are always welcome.

## Setup

1. Clone the repo.
2. Install deps:
   ```bash
   uv sync --all-groups
   ```
3. Make a branch:
   ```bash
   git checkout -b my-change
   ```
4. Run checks:
   ```bash
   uv run pre-commit && uv run pytest
   ```
5. Open a PR.

## PR Checklist

- Add or update tests if needed.
- Update docs for new/changed features.
- Make sure it works on all supported OSes and Python versions.

## Code of Conduct

Be decent. By contributing, you agree to our Code of Conduct.
