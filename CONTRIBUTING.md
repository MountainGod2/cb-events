# Contributing to cb-events

## Setup

Requires [uv](https://docs.astral.sh/uv/).

```bash
make setup
```

This installs all dependency groups, the supported Python versions, and the pre-commit hooks.
`make setup` is equivalent to `uv sync --all-groups` followed by Python version installs and
pre-commit setup - either works if you want to handle those steps yourself.

## Common Commands

```bash
make format       # format code
make fix          # format + apply lint autofixes
make lint         # lint, type-check, complexity
make test         # run tests (excludes live)
make test-cov     # tests with coverage report
make pre-commit   # run all pre-commit hooks
make ci           # full local CI equivalent (lint + security + test-cov)
make check-all    # lint + tests across all supported Python versions
make help         # list all targets
```

## Tests

```bash
make test                    # default: excludes @pytest.mark.live
make test-cov-lowest-direct  # resolve lowest dep bounds, then test
make check-all               # isolated envs for each supported Python version
```

Live end-to-end tests require explicit opt-in:

```bash
CB_RUN_LIVE_TESTS=1 CB_EVENTS_URL="https://eventsapi.chaturbate.com/events/user/token/" \
  make test-live
```

## Dependency Management

The lock file is maintained by Renovate, which opens automated PRs weekly. You don't
normally need to touch it. If you need to pull in a specific package ahead of the next
update:

```bash
uv lock --upgrade-package aiohttp
```

## Commit Messages

[Conventional Commits](https://www.conventionalcommits.org/) format is enforced. A scope
is required:

```text
feat(router): add handler priority support
fix(client): handle empty nextUrl in timeout response
docs(readme): clarify token generation
```

Types: `feat` → minor bump, `fix`/`perf` → patch bump. Breaking changes: add `!` or a
`BREAKING CHANGE:` footer.

## Releases

Automated via python-semantic-release on merge to `main`. No manual steps required.

## PR Checklist

- Tests added or updated for any changed behaviour
- Docstrings and docs updated for any changed public API
- `make ci` passes locally

## Code of Conduct

By contributing, you agree to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).
