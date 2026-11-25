# Contributing to cb-events

## Setup

Requires [uv](https://docs.astral.sh/uv/).

```bash
make setup
```

This installs all dependency groups, the supported Python versions, and the prek (pre-commit)
hooks.

`make setup` is equivalent to `uv sync --all-groups` followed by Python version installs and
installing prek hooks - either works if you would rather handle those steps yourself.

## Common Commands

```bash
make format       # format code
make fix          # format + apply lint autofixes
make lint         # lint, type-check, complexity
make test         # run tests (excludes live)
make test-cov     # tests with coverage report
make pre-commit   # run all prek (pre-commit) hooks
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

Releases are automated by the **Release** GitHub Actions workflow after a push to `main`:

1. The `build` job calculates the next semantic version with
    `python-semantic-release`, builds source and wheel distributions, and uploads
    the `dist` artifact. If no release-producing commit is present, the workflow
    stops normally and creates no release or PyPI publication.
1. The `e2e` job downloads that exact wheel, enables live tests, and runs them
    against the configured Events API URL. Live failures stop the workflow before
    semantic release or PyPI publishing.
1. The `release` job verifies the branch and upstream commit, then runs
    `python-semantic-release` to create the version commit and Git tag.
1. The `deploy` job downloads the built distributions and publishes them to
    PyPI using trusted publishing. PyPI publication uses `skip-existing=true`.

To retry only a failed PyPI upload, run the Release workflow manually with
`publish_tag` set to an existing release tag. The workflow checks out that tag,
rebuilds its distributions, and reruns trusted publishing. Rerunning the normal
push/release workflow is safe: semantic release will not recreate an existing
version, and PyPI skips distributions that already exist.

### Required GitHub Environments and Secrets

Configure these repository environments before releases:

- `testing` - used by CI test jobs.
- `e2e` - used by live release tests. It requires the `CB_EVENTS_URL` repository
    or environment secret and may also require repository access controls/approvers.
- `release` - used to create the GitHub release. It requires
    `RELEASE_APP_CLIENT_ID` and `RELEASE_APP_PRIVATE_KEY` secrets for a GitHub App
    with write access to repository contents.
- `pypi` - used for trusted PyPI publishing. Configure it as the trusted publisher
    for `cb-events` on PyPI and add deployment protection rules as appropriate.

The release workflow must also grant the GitHub Actions token the repository
permissions needed for the release App and PyPI attestation/ID-token operations.

## PR Checklist

- Tests added or updated for any changed behaviour
- Docstrings and docs updated for any changed public API
- `make ci` passes locally

## Code of Conduct

By contributing, you agree to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).
