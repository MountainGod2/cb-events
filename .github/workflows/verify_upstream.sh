#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${GITHUB_SHA:-}" ]]; then
    printf >&2 '%s\n' "::error::GITHUB_SHA is not set"
    exit 1
fi

if [[ -z "${GITHUB_REPOSITORY:-}" ]]; then
    printf >&2 '%s\n' "::error::GITHUB_REPOSITORY is not set"
    exit 1
fi

if [[ -z "${GH_TOKEN:-}" ]]; then
    printf >&2 '%s\n' "::error::GH_TOKEN is not set"
    exit 1
fi

UPSTREAM_SHA="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main" --jq '.object.sha')"

if [[ "$GITHUB_SHA" != "$UPSTREAM_SHA" ]]; then
    printf >&2 '%s\n' "[GITHUB_SHA]   $GITHUB_SHA"
    printf >&2 '%s\n' "[origin/main]  $UPSTREAM_SHA"
    printf >&2 '%s\n' "::error::Upstream has changed since workflow was triggered, aborting release..."
    exit 1
fi

printf '%s\n' "Verified upstream is unchanged (${GITHUB_SHA}), continuing with release..."
