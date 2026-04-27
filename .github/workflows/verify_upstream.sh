#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${GITHUB_SHA:-}" ]]; then
    printf >&2 '%s\n' "::error::GITHUB_SHA is not set"
    exit 1
fi

git fetch --no-tags --depth=1 origin main

UPSTREAM_SHA="$(git rev-parse origin/main)"

if [[ "$GITHUB_SHA" != "$UPSTREAM_SHA" ]]; then
    printf >&2 '%s\n' "[GITHUB_SHA] $GITHUB_SHA != $UPSTREAM_SHA [origin/main]"
    printf >&2 '%s\n' "::error::Upstream has changed since workflow was triggered, aborting release..."
    exit 1
fi

printf '%s\n' "Verified upstream is unchanged, continuing with release..."
