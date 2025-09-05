---

# Chaturbate Events – Copilot Instructions

## Overview
Async Python wrapper for Chaturbate Events API. Real-time event notifications.

> **Note:** Active development. Breaking changes possible.

## Core Principles
- Async-first, strong typing, custom exceptions
- Context managers, token masking (last 4 chars only)
- Environment variables for credentials (`CB_USERNAME`, `CB_TOKEN`)

## Features
- Events: messages, tips, user actions, broadcasts, fanclub, media
- Token auth, longpoll JSON feed, 2000 req/min limit
- EventRouter with decorator-based handlers (@router.on, @router.on_any)
- Testbed support via `use_testbed=True`

## Commands
```bash
uv sync --dev           # Dependencies
uv run ruff format      # Format
uv run ruff check --fix # Lint+fix
make lint               # Type check
make test               # Tests
make test-cov           # With coverage
```

## Event Types
- `broadcastStart`, `broadcastStop`
- `message` (public/private)
- `tip`
- `userEnter`, `userLeave`
- `follow`, `unfollow`
- `fanclubJoin`
- `mediaPurchase`
- `roomSubjectChange`

## Guidelines
- Google Python Style Guide, use `uv`, type hints required
- Use pytest fixtures, mock API responses, parametrize tests
- Update `__init__.__all__` for public API changes
- Use `EventsError` for custom exceptions  
- Never log full tokens, avoid blocking calls
- Tests pass (`make lint`), high coverage required
- Requires Python >=3.11, core deps: aiohttp, pydantic

*API response structure: see `examples/event_response_example.json`*
