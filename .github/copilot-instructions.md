---

# Chaturbate Events – Copilot Instructions

## Overview
Async Python wrapper for the Chaturbate Events API, delivering real-time event notifications.

> **Note:** This project is under active development. Breaking changes may occur at any time.

## Principles
- Async-first (`asyncio`)
- Strong type hints
- Custom exceptions
- Context manager for resources
- Token masking (show only last 4 chars)
- Exponential backoff (configurable)

## Features
- Real-time events: messages, tips, user actions, broadcast states, fan club joins, media purchases
- Token-based authentication (Events API scope)
- Longpoll JSON event feed (`nextUrl` pattern)
- Rate limit: 2000 requests/min

## Workflow
```bash
uv sync --dev           # Install dependencies
uv run ruff format      # Format code
uv run ruff check --fix # Lint and fix
make lint               # mypy, pylint, pyright, ty
make test               # Run tests
make test-cov           # Test with coverage
```

## Structure
```
src/chaturbate_events/
  __init__.py        # Exports
  client.py          # EventClient
  exceptions.py      # Custom exceptions
  models.py          # Pydantic models
  py.typed           # Typing marker
  router.py          # EventRouter

tests/
  __init__.py
  conftest.py        # Fixtures
  test_chaturbate_events.py
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

## API Response Example
See `examples/event_response_example.json` for a full event response structure.

> Note: In `event_response_example.json`, the asterisks (`***********`) in the `nextUrl` field represent a redacted API key/token. In real API responses, this will be a unique token string.

## Guidelines

### Code Style
- Follow Google Python Style Guide
- Use `uv` for dependencies
- Type hints and docstrings required
- Use custom exceptions

### Testing
- Use pytest fixtures
- Mock API responses
- Test both success and error cases
- Parametrize for event types

### Extension
- Update `__init__.__all__` for public API changes
- Use `EventsError` for exceptions
- Update tests/examples for new behavior

### Security
- Never log full tokens
- Avoid blocking calls in polling

## Pre-commit Checklist
- [ ] Tests for new features
- [ ] Lint passes (`make lint`)
- [ ] Public API documented
- [ ] High test coverage
