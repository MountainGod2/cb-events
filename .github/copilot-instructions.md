---

# Chaturbate Events – Copilot Instructions

## Overview
Async Python wrapper for Chaturbate Events API. Real-time event notifications with strong typing and rate limiting.

> **Status:** Active development. Breaking changes possible.

## Core Architecture
- **Async-first design**: All operations use asyncio with proper context management
- **Strong typing**: Full Pydantic models with type hints throughout
- **Security**: Token masking (last 4 chars), secure credential handling
- **Rate limiting**: Built-in 2000 req/min rate limiter with aiolimiter
- **Retry logic**: Configurable exponential backoff retry with aiohttp-retry
- **Environment integration**: `CB_USERNAME`, `CB_TOKEN` for credentials

## Key Components

### EventClient
- Async context manager for API connections
- Supports both production and testbed endpoints (`use_testbed=True`)
- Automatic rate limiting and timeout handling
- Configurable retry logic with exponential backoff (individual parameters)
- Iterator protocol for continuous event streaming

### EventRouter
- Decorator-based event handling (`@router.on`, `@router.on_any`)
- Type-safe event dispatching
- Multiple handlers per event type supported

### Models (Pydantic-based)
- `Event`: Core event container with type-safe property access
- `EventType`: String enum for all supported event types
- `User`, `Message`, `Tip`, `RoomSubject`: Typed data models
- All models use snake_case conversion and are frozen

## Development Commands
```bash
# Setup and dependencies
uv sync --all-groups    # Install all dependencies
make dev-setup          # First-time contributor setup
make install            # Basic installation

# Code quality
uv run ruff format      # Format code
uv run ruff check --fix # Lint and auto-fix
make type-check         # MyPy + Pyright
make lint               # Full static analysis (ruff + type + pylint)

# Testing
make test               # Run tests
make test-cov           # With coverage reports
make test-e2e           # End-to-end tests
make pre-commit         # Validate before commit

# Documentation
make docs               # Build Sphinx docs
make docs-serve         # Serve docs locally
```

## Event Types (EventType enum)
- **Broadcast**: `BROADCAST_START`, `BROADCAST_STOP`, `ROOM_SUBJECT_CHANGE`
- **Messages**: `CHAT_MESSAGE`, `PRIVATE_MESSAGE`
- **User activity**: `USER_ENTER`, `USER_LEAVE`, `FOLLOW`, `UNFOLLOW`
- **Monetization**: `TIP`, `FANCLUB_JOIN`, `MEDIA_PURCHASE`

## Development Standards
- **Python**: >=3.11 required, semantic versioning via python-semantic-release
- **Dependencies**: Core: aiohttp, aiohttp-retry, aiolimiter, pydantic; Dev: pytest, ruff, mypy, etc.
- **Code style**: Ruff formatting, strict type checking (mypy + pyright)
- **Testing**: pytest with asyncio, aioresponses for mocking, high coverage required
- **Test philosophy**: Modify tests to match codebase changes, not the reverse - maintain code integrity as source of truth
- **Documentation**: Sphinx with autoapi, Google-style docstrings
- **API changes**: Update `__init__.__all__` for public exports
- **Error handling**: Use `EventsError` base class, `AuthError` for auth failures
- **Security**: Never log full tokens, use token masking utilities
- **Performance**: Avoid blocking calls, use async context managers

## Usage Patterns
```python
# Basic usage with router
async with EventClient(username, token) as client:
    async for event in client:
        await router.dispatch(event)

# Type-safe event handling
@router.on(EventType.TIP)
async def handle_tip(event: Event) -> None:
    if event.tip and event.user:
        print(f"{event.user.username}: {event.tip.tokens} tokens")

# Custom retry configuration
async with EventClient(
    username,
    token,
    retry_attempts=5,
    retry_backoff=2.0,
    retry_max_delay=60.0
) as client:
    async for event in client:
        await router.dispatch(event)
```

*Reference: `examples/event_response_example.json` for API response structure*
