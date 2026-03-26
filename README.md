# CB Events

Async Python client for the Chaturbate Events API.

[![PyPI](https://img.shields.io/pypi/v/cb-events)](https://pypi.org/project/cb-events/)
[![Tag](https://img.shields.io/github/v/tag/MountainGod2/cb-events)](https://github.com/MountainGod2/cb-events/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/MountainGod2/cb-events/ci-cd.yml?label=ci)](https://github.com/MountainGod2/cb-events/actions/workflows/ci-cd.yml)
[![Python](https://img.shields.io/pypi/pyversions/cb-events)](https://pypi.org/project/cb-events/)
[![License](https://img.shields.io/github/license/MountainGod2/cb-events?label=license)](https://github.com/MountainGod2/cb-events/blob/main/LICENSE)

## Installation

```bash
pip install cb-events
```

With uv:

```bash
uv add cb-events
```

## Quick Start

```python
import asyncio
from cb_events import EventClient, Router, EventType, Event

router = Router()

username = "your_username"
token = "your_api_token"

@router.on(EventType.TIP)
async def handle_tip(event: Event) -> None:
    if event.user and event.tip:
        print(f"{event.user.username} tipped {event.tip.tokens} tokens")

async def main():
    async with EventClient(username, token) as client:
        async for event in client:
            await router.dispatch(event)

asyncio.run(main())
```

Generate API token at https://chaturbate.com/statsapi/authtoken/ with `Events API` scope.

See [example.py](https://github.com/MountainGod2/cb-events/blob/main/examples/example.py).

## Event Types

`TIP` · `FANCLUB_JOIN` · `MEDIA_PURCHASE` · `CHAT_MESSAGE` · `PRIVATE_MESSAGE` · `USER_ENTER` · `USER_LEAVE` · `FOLLOW` · `UNFOLLOW` · `BROADCAST_START` · `BROADCAST_STOP` · `ROOM_SUBJECT_CHANGE`

## Configuration

```python
from cb_events import ClientConfig

config = ClientConfig(
    timeout=10,                   # Request timeout (seconds)
    use_testbed=False,            # Use testbed endpoint with test tokens
    strict_validation=True,       # Raise on invalid events vs. skip
    retry_attempts=8,             # Total attempts (initial + retries)
    retry_backoff=1.0,            # Initial backoff (seconds)
    retry_factor=2.0,             # Backoff multiplier
    retry_max_delay=30.0,         # Max retry delay (seconds)
    next_url_allowed_hosts=None,  # List of allowed hostnames
)

client = EventClient(username, token, config=config)
```

## Rate Limiting

Default: 2000 requests/60s per client.

Shared limiter:

```python
from aiolimiter import AsyncLimiter

limiter = AsyncLimiter(max_rate=2000, time_period=60)
client1 = EventClient(username1, token1, rate_limiter=limiter)
client2 = EventClient(username2, token2, rate_limiter=limiter)
```

## Event Properties

```python
event.user          # User object (most events)
event.tip           # Tip object (TIP only)
event.message       # Message object (CHAT_MESSAGE, PRIVATE_MESSAGE)
event.room_subject  # RoomSubject object (ROOM_SUBJECT_CHANGE)
event.broadcaster   # Broadcaster username string
```

## Error Handling

```python
from cb_events import AuthError, EventsError

try:
    async with EventClient(username, token) as client:
        async for event in client:
            await router.dispatch(event)
except AuthError:
    # Authentication failed (401/403)
    pass
except EventsError as e:
    # API/network errors - check e.status_code, e.response_text
    pass
```

**Retries:** 429, 5xx, Cloudflare 521-524. Not retriable: 401/403.

**Handlers:** Sequential execution. Errors logged but don't stop processing.

## Logging

```python
import logging

logging.getLogger('cb_events').setLevel(logging.DEBUG)
```

## Requirements

Python ≥3.12

## License

MIT

---

> Not affiliated with Chaturbate.
