# CB Events

Async Python client for the Chaturbate Events API.

[![PyPI](https://img.shields.io/pypi/v/cb-events)](https://pypi.org/project/cb-events/)
[![Python](https://img.shields.io/pypi/pyversions/cb-events)](https://pypi.org/project/cb-events/)
[![License](https://img.shields.io/github/license/MountainGod2/cb-events)](https://github.com/MountainGod2/cb-events/blob/main/LICENSE)

## Installation

```bash
uv pip install cb-events
```

## Quick Start

```python
import asyncio
from cb_events import EventClient, EventRouter, EventType, Event

router = EventRouter()

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

## Event Types

`TIP` · `FANCLUB_JOIN` · `MEDIA_PURCHASE` · `CHAT_MESSAGE` · `PRIVATE_MESSAGE` · `USER_ENTER` · `USER_LEAVE` · `FOLLOW` · `UNFOLLOW` · `BROADCAST_START` · `BROADCAST_STOP` · `ROOM_SUBJECT_CHANGE`

## Configuration

```python
from cb_events import EventClientConfig

config = EventClientConfig(
    timeout=10,              # Request timeout (seconds)
    use_testbed=False,       # Use testbed endpoint
    retry_attempts=8,        # Max retry attempts
    retry_backoff=1.0,       # Initial backoff (seconds)
    retry_factor=2.0,        # Backoff multiplier
    retry_max_delay=30.0,    # Max retry delay (seconds)
)

client = EventClient(username, token, config=config)
```

**Note:** Config is immutable after creation. `config` parameter must be passed as keyword argument.

## Rate Limiting

Default: 2000 requests/60s per client. Share rate limiter across clients:

```python
from aiolimiter import AsyncLimiter

limiter = AsyncLimiter(max_rate=2000, time_period=60)
client1 = EventClient(username1, token1, rate_limiter=limiter)
client2 = EventClient(username2, token2, rate_limiter=limiter)
```

## Event Properties

Properties return `None` on incompatible event types:

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
    # API/network errors - e.status_code, e.response_text
    pass
```

**Retries:** Automatic on 429, 5xx, Cloudflare errors. No retry on auth errors.

**Handlers:** Execute sequentially. If a handler raises an exception, it propagates immediately and stops subsequent handlers.

## Logging

```python
import logging
```
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
    # API/network errors - e.status_code, e.response_text
    pass
```

**Retries:** Automatic on 429, 5xx, Cloudflare errors. No retry on auth errors.

**Handlers:** Execute sequentially. If a handler raises an exception, it propagates immediately and stops subsequent handlers.

## Logging

```python
import logging

logging.getLogger('cb_events').setLevel(logging.DEBUG)
```

## Requirements

Python ≥3.12 - [Dependencies](https://github.com/MountainGod2/cb-events/blob/main/pyproject.toml#L41)

## License

MIT - See [LICENSE](https://github.com/MountainGod2/cb-events/blob/main/LICENSE)

---

Not affiliated with Chaturbate.
