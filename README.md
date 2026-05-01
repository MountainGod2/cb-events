# CB Events

Async Python client for the Chaturbate Events API.

[![PyPI](https://img.shields.io/pypi/v/cb-events)](https://pypi.org/project/cb-events/)
[![Tag](https://img.shields.io/github/v/tag/MountainGod2/cb-events)](https://github.com/MountainGod2/cb-events/releases)
[![Python](https://img.shields.io/pypi/pyversions/cb-events)](https://pypi.org/project/cb-events/)
[![OpenSSF Best Practices](https://img.shields.io/cii/summary/12375?label=openssf%20best%20practices)](https://www.bestpractices.dev/en/projects/12375)
[![Builds](https://img.shields.io/github/actions/workflow/status/MountainGod2/cb-events/ci-cd.yml?label=builds)](https://github.com/MountainGod2/cb-events/actions/workflows/ci-cd.yml)
[![License](https://img.shields.io/github/license/MountainGod2/cb-events?label=license)](https://github.com/MountainGod2/cb-events/blob/main/LICENSE)

## Installation

```bash
pip install cb-events
```

With [uv](https://docs.astral.sh/uv/) (recommended):

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

```text
mountaingod2 tipped 100 tokens
```

For usage examples, see the [examples folder](https://github.com/MountainGod2/cb-events/blob/main/examples).

> [!NOTE]
> Generate an API token at https://chaturbate.com/statsapi/authtoken/ with `Events API` scope.

## Event Types

`TIP` · `FANCLUB_JOIN` · `MEDIA_PURCHASE` · `CHAT_MESSAGE` · `PRIVATE_MESSAGE` · `USER_ENTER` · `USER_LEAVE` · `FOLLOW` · `UNFOLLOW` · `BROADCAST_START` · `BROADCAST_STOP` · `ROOM_SUBJECT_CHANGE`

## Configuration

```python
from cb_events import ClientConfig

config = ClientConfig(
    timeout=10,                   # Server long-poll timeout (seconds)
    use_testbed=False,            # Use testbed endpoint (https://www.testbed.cb.dev)
    strict_validation=False,      # False skips & logs invalid events; True raises.
    retry_attempts=8,             # Total attempts (initial + retries)
    retry_backoff=1.0,            # Initial backoff (seconds)
    retry_factor=2.0,             # Backoff multiplier
    retry_max_delay=30.0,         # Max retry delay (seconds)
)

client = EventClient(username, token, config=config)
```

> **Testbed:** Register at <https://www.testbed.cb.dev>. New accounts include preloaded tokens for testing. Generate an API token the same way as a live account, then pass `use_testbed=True` with those credentials.

## Rate Limiting

Default: 2000 req/60s per client. Multiple clients each get an independent
budget unless a shared limiter is passed:

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
event.media         # Media object (MEDIA_PURCHASE)
event.room_subject  # RoomSubject object (ROOM_SUBJECT_CHANGE)
event.broadcaster   # Broadcaster username string or None
```

[See full docs for additional details](https://cb-events.readthedocs.io/latest/event_models.html).

## Error Handling

`AuthError` is a subclass of `EventsError` — `except EventsError` catches both. Put `AuthError` first if you need to distinguish them.

```python
import logging
import sys

from cb_events import AuthError, EventsError

logger = logging.getLogger(__name__)

try:
    async with EventClient(username, token) as client:
        async for event in client:
            await router.dispatch(event)
except AuthError:
    # Authentication failed (401/403) — never retried
    logger.error("Invalid credentials — check username and token")
    sys.exit(1)
except EventsError as e:
    # All other API/network errors — check e.status_code, e.response_text
    logger.error("API error %s: %s", e.status_code, e.response_text)
    raise
```

**Retries:** 429, 5xx, Cloudflare 521-524. Not retriable: 401/403.

**Handlers:** Sequential execution. Errors logged but don't stop processing.

## Logging

Set the logger to `DEBUG` for verbose polling data:

```python
import logging
logging.getLogger("cb_events").setLevel(logging.DEBUG)
```

Example output:

```text
DEBUG:cb_events.client:Polling https://eventsapi.chaturbate.com/events/user/************************/?timeout=10
DEBUG:cb_events.client:Received 1 events for user
DEBUG:cb_events.router:Dispatching chatMessage event 1775683684418-0 to 2 handlers
```

## Requirements

Python 3.10+

## License

MIT

---

Not affiliated with Chaturbate.
