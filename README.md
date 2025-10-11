# CB Events

Async Python client for the Chaturbate Events API with real-time event streaming.

[![PyPI](https://img.shields.io/pypi/v/cb-events)](https://pypi.org/project/cb-events/)
[![Python](https://img.shields.io/pypi/pyversions/cb-events)](https://pypi.org/project/cb-events/)
[![License](https://img.shields.io/github/license/MountainGod2/cb-events)](./LICENSE)

## Installation

```bash
$ uv pip install cb-events
```

## Usage
```python
import asyncio
import os
from cb_events import EventClient, EventRouter, EventType, Event

router = EventRouter()

@router.on(EventType.TIP)
async def handle_tip(event: Event) -> None:
    if event.user and event.tip:
        print(f"{event.user.username} tipped {event.tip.tokens} tokens")

@router.on(EventType.CHAT_MESSAGE)
async def handle_chat(event: Event) -> None:
    if event.user and event.message:
        print(f"{event.user.username}: {event.message.message}")

async def main():
    username = os.getenv("CB_USERNAME")
    token = os.getenv("CB_TOKEN")

    async with EventClient(username, token) as client:
        async for event in client:
            await router.dispatch(event)

asyncio.run(main())
```

## Event Types

- `TIP`, `FANCLUB_JOIN`, `MEDIA_PURCHASE`
- `CHAT_MESSAGE`, `PRIVATE_MESSAGE`
- `USER_ENTER`, `USER_LEAVE`, `FOLLOW`, `UNFOLLOW`
- `BROADCAST_START`, `BROADCAST_STOP`, `ROOM_SUBJECT_CHANGE`

## Configuration

Environment variables:

```bash
export CB_USERNAME="username"
export CB_TOKEN="api_token"
```

Direct instantiation:

```python
from cb_events import EventClient, EventClientConfig

client = EventClient("username", "token")
```

Configuration options (defaults shown):

```python
from cb_events import EventClient, EventClientConfig

client = EventClient(
    username="your_username",
    token="your_api_token",
    config=EventClientConfig(
        timeout=10,              # Timeout for API requests in seconds
        use_testbed=False,       # Use testbed API endpoint
        retry_attempts=8,        # Maximum retry attempts for failed requests
        retry_backoff=1.0,       # Initial backoff time in seconds
        retry_factor=2.0,        # Exponential backoff multiplier
        retry_max_delay=30.0,    # Maximum delay between retries in seconds
    )
)
```

Note: The `config` parameter must be passed as a keyword argument.

## Error Handling

```python
from cb_events import AuthError, EventsError, RouterError

try:
    async with EventClient(username, token) as client:
        async for event in client:
            await router.dispatch(event)
except AuthError:
    # Authentication failed (401/403)
    pass
except RouterError as e:
    # Handler execution failed
    print(f"Handler '{e.handler_name}' failed on {e.event_type}")
except EventsError as e:
    # API errors (HTTP errors, network issues)
    if e.status_code:
        print(f"API error {e.status_code}: {e.message}")
```

Handler exceptions are caught, logged, and re-raised as `RouterError` with context.

Automatic retry on 429, 5xx, and Cloudflare error codes. No retry on authentication errors.

## Requirements

- Python ≥3.11
- aiohttp, pydantic, aiolimiter

```bash
$ uv pip compile pyproject.toml -o requirements.txt
```

## License

MIT licensed. See [LICENSE](./LICENSE).

## Disclaimer

Not affiliated with Chaturbate.
