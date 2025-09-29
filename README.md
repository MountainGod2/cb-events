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
from cb_events import EventClient, EventRouter, EventType

router = EventRouter()

@router.on(EventType.TIP)
async def handle_tip(event):
    print(f"{event.user.username} tipped {event.tip.tokens} tokens")

@router.on(EventType.CHAT_MESSAGE)
async def handle_chat(event):
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
client = EventClient("username", "token")
```

Configuration options (defaults shown below):

```python
client = EventClient(
    username="your_username",
    token="your_api_token",
    config=EventClientConfig(
        timeout=10                   # Maximum time to wait for events
        use_testbed=False,           # Use Chaturbate testbed URL
        retry_attempts=8,            # Maximum retry attempts
        retry_backoff=1.0,           # Initial backoff delay in seconds
        retry_exponential_base=2.0   # Exponential backoff factor
        retry_max_delay=30.0,        # Maximum delay between retries
        )
    )
```

## Error Handling

```python
from cb_events.exceptions import AuthError, EventsError

try:
    async with EventClient(username, token) as client:
        async for event in client:
            await router.dispatch(event)
except AuthError:
    # Authentication failed
    pass
except EventsError as e:
    # API error
    pass
```

Automatic retry on 429, 5xx status codes. No retry on authentication errors.

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
