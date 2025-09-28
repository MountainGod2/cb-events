# CB Events

Async Python wrapper for Chaturbate Events API with real-time event notifications.

[![PyPI](https://img.shields.io/pypi/v/cb-events)](https://pypi.org/project/cb-events/)
[![Python](https://img.shields.io/pypi/pyversions/cb-events)](https://pypi.org/project/cb-events/)
[![License](https://img.shields.io/github/license/MountainGod2/cb-events)](./LICENSE)

## Installation

```bash
pip install cb-events
```

## Quick Start

```python
import asyncio
import os
from cb_events import EventClient, EventRouter, EventType

async def main():
    # Get credentials from environment
    username = os.getenv("CB_USERNAME")
    token = os.getenv("CB_TOKEN")

    router = EventRouter()

    @router.on(EventType.TIP)
    async def handle_tip(event):
        tip = event.tip
        user = event.user
        if tip and user:
            print(f"{user.username} tipped {tip.tokens} tokens")

    @router.on(EventType.CHAT_MESSAGE)
    async def handle_message(event):
        message = event.message
        user = event.user
        if message and user:
            print(f"{user.username}: {message.message}")

    async with EventClient(username, token) as client:
        async for event in client:
            await router.dispatch(event)

if __name__ == "__main__":
    asyncio.run(main())
```

## Event Types

Handle various broadcaster events:

- **Tips**: `TIP`
- **Chat**: `CHAT_MESSAGE`, `PRIVATE_MESSAGE`
- **Users**: `USER_ENTER`, `USER_LEAVE`, `FOLLOW`, `UNFOLLOW`
- **Broadcast**: `BROADCAST_START`, `BROADCAST_STOP`, `ROOM_SUBJECT_CHANGE`
- **Fanclub**: `FANCLUB_JOIN`
- **Media**: `MEDIA_PURCHASE`

## Configuration

Set credentials via environment variables:

```bash
export CB_USERNAME="your_username"
export CB_TOKEN="your_api_token"
```

Or pass directly to client:

```python
from cb_events import EventClient

client = EventClient(username="your_username"token="your_api_token")
```

### Retry Configuration

Configure retry behavior for handling network errors:

```python
from cb_events import EventClient

client = EventClient(
    username="your_username",
    token="your_api_token",
    config=EventClientConfig(
        timeout=10
        use_testbed=True,
        retry_attempts=5,            # Maximum retry attempts
        retry_backoff=2.0,           # Initial backoff delay in seconds
        retry_max_delay=60.0,        # Maximum delay between retries
        retry_exponential_base=2.0   # Exponential backoff factor
        )
    )
```

**Default retry behavior:**
- Retries on: 500, 502-504, 521-524 (Cloudflare), and 429 status codes
- No retry on: authentication errors (401, 403)
- 8 attempts with exponential backoff (1s, 2s, 4s...)
- Maximum delay: 30 seconds

## Error Handling

```python
from cb_events.exceptions import EventsError, AuthError

try:
    async with EventClient(username, token) as client:
        async for event in client:
            await router.dispatch(event)
except AuthError:
    logger.error("Authentication failed")
except EventsError as e:
    logger.error("API error: %s", e.message)
```

## Requirements

- Python 3.11+
- aiohttp
- pydantic
- aiolimiter

## License

MIT licensed. See [LICENSE](./LICENSE).

## Disclaimer

Not affiliated with Chaturbate.
