# Chaturbate Events

Async Python wrapper for Chaturbate Events API with real-time event notifications.

[![PyPI](https://img.shields.io/pypi/v/chaturbate-events)](https://pypi.org/project/chaturbate-events/)
[![Python](https://img.shields.io/pypi/pyversions/chaturbate-events)](https://pypi.org/project/chaturbate-events/)
[![License](https://img.shields.io/github/license/MountainGod2/chaturbate-events)](./LICENSE)

## Installation

```bash
pip install chaturbate-events
```

## Quick Start

```python
import asyncio
import os
from chaturbate_events import EventClient, EventRouter, EventType

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
client = EventClient(
    username="your_username",
    token="your_api_token",
    timeout=10,
    use_testbed=True  # For development
)
```

## Error Handling

```python
from chaturbate_events import EventsError, AuthError

try:
    async with EventClient(username, token) as client:
        async for event in client:
            await router.dispatch(event)
except AuthError:
    print("Invalid credentials")
except EventsError as e:
    print(f"API error: {e}")
```

## Requirements

- Python 3.11+
- aiohttp
- pydantic

## License

MIT licensed. See [LICENSE](./LICENSE).

## Disclaimer

Not affiliated with Chaturbate.
