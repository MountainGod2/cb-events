# Chaturbate Events

An asynchronous client for the Chaturbate Events API.

## Installation

```bash
pip install chaturbate-events
```

## Quick Start

```python
import asyncio
from chaturbate_events import EventClient, EventRouter, EventType

async def main():
    router = EventRouter()
    client = EventClient("your_username", "your_token")

    @router.on(EventType.TIP)
    async def on_tip(event):
        amount = event.data.get("tip").get("tokens")
        user = event.data.get("user").get("username")
        print(f"Tip: {amount} tokens from {user}")

    async with client:
        async for event in client:
            await router.dispatch(event)

if __name__ == "__main__":
    asyncio.run(main())
```

## Disclaimer

This project is not affiliated with, endorsed by, or sponsored by Chaturbate.
