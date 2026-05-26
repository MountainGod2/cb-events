# Quick Start

```python
import asyncio
from cb_events import Event, EventClient, EventType, Router

router = Router()

events_url = "https://eventsapi.chaturbate.com/events/your_username/your_api_token/"


@router.on(EventType.USER_ENTER)
async def handle_user_enter(event: Event) -> None:
    if event.user:
        print(f"{event.user.username} entered the room")


@router.on(EventType.TIP)
async def handle_tip(event: Event) -> None:
    if event.user and event.tip:
        print(f"{event.user.username} tipped {event.tip.tokens} tokens")


async def main() -> None:
    async with EventClient(events_url) as client:
        async for event in client:
            await router.dispatch(event)


asyncio.run(main())
```

**Example output**:

```text
mountaingod2 entered the room
mountaingod2 tipped 100 tokens
```

## Event Types

- `TIP`: User sends a tip.
- `FANCLUB_JOIN`: User joins fan club.
- `MEDIA_PURCHASE`: User purchases media.
- `CHAT_MESSAGE`: Public chat message.
- `PRIVATE_MESSAGE`: Private message received.
- `USER_ENTER`: User enters room.
- `USER_LEAVE`: User leaves room.
- `FOLLOW`: User follows broadcaster.
- `UNFOLLOW`: User unfollows broadcaster.
- `BROADCAST_START`: Broadcast begins.
- `BROADCAST_STOP`: Broadcast ends.
- `ROOM_SUBJECT_CHANGE`: Room subject updated.

## Catch-All Handler

```python
@router.on_any()
async def handle_all(event: Event) -> None:
    print(f"Event type: {event.type}")
```

## Multiple Handlers

```python
import logging

@router.on(EventType.TIP)
async def log_tip(event: Event) -> None:
    if event.tip:
        logging.info(f"Tip received: {event.tip.tokens}")


@router.on(EventType.TIP)
async def thank_tipper(event: Event) -> None:
    if event.user:
        print(f"Thanks for the tip, {event.user.username}!")
```

!!! note

    Handlers run sequentially in registration order. Regular handler exceptions are
    logged and dispatch continues. A failing handler does not stop other handlers.
    `asyncio.CancelledError` always propagates immediately.
