# Quick Start

--8<-- "docs/snippets/quickstart.md"

**Example output**:

```text
mountaingod2 entered the room
mountaingod2 tipped 100 tokens
```

## Long Polling and `nextUrl`

The Events API uses long polling and returns a `nextUrl` continuation URL on each request.
`EventClient` follows that `nextUrl` automatically while iterating through events.

Use `await client.poll()` when you want one batch of events instead of continuous
iteration. It follows the same `nextUrl` progression and returns an empty list on
a long-poll timeout.

`EventClient` serializes polls per instance, so only one request is in flight
at a time for a given client. This keeps `nextUrl` progression consistent
without requiring extra synchronization in your application code.

Avoid restarting the client in the middle of a live stream. A restart creates a
new polling session, which can reset the `nextUrl` position and lead to missed or
duplicate events.

For the cleanest `nextUrl` progression, prefer a single polling consumer per
`EventClient` instance.

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
@router.on_any
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

    Dispatch runs handlers sequentially. `on_any` handlers run first, then
    handlers registered for the event type; within each group, handlers run in
    registration order. Regular handler exceptions are logged and dispatch
    continues, while `asyncio.CancelledError` propagates immediately.
