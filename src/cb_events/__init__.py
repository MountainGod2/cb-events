"""Async client for the Chaturbate Events API.

Stream real-time events from Chaturbate with automatic retries, rate limiting,
and type-safe event handling.

Example:
    >>> import asyncio
    >>> from cb_events import EventClient, EventRouter, EventType, Event
    >>>
    >>> router = EventRouter()
    >>>
    >>> @router.on(EventType.TIP)
    >>> async def handle_tip(event: Event) -> None:
    ...     if event.tip and event.user:
    ...         print(f"{event.user.username} tipped {event.tip.tokens} tokens")
    >>>
    >>> async def main():
    ...     async with EventClient("username", "token") as client:
    ...         async for event in client:
    ...             await router.dispatch(event)
    >>>
    >>> asyncio.run(main())
"""

from importlib.metadata import PackageNotFoundError, version

from .client import EventClient
from .config import EventClientConfig
from .exceptions import AuthError, EventsError
from .models import (
    Event,
    EventType,
    Message,
    RoomSubject,
    Tip,
    User,
)
from .router import EventHandler, EventRouter

try:
    __version__ = version("cb-events")
except PackageNotFoundError:
    __version__ = "0.0.0"

__all__: list[str] = [
    "AuthError",
    "Event",
    "EventClient",
    "EventClientConfig",
    "EventHandler",
    "EventRouter",
    "EventType",
    "EventsError",
    "Message",
    "RoomSubject",
    "Tip",
    "User",
]
