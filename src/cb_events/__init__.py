"""Async client for the Chaturbate Events API.

Stream real-time events from Chaturbate with automatic retries, rate limiting,
and type-safe event handling.

Example:
    >>> import asyncio
    >>> from cb_events import EventClient, Router, EventType, Event
    >>>
    >>> router = Router()
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
from .config import ClientConfig
from .exceptions import AuthError, EventsError
from .models import Event, EventType, Media, Message, RoomSubject, Tip, User
from .router import HandlerFunc, Router

try:
    __version__: str = version("cb-events")
except PackageNotFoundError:  # pragma: no cover
    __version__ = "0.0.0"

__all__: list[str] = [
    "AuthError",
    "ClientConfig",
    "Event",
    "EventClient",
    "EventType",
    "EventsError",
    "HandlerFunc",
    "Media",
    "Message",
    "RoomSubject",
    "Router",
    "Tip",
    "User",
]
