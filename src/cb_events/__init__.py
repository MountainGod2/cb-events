"""Async client for the Chaturbate Events API.

This library provides a high-level async client for streaming real-time events
from Chaturbate with automatic retries, rate limiting, and type-safe event
handling.

Key Components:
    EventClient: Async context manager for API polling.
    Router: Decorator-based event dispatcher.
    Event: Type-safe event model with nested data accessors.
    ClientConfig: Immutable configuration for client behavior.

Example:
    Basic usage with event routing::

        import asyncio
        from cb_events import EventClient, Router, EventType, Event

        router = Router()

        @router.on(EventType.TIP)
        async def handle_tip(event: Event) -> None:
            if event.tip and event.user:
                print(f"{event.user.username} tipped {event.tip.tokens} tokens")

        async def main() -> None:
            async with EventClient("username", "token") as client:
                async for event in client:
                    await router.dispatch(event)

        asyncio.run(main())
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
