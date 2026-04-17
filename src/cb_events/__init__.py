"""Async client for the Chaturbate Events API.

Provides automatic retries, rate limiting, and type-safe event handling.

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

from __future__ import annotations

from .client import EventClient
from .config import ClientConfig
from .exceptions import (
    AuthError,
    ClientRequestError,
    EventsError,
    HttpStatusError,
    RateLimitError,
    ServerError,
)
from .models import Event, EventType, Media, Message, RoomSubject, Tip, User
from .router import HandlerFunc, Router
from .version import __version__

__all__: tuple[str, ...] = (
    "AuthError",
    "ClientConfig",
    "ClientRequestError",
    "Event",
    "EventClient",
    "EventType",
    "EventsError",
    "HandlerFunc",
    "HttpStatusError",
    "Media",
    "Message",
    "RateLimitError",
    "RoomSubject",
    "Router",
    "ServerError",
    "Tip",
    "User",
    "__version__",
)
