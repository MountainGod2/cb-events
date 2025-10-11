"""Asynchronous Python wrapper for the Chaturbate Events API.

This package provides a complete async client for streaming real-time events
from the Chaturbate Events API. It includes automatic retry logic, rate limiting,
secure credential handling, and type-safe event routing.

Main Components:
    EventClient: Async HTTP client for polling and streaming events.
    EventRouter: Decorator-based event handler registration and dispatch.
    Event: Type-safe event model with property-based data access.
    EventType: Enumeration of all supported event types.
    EventClientConfig: Configuration for client behavior and retry logic.

Exception Classes:
    EventsError: Base exception for all API-related errors.
    AuthError: Authentication and authorization failures.

Example:
    Basic usage with async context manager and event router:

    .. code-block:: python

        import asyncio
        from cb_events import EventClient, EventRouter, EventType, Event

        router = EventRouter()

        @router.on(EventType.TIP)
        async def handle_tip(event: Event) -> None:
            if event.tip and event.user:
                print(f"{event.user.username} tipped {event.tip.tokens} tokens")

        async def main():
            async with EventClient(username="...", token="...", config=None) as client:
                async for event in client:
                    await router.dispatch(event)

        asyncio.run(main())

Note:
    The `config` parameter in EventClient must be passed as a keyword argument.

See individual module docstrings and the project README for detailed usage
examples and API documentation.
"""

from importlib.metadata import version as get_version

from .client import EventClient
from .config import EventClientConfig
from .exceptions import AuthError, EventsError, RouterError
from .models import (
    Event,
    EventType,
    Message,
    RoomSubject,
    Tip,
    User,
)
from .router import EventHandler, EventRouter

__version__ = get_version("cb-events")
__all__ = [
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
    "RouterError",
    "Tip",
    "User",
]
