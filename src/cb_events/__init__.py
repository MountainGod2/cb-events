"""Async client for the Chaturbate Events API.

Stream real-time events from Chaturbate with automatic retries, rate limiting,
and type-safe event handling.

Main components:
    EventClient: HTTP client for polling events
    EventRouter: Decorator-based event handler registration
    Event: Type-safe event model with property access
    EventType: Enum of supported event types
    EventClientConfig: Client configuration and retry settings

Exceptions:
    EventsError: Base exception for API errors
    AuthError: Authentication failures
    ValidationError: Invalid event data (from pydantic)

Important:
    Event properties (user, tip, message, room_subject) return None if data
    is present but invalid. Set strict_validation=False in config to skip
    invalid events during polling instead of raising ValidationError.

    Models use extra="forbid" - unknown fields cause ValidationError.

Example:
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
    The config parameter must be passed as a keyword argument.
"""

from importlib.metadata import version

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

__version__ = version("cb-events")
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
