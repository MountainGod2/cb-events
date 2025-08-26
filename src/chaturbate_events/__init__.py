"""Chaturbate Events API Python package.

This package provides an async Python wrapper for the Chaturbate Events API,
enabling real-time event notifications and flexible event routing.

Core components:
- EventClient: Async HTTP client for polling and streaming events
- EventRouter: Decorator-based event handler registration and dispatch
- Event, EventType, and related models: Strongly-typed Pydantic models for API data
- Custom exceptions for error handling

See individual module docstrings and the project README for usage examples and details.
"""

from importlib.metadata import version as get_version

from .client import EventClient
from .exceptions import (
    AuthError,
    EventsError,
)
from .models import (
    Event,
    EventType,
    Message,
    RoomSubject,
    Tip,
    User,
)
from .router import EventRouter

__version__ = get_version("chaturbate-events")
__all__ = [
    "AuthError",
    "Event",
    "EventClient",
    "EventRouter",
    "EventType",
    "EventsError",
    "Message",
    "RoomSubject",
    "Tip",
    "User",
]
