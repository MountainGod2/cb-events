"""Public package API for cb_events.

Re-exports the client, router, models, configuration, and exceptions needed
for typical integration code.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

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

try:  # noqa: RUF067 # Version lookup at import time is intentional
    __version__: str = version("cb-events")
except PackageNotFoundError:  # pragma: no cover
    __version__ = "0.0.0"


__all__: list[str] = [
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
]
