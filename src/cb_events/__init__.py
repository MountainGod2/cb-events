"""Public package API for cb_events.

Re-exports the client, router, models, configuration, and exceptions needed
for typical integration code.
"""

from __future__ import annotations

import logging
from importlib.metadata import PackageNotFoundError, version

from ._client import EventClient
from ._config import ClientConfig
from ._exceptions import (
    AuthError,
    ClientRequestError,
    EventsError,
    HttpStatusError,
    RateLimitError,
    ServerError,
)
from ._models import Event, EventType, Media, Message, RoomSubject, Tip, User
from ._router import HandlerFunc, Router

try:  # ruff: ignore[non-empty-init-module] # Version lookup at import time is intentional
    __version__: str = version("cb-events")
except PackageNotFoundError:  # pragma: no cover
    __version__ = "0.0.0"

logging.getLogger(__name__).addHandler(logging.NullHandler())  # ruff: ignore[non-empty-init-module] # Configuration of handlers is the prerogative of end-users


__all__ = [
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
