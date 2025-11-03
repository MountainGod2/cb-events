"""Event routing with decorator-based handler registration."""

import logging
from collections import defaultdict
from collections.abc import Awaitable, Callable
from functools import wraps
from inspect import isawaitable

from .models import Event, EventType

logger = logging.getLogger(__name__)


type EventCallback = Callable[[Event], Awaitable[None] | None]
type EventHandler = Callable[[Event], Awaitable[None]]


def _normalize_handler(func: EventCallback) -> EventHandler:
    """Wrap callable so sync and async handlers share a common signature.

    Args:
        func: Handler from user.

    Returns:
        Async handler.
    """

    @wraps(func)
    async def wrapper(event: Event) -> None:
        result = func(event)
        if isawaitable(result):
            await result

    return wrapper


class EventRouter:
    """Routes events to registered handlers.

    Handlers are called in registration order.
    """

    __slots__ = ("_handlers",)

    def __init__(self) -> None:
        """Initialize the router."""
        self._handlers: defaultdict[EventType | None, list[EventHandler]] = (
            defaultdict(list)
        )

    def on(
        self, event_type: EventType
    ) -> Callable[[EventCallback], EventCallback]:
        """Register handler for a specific event type.

        Args:
            event_type: Event type to handle.

        Returns:
            Decorator that registers and returns the handler.
        """

        def decorator(func: EventCallback) -> EventCallback:
            self._handlers[event_type].append(_normalize_handler(func))
            return func

        return decorator

    def on_any(self) -> Callable[[EventCallback], EventCallback]:
        """Register handler for all event types.

        Returns:
            Decorator that registers and returns the handler.
        """

        def decorator(func: EventCallback) -> EventCallback:
            self._handlers[None].append(_normalize_handler(func))
            return func

        return decorator

    async def dispatch(self, event: Event) -> None:
        """Dispatch event to matching handlers.

        Handlers for all events run first, then type-specific handlers.
        If a handler raises an exception, subsequent handlers don't run.

        Args:
            event: Event to dispatch.

        Raises:
            Any exception raised by a handler.
        """
        all_handlers = [
            *self._handlers[None],
            *self._handlers[event.type],
        ]

        if not all_handlers:
            return

        logger.debug(
            "Dispatching %s event to %d handlers",
            event.type.value,
            len(all_handlers),
        )

        for handler in all_handlers:
            await handler(event)
