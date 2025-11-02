"""Event routing with decorator-based handler registration."""

import logging
from collections import defaultdict
from collections.abc import Awaitable, Callable

from .models import Event, EventType

logger = logging.getLogger(__name__)


type EventHandler = Callable[[Event], Awaitable[None]]


class EventRouter:
    """Routes events to registered handlers.

    Handlers are called in registration order. Use decorators to register handlers
    for specific event types or all events.
    """

    __slots__ = ("_handlers",)

    def __init__(self) -> None:
        """Initialize the router."""
        self._handlers: defaultdict[EventType | None, list[EventHandler]] = defaultdict(list)

    def on(self, event_type: EventType) -> Callable[[EventHandler], EventHandler]:
        """Register handler for a specific event type.

        Args:
            event_type: Event type to handle.

        Returns:
            Decorator that registers and returns the handler.
        """

        def decorator(func: EventHandler) -> EventHandler:
            self._handlers[event_type].append(func)
            return func

        return decorator

    def on_any(self) -> Callable[[EventHandler], EventHandler]:
        """Register handler for all event types.

        Returns:
            Decorator that registers and returns the handler.
        """

        def decorator(func: EventHandler) -> EventHandler:
            self._handlers[None].append(func)
            return func

        return decorator

    async def dispatch(self, event: Event) -> None:
        """Dispatch event to matching handlers.

        Handlers for all events run first, then handlers for the specific type.
        If a handler raises an exception, it stops subsequent handlers.

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
