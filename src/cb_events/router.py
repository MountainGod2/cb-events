"""Event routing system with decorator-based handler registration."""

import logging
from collections import defaultdict
from collections.abc import Awaitable, Callable

from .models import Event, EventType

logger = logging.getLogger(__name__)
"""logging.Logger: Default logger for the EventRouter module."""

EventHandler = Callable[[Event], Awaitable[None]]
"""Type alias for event handler functions."""


class EventRouter:
    """Routes events to registered handlers based on event type.

    Provides decorator-based registration of async event handlers for specific
    event types or all events. Handlers are called in registration order when
    events are dispatched.
    """

    def __init__(self) -> None:
        """Initialize the event router with handler registries."""
        self._handlers: dict[str, list[EventHandler]] = defaultdict(list)
        self._global_handlers: list[EventHandler] = []

    def on(self, event_type: EventType) -> Callable[[EventHandler], EventHandler]:
        """Register a handler for a specific event type.

        Args:
            event_type: The event type to handle.

        Returns:
            A decorator function that registers the handler for the specified
            event type.
        """
        type_key = event_type.value

        def decorator(func: EventHandler) -> EventHandler:
            self._handlers[type_key].append(func)
            return func

        return decorator

    def on_any(self) -> Callable[[EventHandler], EventHandler]:
        """Register a handler for all event types.

        Returns:
            A decorator function that registers the handler for all event types.
        """

        def decorator(func: EventHandler) -> EventHandler:
            self._global_handlers.append(func)
            return func

        return decorator

    async def dispatch(self, event: Event) -> None:
        """Dispatch an event to all matching registered handlers.

        Args:
            event: The event to dispatch to registered handlers.
        """
        logger.debug(
            "Dispatching %s event to %d handlers",
            event.type.value,
            len(self._global_handlers) + len(self._handlers.get(event.type.value, [])),
        )
        for handler in self._global_handlers:
            await handler(event)
        for handler in self._handlers.get(event.type.value, []):
            await handler(event)
