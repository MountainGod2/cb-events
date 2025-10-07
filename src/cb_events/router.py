"""Event routing system with decorator-based handler registration."""

import logging
from collections import defaultdict
from collections.abc import Awaitable, Callable

from .models import Event, EventType

logger = logging.getLogger(__name__)

EventHandler = Callable[[Event], Awaitable[None]]


class EventRouter:
    """Routes events to registered handlers based on event type.

    Provides decorator-based registration of async event handlers for specific
    event types or all events. Handlers are called in registration order when
    events are dispatched, allowing multiple handlers per event type.

    Use the @router.on(EventType.X) decorator to register type-specific handlers,
    or @router.on_any() to register handlers that receive all events.

    Attributes:
        _handlers: Dictionary mapping event type values to lists of handlers.
        _global_handlers: List of handlers that receive all event types.
    """

    def __init__(self) -> None:
        """Initialize the event router with empty handler registries."""
        self._handlers: dict[str, list[EventHandler]] = defaultdict(list)
        self._global_handlers: list[EventHandler] = []

    def on(self, event_type: EventType) -> Callable[[EventHandler], EventHandler]:
        """Register a handler for a specific event type.

        Decorator that registers an async handler function to be called when
        events of the specified type are dispatched. Multiple handlers can be
        registered for the same event type.

        Args:
            event_type: The event type to handle.

        Returns:
            A decorator function that registers the handler for the specified
            event type and returns the original handler function.

        Example:
            .. code-block:: python

                @router.on(EventType.TIP)
                async def handle_tip(event: Event) -> None:
                    print(f"Received tip: {event.tip.tokens} tokens")
        """
        type_key = event_type.value

        def decorator(func: EventHandler) -> EventHandler:
            self._handlers[type_key].append(func)
            return func

        return decorator

    def on_any(self) -> Callable[[EventHandler], EventHandler]:
        """Register a handler for all event types.

        Decorator that registers an async handler function to be called for
        every event dispatched through this router, regardless of type.

        Returns:
            A decorator function that registers the handler for all event types
            and returns the original handler function.

        Example:
            .. code-block:: python

                @router.on_any()
                async def log_all_events(event: Event) -> None:
                    print(f"Event: {event.type.value}")
        """

        def decorator(func: EventHandler) -> EventHandler:
            self._global_handlers.append(func)
            return func

        return decorator

    async def dispatch(self, event: Event) -> None:
        """Dispatch an event to all matching registered handlers.

        Calls all registered handlers for the given event. Global handlers
        (registered with on_any) are called first, followed by type-specific
        handlers. All handlers are awaited in registration order.

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
