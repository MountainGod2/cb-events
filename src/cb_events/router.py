"""Event routing system with decorator-based handler registration and safe handler execution."""

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
    """

    def __init__(self) -> None:
        """Initialize the event router with empty handler registries."""
        # Use EventType as the key rather than str; this keeps typing/enums consistent.
        self._handlers: dict[EventType, list[EventHandler]] = defaultdict(list)
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

        def decorator(func: EventHandler) -> EventHandler:
            self._handlers[event_type].append(func)
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

        All registered handlers are awaited sequentially.
        Exceptions in individual handlers are logged and ignored so they do
        not interrupt dispatch of subsequent handlers.

        Args:
            event: The event to dispatch.
        """
        event_type = event.type
        specific_handlers = self._handlers.get(event_type, [])
        all_handlers: list[EventHandler] = [*self._global_handlers, *specific_handlers]

        logger.debug(
            "Dispatching %s event to %d handlers",
            getattr(event_type, "value", str(event_type)),
            len(all_handlers),
        )

        for handler in all_handlers:
            try:
                await handler(event)
            except Exception:  # pylint: disable=broad-exception-caught
                logger.exception(
                    "Error in handler %r for event type %s",
                    getattr(handler, "__name__", repr(handler)),
                    getattr(event_type, "value", str(event_type)),
                )
