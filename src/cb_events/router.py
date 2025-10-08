"""Event routing system with decorator-based handler registration."""

import logging
from collections import defaultdict
from collections.abc import Awaitable, Callable

from .exceptions import RouterError
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

    async def dispatch(self, event: Event, *, raise_on_error: bool = False) -> None:
        """Dispatch an event to all matching registered handlers.

        Calls all registered handlers for the given event. Global handlers
        (registered with on_any) are called first, followed by type-specific
        handlers. All handlers are awaited in registration order.

        By default, handler exceptions are logged but do not stop dispatch.
        If raise_on_error is True, the first handler exception will be wrapped
        in a RouterError and raised, stopping further handler execution.

        Args:
            event: The event to dispatch to registered handlers.
            raise_on_error: If True, raise RouterError on handler failure.
                If False (default), log errors and continue dispatch.

        Raises:
            RouterError: If raise_on_error is True and a handler raises an exception.
        """
        logger.debug(
            "Dispatching %s event to %d handlers",
            event.type.value,
            len(self._global_handlers) + len(self._handlers.get(event.type.value, [])),
        )

        # Dispatch to global handlers
        for handler in self._global_handlers:
            try:
                await handler(event)
            except Exception as e:
                handler_name = getattr(handler, "__name__", repr(handler))
                logger.exception(
                    "Error in global handler '%s' for %s event",
                    handler_name,
                    event.type.value,
                )
                if raise_on_error:
                    msg = f"Handler '{handler_name}' failed for {event.type.value} event"
                    raise RouterError(
                        msg,
                        event_type=event.type.value,
                        handler_name=handler_name,
                        original_error=e,
                    ) from e

        # Dispatch to type-specific handlers
        for handler in self._handlers.get(event.type.value, []):
            try:
                await handler(event)
            except Exception as e:
                handler_name = getattr(handler, "__name__", repr(handler))
                logger.exception(
                    "Error in handler '%s' for %s event",
                    handler_name,
                    event.type.value,
                )
                if raise_on_error:
                    msg = f"Handler '{handler_name}' failed for {event.type.value} event"
                    raise RouterError(
                        msg,
                        event_type=event.type.value,
                        handler_name=handler_name,
                        original_error=e,
                    ) from e
