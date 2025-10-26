"""Event routing system with decorator-based handler registration."""

import logging
from collections import defaultdict
from collections.abc import Callable
from typing import Protocol

from .exceptions import RouterError
from .models import Event, EventType

logger = logging.getLogger(__name__)


class EventHandler(Protocol):  # pylint: disable=too-few-public-methods
    """Protocol for async event handler functions.

    Event handlers are async callables that accept an Event and return None.
    They are registered using the EventRouter.on() or EventRouter.on_any()
    decorators and are called sequentially when events are dispatched.

    Example:
        .. code-block:: python

            async def my_handler(event: Event) -> None:
                print(f"Received event: {event.type}")
    """

    async def __call__(self, event: Event) -> None:
        """Handle an event.

        Args:
            event: The event to handle.
        """
        ...  # pylint: disable=unnecessary-ellipsis


class EventRouter:
    """Routes events to registered handlers based on event type.

    Provides decorator-based registration of async event handlers for specific
    event types or all events. Handlers are called in registration order when
    events are dispatched, allowing multiple handlers per event type.
    """

    __slots__ = ("_handlers",)

    def __init__(self) -> None:
        """Initialize the event router with unified handler registry."""
        self._handlers: dict[EventType | None, list[EventHandler]] = defaultdict(list)

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
            self._handlers[None].append(func)
            return func

        return decorator

    async def dispatch(self, event: Event) -> None:
        """Dispatch an event to all matching registered handlers.

        All registered handlers are awaited sequentially. Handlers for the
        specific event type are called after any handlers registered for all
        event types. All handlers are attempted even if one fails. If any
        handlers raise exceptions, a RouterError is raised after all handlers
        have been attempted.

        Args:
            event: The event to dispatch.

        Raises:
            RouterError: If any handler raises an exception during execution.
                The first exception is included as the cause, and details of all
                failed handlers are logged.
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

        errors: list[tuple[str, Exception]] = []
        for handler in all_handlers:
            try:
                await handler(event)
            except Exception as e:  # pylint: disable=broad-except
                handler_name = getattr(handler, "__name__", repr(handler))
                errors.append((handler_name, e))
                logger.exception(
                    "Handler %s failed for event type %s",
                    handler_name,
                    event.type.value,
                )

        if errors:
            first_handler_name, first_error = errors[0]
            if len(errors) == 1:
                msg = f"Error in handler {first_handler_name} for event type {event.type.value}"
            else:
                failed_handlers = ", ".join(name for name, _ in errors)
                msg = (
                    f"{len(errors)} handlers failed for event type {event.type.value}: "
                    f"{failed_handlers}"
                )
            raise RouterError(
                msg,
                event_type=event.type,
                handler_name=first_handler_name,
            ) from first_error
