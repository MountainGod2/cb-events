"""Event routing with decorator-based handler registration."""

import logging
from collections import defaultdict
from collections.abc import Callable
from typing import Protocol

from .models import Event, EventType

logger = logging.getLogger(__name__)


class EventHandler(Protocol):  # pylint: disable=too-few-public-methods
    """Protocol for async event handlers.

    Handlers are async callables that accept an Event and return None.
    Registered via EventRouter.on() or EventRouter.on_any() decorators.

    Example:
        .. code-block:: python

            async def my_handler(event: Event) -> None:
                print(f"Received event: {event.type}")
    """

    async def __call__(self, event: Event) -> None:
        """Handle an event.

        Args:
            event: Event to handle.
        """


class EventRouter:
    """Routes events to registered handlers.

    Decorator-based registration for specific event types or all events.
    Handlers are called in registration order.
    """

    __slots__ = ("_handlers",)

    def __init__(self) -> None:
        """Initialize the router."""
        self._handlers: dict[EventType | None, list[EventHandler]] = defaultdict(list)

    def on(self, event_type: EventType) -> Callable[[EventHandler], EventHandler]:
        """Register handler for specific event type.

        Decorator for registering async handlers for specific event types.
        Multiple handlers can be registered for the same type.

        Args:
            event_type: Event type to handle.

        Returns:
            Decorator that registers and returns the handler.

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
        """Register handler for all event types.

        Decorator for registering handlers called for every event.

        Returns:
            Decorator that registers and returns the handler.

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
        """Dispatch event to matching handlers.

        Handlers are awaited sequentially. Handlers for all events run first,
        then handlers for the specific event type.

        Important:
            If a handler raises an exception, it propagates immediately and stops
            subsequent handlers. Handle exceptions in your handlers if needed.

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
