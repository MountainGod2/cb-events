"""Event routing system with decorator-based handler registration."""

from collections import defaultdict
from collections.abc import Awaitable, Callable

from .models import Event, EventType

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

    def on(self, event_type: EventType | str) -> Callable[[EventHandler], EventHandler]:
        """Register a handler for a specific event type.

        Args:
            event_type: The event type to handle, either an EventType enum or string.

        Returns:
            A decorator function that registers the handler for the specified
            event type.
        """
        type_key = (
            event_type.value if isinstance(event_type, EventType) else str(event_type)
        )

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
        for handler in self._global_handlers:
            await handler(event)
        for handler in self._handlers.get(event.type.value, []):
            await handler(event)
