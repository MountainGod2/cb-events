"""Event routing system with decorator-based handler registration."""

from collections.abc import Callable, Coroutine
from typing import Any

from .models import Event, EventType


class EventRouter:
    """Routes events to registered async handlers based on event type."""

    def __init__(self) -> None:
        """Initialize a new event router."""
        self._handlers: dict[
            str, list[Callable[[Event], Coroutine[Any, Any, None]]]
        ] = {}
        self._global_handlers: list[Callable[[Event], Coroutine[Any, Any, None]]] = []

    def on(
        self, event_type: EventType | str
    ) -> Callable[
        [Callable[[Event], Coroutine[Any, Any, None]]],
        Callable[[Event], Coroutine[Any, Any, None]],
    ]:
        """Register a handler for a specific event type."""
        type_key = (
            event_type.value if isinstance(event_type, EventType) else str(event_type)
        )

        def decorator(
            func: Callable[[Event], Coroutine[Any, Any, None]],
        ) -> Callable[[Event], Coroutine[Any, Any, None]]:
            self._handlers.setdefault(type_key, []).append(func)
            return func

        return decorator

    def on_any(
        self,
    ) -> Callable[
        [Callable[[Event], Coroutine[Any, Any, None]]],
        Callable[[Event], Coroutine[Any, Any, None]],
    ]:
        """Register a handler that receives all events."""

        def decorator(
            func: Callable[[Event], Coroutine[Any, Any, None]],
        ) -> Callable[[Event], Coroutine[Any, Any, None]]:
            self._global_handlers.append(func)
            return func

        return decorator

    async def dispatch(self, event: Event) -> None:
        """Invoke matching handlers for the given event."""
        # Execute global handlers first
        for handler in self._global_handlers:
            await handler(event)

        # Execute type-specific handlers
        for handler in self._handlers.get(event.type.value, []):
            await handler(event)
