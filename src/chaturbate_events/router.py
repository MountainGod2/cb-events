"""Event routing system with decorator-based handler registration."""

from collections import defaultdict
from collections.abc import Callable, Coroutine

from .models import Event, EventType


class EventRouter:
    """Routes events to registered async handlers based on event type."""

    def __init__(self) -> None:
        """Initialize the event router with handler registries."""
        self._handlers: dict[
            str, list[Callable[[Event], Coroutine[object, object, None]]]
        ] = defaultdict(list)
        self._global_handlers: list[
            Callable[[Event], Coroutine[object, object, None]]
        ] = []

    def on(
        self, event_type: EventType | str
    ) -> Callable[
        [Callable[[Event], Coroutine[object, object, None]]],
        Callable[[Event], Coroutine[object, object, None]],
    ]:
        """Decorator to register a handler for a specific event type."""
        type_key = (
            event_type.value if isinstance(event_type, EventType) else str(event_type)
        )

        def decorator(
            func: Callable[[Event], Coroutine[object, object, None]],
        ) -> Callable[[Event], Coroutine[object, object, None]]:
            self._handlers[type_key].append(func)
            return func

        return decorator

    def on_any(
        self,
    ) -> Callable[
        [Callable[[Event], Coroutine[object, object, None]]],
        Callable[[Event], Coroutine[object, object, None]],
    ]:
        """Decorator to register a handler for all events."""

        def decorator(
            func: Callable[[Event], Coroutine[object, object, None]],
        ) -> Callable[[Event], Coroutine[object, object, None]]:
            self._global_handlers.append(func)
            return func

        return decorator

    async def dispatch(self, event: Event) -> None:
        """Invoke all matching handlers for the given event."""
        for handler in self._global_handlers:
            await handler(event)
        for handler in self._handlers.get(event.type.value, []):
            await handler(event)
