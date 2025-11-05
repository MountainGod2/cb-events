"""Event routing with decorator-based handler registration."""

import logging
from collections.abc import Awaitable, Callable
from inspect import iscoroutinefunction

from .models import Event, EventType

logger: logging.Logger = logging.getLogger(__name__)


type HandlerFunc = Callable[[Event], Awaitable[None]]


class Router:
    """Routes events to registered handlers.

    Handlers run in registration order. Errors are logged but don't
    prevent other handlers from running.
    """

    __slots__ = ("_handlers",)

    def __init__(self) -> None:
        """Initialize router with empty handler registry."""
        self._handlers: dict[EventType | None, list[HandlerFunc]] = {}

    def on(self, event_type: EventType) -> Callable[[HandlerFunc], HandlerFunc]:
        """Register handler for a specific event type.

        Returns:
            Decorator that registers the handler.
        """

        def decorator(func: HandlerFunc) -> HandlerFunc:
            if not iscoroutinefunction(func):
                msg: str = f"Handler {func.__name__} must be async"
                raise TypeError(msg)
            self._handlers.setdefault(event_type, []).append(func)
            return func

        return decorator

    def on_any(self) -> Callable[[HandlerFunc], HandlerFunc]:
        """Register handler for all event types.

        Returns:
            Decorator that registers the handler.
        """

        def decorator(func: HandlerFunc) -> HandlerFunc:
            if not iscoroutinefunction(func):
                msg: str = f"Handler {func.__name__} must be async"
                raise TypeError(msg)
            self._handlers.setdefault(None, []).append(func)
            return func

        return decorator

    async def dispatch(self, event: Event) -> None:
        """Dispatch event to matching handlers.

        Wildcard handlers run first, then type-specific handlers.
        """
        handlers: list[HandlerFunc] = [
            *self._handlers.get(None, []),
            *self._handlers.get(event.type, []),
        ]

        if not handlers:
            return

        logger.debug(
            "Dispatching %s to %d handlers",
            event.type.value,
            len(handlers),
        )

        for handler in handlers:
            try:
                await handler(event)
            except Exception:  # pylint: disable=broad-exception-caught
                logger.exception(
                    "Handler %s failed for event %s",
                    handler.__name__,
                    event.id,
                )
