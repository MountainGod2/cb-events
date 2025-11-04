"""Event routing with decorator-based handler registration."""

import logging
from collections import defaultdict
from collections.abc import Awaitable, Callable
from functools import wraps
from inspect import isawaitable
from logging import Logger

from .models import Event, EventType

logger: Logger = logging.getLogger(__name__)


type EventCallback = Callable[[Event], Awaitable[None] | None]
type EventHandler = Callable[[Event], Awaitable[None]]


def _make_async(func: EventCallback) -> EventHandler:
    """Convert sync or async callback to async handler.

    Args:
        func: User-provided callback (sync or async).

    Returns:
        Async handler.
    """

    @wraps(func)
    async def wrapper(event: Event) -> None:
        result: Awaitable[None] | None = func(event)
        if isawaitable(result):
            await result

    return wrapper


class EventRouter:
    """Routes events to registered handlers.

    Handlers run in registration order. If a handler fails, the error
    is logged and remaining handlers still execute.
    """

    __slots__ = ("_handlers",)

    def __init__(self) -> None:
        """Initialize the router."""
        self._handlers: defaultdict[EventType | None, list[EventHandler]] = (
            defaultdict(list)
        )

    def on(
        self, event_type: EventType
    ) -> Callable[[EventCallback], EventCallback]:
        """Register handler for a specific event type.

        Args:
            event_type: Event type to handle.

        Returns:
            Decorator that registers and returns the handler.
        """

        def decorator(func: EventCallback) -> EventCallback:
            self._handlers[event_type].append(_make_async(func))
            return func

        return decorator

    def on_any(self) -> Callable[[EventCallback], EventCallback]:
        """Register handler for all event types.

        Returns:
            Decorator that registers and returns the handler.
        """

        def decorator(func: EventCallback) -> EventCallback:
            self._handlers[None].append(_make_async(func))
            return func

        return decorator

    async def dispatch(self, event: Event) -> None:
        """Dispatch event to matching handlers.

        Wildcard handlers (registered with on_any) run first, then
        type-specific handlers. Handler errors are logged but don't
        prevent other handlers from running.

        Args:
            event: Event to dispatch.
        """
        all_handlers: list[EventHandler] = [
            *self._handlers[None],
            *self._handlers[event.type],
        ]

        if not all_handlers:
            return

        logger.debug(
            "Dispatching %s to %d handlers",
            event.type.value,
            len(all_handlers),
        )

        for handler in all_handlers:
            try:
                await handler(event)
            except Exception:  # pylint: disable=broad-exception-caught
                logger.exception(
                    "Handler %s failed for event %s",
                    handler.__name__,
                    event.id,
                )
