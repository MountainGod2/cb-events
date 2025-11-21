"""Event routing with decorator-based handler registration."""

import asyncio
import logging
from collections.abc import Awaitable, Callable
from functools import partial
from inspect import iscoroutinefunction

from .models import Event, EventType

logger: logging.Logger = logging.getLogger(__name__)
"""Logger for the cb_events.router module."""
type HandlerFunc = Callable[[Event], Awaitable[None]]


def _is_async_callable(func: object) -> bool:
    """Return whether ``func`` produces an awaitable when invoked once.

    Args:
        func: Candidate handler or callable-like object.

    Returns:
        ``True`` if the callable is async or returns a coroutine; otherwise
        ``False``.
    """
    if iscoroutinefunction(func):
        return True

    if callable(func):
        try:
            call_method = type(func).__call__
        except AttributeError:
            call_method = None
        if call_method and iscoroutinefunction(call_method):
            return True

    underlying = getattr(func, "func", None)
    if callable(underlying) and underlying is not func:
        return _is_async_callable(underlying)

    return False


def _handler_name(handler: object) -> str:
    """Return a safe name for logging handler failures.

    Args:
        handler: Handler object or partial.

    Returns:
        Best-effort human-readable name for logging.
    """
    seen: set[int] = set()
    current: object = handler

    while id(current) not in seen:
        seen.add(id(current))
        name: str | None = getattr(current, "__name__", None)
        if name:
            return name

        if isinstance(current, partial):
            current = current.func
            continue

        wrapped = getattr(current, "__wrapped__", None)
        if callable(wrapped) and wrapped is not current:
            current = wrapped
            continue

        func_attr = getattr(current, "func", None)
        if callable(func_attr) and func_attr is not current:
            current = func_attr
            continue

        break

    return type(current).__name__


class Router:
    """Routes events to registered handlers.

    Handlers run in registration order. Errors are logged but don't
    prevent other handlers from running.
    """

    __slots__: tuple[str, ...] = ("_handlers",)

    def __init__(self) -> None:
        """Initialize router with an empty handler registry."""
        self._handlers: dict[EventType | None, list[HandlerFunc]] = {}

    def on(self, event_type: EventType) -> Callable[[HandlerFunc], HandlerFunc]:
        """Register handler for a specific event type.

        Args:
            event_type: Event category to associate with the handler.

        Returns:
            Decorator that registers the handler and returns it unchanged.
        """

        def decorator(func: HandlerFunc) -> HandlerFunc:
            if not _is_async_callable(func):
                msg: str = f"Handler {_handler_name(func)} must be async"
                raise TypeError(msg)
            self._handlers.setdefault(event_type, []).append(func)
            return func

        return decorator

    def on_any(self) -> Callable[[HandlerFunc], HandlerFunc]:
        """Register handler for all event types.

        Returns:
            Decorator that registers the handler and returns it unchanged.
        """

        def decorator(func: HandlerFunc) -> HandlerFunc:
            if not _is_async_callable(func):
                msg: str = f"Handler {_handler_name(func)} must be async"
                raise TypeError(msg)
            self._handlers.setdefault(None, []).append(func)
            return func

        return decorator

    async def dispatch(self, event: Event) -> None:
        """Dispatch event to matching handlers.

        Wildcard handlers execute before type-specific handlers.

        Args:
            event: Event payload to route to registered handlers.
        """
        handlers: list[HandlerFunc] = [
            *self._handlers.get(None, []),
            *self._handlers.get(event.type, []),
        ]

        if not handlers:
            return

        logger.debug(
            "Dispatching %s event %s to %d handlers",
            event.type.value,
            event.id,
            len(handlers),
        )

        for handler in handlers:
            try:
                await handler(event)
            except Exception as exc:  # pylint: disable=broad-exception-caught
                if isinstance(exc, asyncio.CancelledError):
                    raise
                logger.exception(
                    "Handler %s failed for event %s (type: %s)",
                    _handler_name(handler),
                    event.id,
                    event.type.value,
                )
