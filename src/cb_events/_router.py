"""Async event routing primitives.

Provides decorator-based registration and dispatch for typed and wildcard
event handlers.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from inspect import getattr_static, iscoroutinefunction
from itertools import chain
from typing import TYPE_CHECKING, TypeAlias, overload

from ._models import Event

if TYPE_CHECKING:
    from ._models import EventType

_logger = logging.getLogger(__name__)
"""Logger for the cb_events.router module."""

HandlerFunc: TypeAlias = Callable[[Event], Awaitable[None]]
"""Async handler signature accepted by Router decorators."""


async def _dispatch_handler(handler: HandlerFunc, event: Event) -> None:
    """Run one handler and log failures without stopping dispatch.

    Args:
        handler: Async callable that processes the event.
        event: The event to pass to the handler.
    """
    try:
        await handler(event)
    # BaseException (including CancelledError) intentionally propagates
    except Exception:  # pylint: disable=broad-exception-caught
        _logger.exception(
            "Handler %s failed for event %s (type: %s)",
            _handler_name(handler),
            event.id,
            event.type,
        )


def _is_async_callable(func: object) -> bool:
    """Check if a callable can be awaited.

    Args:
        func: Object to check for async callability.

    Returns:
        True if func is an async function or has an async __call__, and False
        if func is not an async function and does not define an async __call__
        method (i.e., cannot be awaited).
    """
    if iscoroutinefunction(func):
        return True
    call_method = getattr_static(func, "__call__", None)  # pyright: ignore[reportAny]
    if call_method is not None and iscoroutinefunction(call_method):  # pyright: ignore[reportAny]
        return True
    underlying = getattr(func, "func", None)
    if callable(underlying) and underlying is not func:
        return _is_async_callable(underlying)
    return False


def _handler_name(handler: object) -> str:
    """Return a stable handler name for logging."""
    seen: set[int] = set()
    current = handler

    while id(current) not in seen:
        seen.add(id(current))
        name: str | None = getattr(current, "__name__", None)
        if name:
            return name

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
    """Dispatch events to registered async handlers.

    Wildcard handlers run before type-specific handlers. Exceptions raised by
    handlers are logged and do not stop dispatch of remaining handlers.
    """

    def __init__(self) -> None:
        """Initialize an empty handler registry."""
        self._handlers: dict[EventType | None, list[HandlerFunc]] = {}

    def _register(self, key: EventType | None, func: HandlerFunc) -> HandlerFunc:
        """Validate and register a handler.

        Args:
            key: Event type to register for, or None for wildcard handlers.
            func: Async handler to register.

        Returns:
            The same handler object.

        Raises:
            TypeError: If the handler is not async.
        """
        if not _is_async_callable(func):
            msg = f"Handler {_handler_name(func)} must be async"
            raise TypeError(msg)
        self._handlers.setdefault(key, []).append(func)
        return func

    def on(self, event_type: EventType) -> Callable[[HandlerFunc], HandlerFunc]:
        """Register a handler for one event type.

        Args:
            event_type: Event category to associate with the handler.

        Returns:
            Decorator that registers the handler and returns it unchanged.
        """

        def decorator(func: HandlerFunc) -> HandlerFunc:
            return self._register(event_type, func)

        return decorator

    @overload
    def on_any(self, func: None = None) -> Callable[[HandlerFunc], HandlerFunc]: ...

    @overload
    def on_any(self, func: HandlerFunc) -> HandlerFunc: ...

    def on_any(
        self,
        func: HandlerFunc | None = None,
    ) -> Callable[[HandlerFunc], HandlerFunc] | HandlerFunc:
        """Register a handler for all event types.

        Supports both @router.on_any and @router.on_any().

        Args:
            func: Optional handler when used as ``@router.on_any``.

        Returns:
            Registered handler when ``func`` is provided, otherwise a decorator.
        """
        if func is not None:
            return self._register(None, func)

        def decorator(handler: HandlerFunc) -> HandlerFunc:
            return self._register(None, handler)

        return decorator

    async def dispatch(self, event: Event) -> None:
        """Dispatch an event to matching handlers.

        Executes wildcard handlers first, then type-specific handlers, in
        registration order. Handler exceptions are caught, logged, and do not
        propagate or prevent other handlers from executing.

        Args:
            event: Event instance to dispatch to registered handlers.

        Note:
            Handlers run sequentially. A slow handler will delay all subsequent
            ones for that event.
        """
        any_handlers = tuple(self._handlers.get(None, ()))
        typed_handlers = tuple(self._handlers.get(event.type, ()))

        if not any_handlers and not typed_handlers:
            return

        handler_count = len(any_handlers) + len(typed_handlers)

        _logger.debug(
            "Dispatching %s event %s to %d handlers",
            event.type,
            event.id,
            handler_count,
        )

        for handler in chain(any_handlers, typed_handlers):
            await _dispatch_handler(handler, event)
