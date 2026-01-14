"""Event routing with decorator-based handler registration.

This module provides the Router class for dispatching events to registered
async handlers based on event type.

Module Attributes:
    HandlerFunc: Type alias for async handler functions accepting an Event
        and returning None.

Example:
    Basic router setup::

        from cb_events import Router, EventType, Event

        router = Router()

        @router.on(EventType.TIP)
        async def handle_tip(event: Event) -> None:
            print(f"Tip received: {event.id}")

        @router.on_any()
        async def log_all(event: Event) -> None:
            print(f"Event: {event.type}")
"""

import logging
from collections.abc import Awaitable, Callable
from functools import partial
from inspect import iscoroutinefunction
from typing import cast

from .models import Event, EventType

logger: logging.Logger = logging.getLogger(__name__)
"""Logger for the cb_events.router module."""

type HandlerFunc = Callable[[Event], Awaitable[None]]
"""Async handler signature accepted by Router decorators."""

# Broad callable accepted by decorators (may be sync, partials, or wrappers).
Handler = Callable[[Event], object]


def _is_async_callable(func: object) -> bool:
    """Return whether func produces an awaitable when invoked once."""
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
    """Return a safe name for logging handler failures."""
    seen = set()
    current = handler

    while id(current) not in seen:
        seen.add(id(current))
        name = getattr(current, "__name__", None)
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
    """Routes events to registered async handlers.

    Provides decorator-based registration for event handlers with support for
    both type-specific and wildcard (catch-all) handlers. Handlers execute
    sequentially in registration order; errors are logged but do not prevent
    subsequent handlers from running.

    Example:
        Register and dispatch handlers::

            router = Router()

            @router.on(EventType.TIP)
            async def handle_tip(event: Event) -> None:
                print(f"Tip: {event.tip.tokens if event.tip else 0}")

            @router.on_any()
            async def log_event(event: Event) -> None:
                print(f"Event received: {event.type}")

            # In your event loop:
            await router.dispatch(event)

    Note:
        Wildcard handlers (registered via on_any()) execute before
        type-specific handlers for each event.
    """

    __slots__: tuple[str, ...] = ("_handlers",)

    def __init__(self) -> None:
        """Initialize router with an empty handler registry."""
        self._handlers: dict[EventType | None, list[HandlerFunc]] = {}

    def _register(self, key: EventType | None, func: Handler) -> Handler:
        """Validate and register a handler function.

        Args:
            key: Event type to register for, or None for wildcard handlers.
            func: Async handler function to register.

        Returns:
            The registered handler function unchanged.

        Raises:
            TypeError: If the handler is not async.
        """
        if not _is_async_callable(func):
            msg = f"Handler {_handler_name(func)} must be async"
            raise TypeError(msg)
        # Store as an async handler; cast to the stricter HandlerFunc type.
        self._handlers.setdefault(key, []).append(cast("HandlerFunc", func))
        return func

    def on(self, event_type: EventType) -> Callable[[Handler], Handler]:
        """Register handler for a specific event type.

        Args:
            event_type: Event category to associate with the handler.

        Returns:
            Decorator that registers the handler and returns it unchanged.
        """

        def decorator(func: Handler) -> Handler:
            return self._register(event_type, func)

        return decorator

    def on_any(self) -> Callable[[Handler], Handler]:
        """Register handler for all event types.

        Returns:
            Decorator that registers the handler and returns it unchanged.
        """

        def decorator(func: Handler) -> Handler:
            return self._register(None, func)

        return decorator

    async def dispatch(self, event: Event) -> None:
        """Dispatch an event to all matching handlers.

        Executes wildcard handlers first, then type-specific handlers, in
        registration order. Handler exceptions are caught, logged, and do not
        propagate or prevent other handlers from executing.

        Args:
            event: Event instance to dispatch to registered handlers.
        """
        handlers = [
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
            except Exception:  # pylint: disable=broad-exception-caught
                logger.exception(
                    "Handler %s failed for event %s (type: %s)",
                    _handler_name(handler),
                    event.id,
                    event.type.value,
                )
