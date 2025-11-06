"""Dispatch tests for :class:`cb_events.Router`."""

import asyncio
from functools import partial
from unittest.mock import AsyncMock

import pytest

from cb_events import Event, EventType, Router

pytestmark = pytest.mark.asyncio


async def test_dispatch_to_specific_handler(
    router: Router,
    mock_handler: AsyncMock,
    simple_tip_event: Event,
) -> None:
    """An event should reach the handler registered for its type."""
    router.on(EventType.TIP)(mock_handler)

    await router.dispatch(simple_tip_event)

    mock_handler.assert_called_once_with(simple_tip_event)


async def test_dispatch_to_any_handler(
    router: Router,
    mock_handler: AsyncMock,
    sample_event: Event,
) -> None:
    """Handlers via ``on_any`` receive events regardless of type."""
    router.on_any()(mock_handler)

    await router.dispatch(sample_event)

    mock_handler.assert_called_once_with(sample_event)


async def test_dispatch_calls_multiple_handlers_in_order(
    router: Router,
    simple_tip_event: Event,
) -> None:
    """All handlers registered for a specific type should execute."""
    handler_one = AsyncMock()
    handler_two = AsyncMock()
    router.on(EventType.TIP)(handler_one)
    router.on(EventType.TIP)(handler_two)

    await router.dispatch(simple_tip_event)

    handler_one.assert_called_once_with(simple_tip_event)
    handler_two.assert_called_once_with(simple_tip_event)


async def test_no_error_when_no_handlers(
    router: Router,
    simple_tip_event: Event,
) -> None:
    """Dispatching without handlers should simply no-op."""
    await router.dispatch(simple_tip_event)


async def test_any_handlers_called_before_specific(
    router: Router,
    simple_tip_event: Event,
) -> None:
    """``on_any`` handlers should run before type-specific handlers."""
    specific_handler = AsyncMock()
    any_handler = AsyncMock()
    router.on(EventType.TIP)(specific_handler)
    router.on_any()(any_handler)

    follow_event = Event.model_validate({
        "method": EventType.FOLLOW.value,
        "id": "follow_event",
        "object": {},
    })

    await router.dispatch(simple_tip_event)
    await router.dispatch(follow_event)

    assert specific_handler.call_count == 1
    assert any_handler.call_count == 2
    specific_handler.assert_called_with(simple_tip_event)
    any_handler.assert_any_call(simple_tip_event)
    any_handler.assert_any_call(follow_event)


async def test_handler_exception_logged(
    router: Router,
    simple_tip_event: Event,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Handler exceptions should be logged without stopping dispatch."""

    async def failing_handler(event: Event) -> None:
        await asyncio.sleep(0)
        msg = "Handler failed"
        raise ValueError(msg)

    router.on(EventType.TIP)(failing_handler)

    await router.dispatch(simple_tip_event)
    assert "Handler failed" in caplog.text
    assert "failing_handler" in caplog.text


async def test_handler_failure_does_not_stop_execution(
    router: Router,
    simple_tip_event: Event,
) -> None:
    """Handlers after a failing one should still run."""
    handler_one = AsyncMock(side_effect=ValueError("Handler 1 failed"))
    handler_two = AsyncMock()
    handler_three = AsyncMock()
    router.on(EventType.TIP)(handler_one)
    router.on(EventType.TIP)(handler_two)
    router.on(EventType.TIP)(handler_three)

    await router.dispatch(simple_tip_event)

    handler_one.assert_called_once_with(simple_tip_event)
    handler_two.assert_called_once_with(simple_tip_event)
    handler_three.assert_called_once_with(simple_tip_event)


def test_reject_non_async_handler_on_decorator(router: Router) -> None:
    """Registering a non-async handler with on() should raise TypeError."""
    with pytest.raises(TypeError, match="must be async"):

        @router.on(EventType.TIP)  # pyright: ignore[reportArgumentType]
        def sync_handler(event: Event) -> None:
            pass


def test_reject_non_async_handler_on_any_decorator(router: Router) -> None:
    """Registering a non-async handler with on_any() should raise TypeError."""
    with pytest.raises(TypeError, match="must be async"):

        @router.on_any()  # pyright: ignore[reportArgumentType]
        def sync_handler(event: Event) -> None:
            pass


def test_reject_partial_sync_handler(router: Router) -> None:
    """Partial objects wrapping sync handlers should be rejected."""

    def sync_handler(event: Event, *, flag: bool) -> None:
        pass

    with pytest.raises(TypeError, match="must be async"):
        router.on(EventType.TIP)(partial(sync_handler, flag=True))


async def test_accept_partial_async_handler(
    router: Router,
    simple_tip_event: Event,
) -> None:
    """Async handlers wrapped in functools.partial should register."""
    seen: list[str] = []

    async def handler(event: Event, *, results: list[str]) -> None:  # noqa: RUF029
        results.append(event.id)

    router.on(EventType.TIP)(partial(handler, results=seen))

    await router.dispatch(simple_tip_event)

    assert seen == [simple_tip_event.id]


async def test_accept_async_callable_object(
    router: Router,
    simple_tip_event: Event,
) -> None:
    """Callable objects with async __call__ should register."""
    seen: list[str] = []

    class AsyncCallable:
        async def __call__(self, event: Event) -> None:
            seen.append(event.id)

    router.on(EventType.TIP)(AsyncCallable())

    await router.dispatch(simple_tip_event)

    assert seen == [simple_tip_event.id]


async def test_cancelled_error_propagates(
    router: Router,
    simple_tip_event: Event,
) -> None:
    """Dispatch should not swallow CancelledError from handlers."""

    async def cancel_handler(event: Event) -> None:  # noqa: RUF029
        raise asyncio.CancelledError

    router.on(EventType.TIP)(cancel_handler)

    with pytest.raises(asyncio.CancelledError):
        await router.dispatch(simple_tip_event)
