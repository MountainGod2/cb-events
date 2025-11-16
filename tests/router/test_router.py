"""Dispatch tests for :class:`cb_events.Router`."""

import asyncio
from functools import partial
from unittest.mock import AsyncMock

import pytest

from cb_events import Event, EventType, Router


@pytest.mark.parametrize(
    "method",
    [
        EventType.TIP,
        EventType.FOLLOW,
        EventType.CHAT_MESSAGE,
        EventType.BROADCAST_START,
        EventType.BROADCAST_STOP,
        EventType.ROOM_SUBJECT_CHANGE,
        EventType.USER_ENTER,
        EventType.USER_LEAVE,
        EventType.UNFOLLOW,
        EventType.FANCLUB_JOIN,
        EventType.PRIVATE_MESSAGE,
        EventType.MEDIA_PURCHASE,
    ],
)
async def test_dispatch_to_specific_handler(
    router: Router,
    mock_handler: AsyncMock,
    method: EventType,
) -> None:
    """An event should reach the handler registered for its type."""
    router.on(method)(mock_handler)

    event = Event.model_validate(
        {"method": method.value, "id": "test", "object": {}},
    )
    await router.dispatch(event)

    mock_handler.assert_called_once_with(event)


@pytest.mark.parametrize(
    "method",
    [
        EventType.TIP,
        EventType.FOLLOW,
        EventType.CHAT_MESSAGE,
        EventType.BROADCAST_START,
        EventType.BROADCAST_STOP,
        EventType.ROOM_SUBJECT_CHANGE,
        EventType.USER_ENTER,
        EventType.USER_LEAVE,
        EventType.UNFOLLOW,
        EventType.FANCLUB_JOIN,
        EventType.PRIVATE_MESSAGE,
        EventType.MEDIA_PURCHASE,
    ],
)
async def test_dispatch_to_any_handler(
    router: Router,
    mock_handler: AsyncMock,
    method: EventType,
) -> None:
    """Handlers via ``on_any`` receive events regardless of type."""
    router.on_any()(mock_handler)
    event = Event.model_validate(
        {"method": method.value, "id": "test", "object": {}},
    )

    await router.dispatch(event)

    mock_handler.assert_called_once_with(event)


@pytest.mark.parametrize(
    "method",
    [EventType.TIP, EventType.FOLLOW, EventType.CHAT_MESSAGE],
)
async def test_dispatch_calls_multiple_handlers_in_order(
    router: Router,
    method: EventType,
) -> None:
    """All handlers registered for a specific type should execute."""
    handler_one = AsyncMock()
    handler_two = AsyncMock()
    router.on(method)(handler_one)
    router.on(method)(handler_two)

    event = Event.model_validate(
        {"method": method.value, "id": "test", "object": {}},
    )
    await router.dispatch(event)

    handler_one.assert_called_once_with(event)
    handler_two.assert_called_once_with(event)


@pytest.mark.parametrize(
    "method",
    [EventType.TIP, EventType.FOLLOW, EventType.CHAT_MESSAGE],
)
async def test_no_error_when_no_handlers(
    router: Router,
    method: EventType,
) -> None:
    """Dispatching without handlers should simply no-op."""
    event = Event.model_validate(
        {"method": method.value, "id": "test", "object": {}},
    )
    await router.dispatch(event)


@pytest.mark.parametrize(
    "method",
    [EventType.TIP, EventType.FOLLOW, EventType.CHAT_MESSAGE],
)
async def test_any_handlers_called_before_specific(
    router: Router,
    method: EventType,
) -> None:
    """``on_any`` handlers should run before type-specific handlers."""
    specific_handler = AsyncMock()
    any_handler = AsyncMock()
    router.on(method)(specific_handler)
    router.on_any()(any_handler)

    other_method = (
        EventType.FOLLOW if method != EventType.FOLLOW else EventType.TIP
    )
    event_one = Event.model_validate({
        "method": method.value,
        "id": "event_one",
        "object": {},
    })
    event_two = Event.model_validate({
        "method": other_method.value,
        "id": "event_two",
        "object": {},
    })

    await router.dispatch(event_one)
    await router.dispatch(event_two)

    assert specific_handler.call_count == 1
    assert any_handler.call_count == 2
    specific_handler.assert_called_with(event_one)
    any_handler.assert_any_call(event_one)
    any_handler.assert_any_call(event_two)


@pytest.mark.parametrize(
    "method",
    [EventType.TIP, EventType.FOLLOW, EventType.CHAT_MESSAGE],
)
async def test_handler_exception_logged(
    router: Router,
    method: EventType,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Handler exceptions should be logged without stopping dispatch."""

    async def failing_handler(event: Event) -> None:
        await asyncio.sleep(0)
        msg = "Handler failed"
        raise ValueError(msg)

    router.on(method)(failing_handler)

    event = Event.model_validate(
        {"method": method.value, "id": "event_1", "object": {}},
    )
    await router.dispatch(event)
    assert "Handler failed" in caplog.text
    assert "failing_handler" in caplog.text


@pytest.mark.parametrize(
    "method",
    [EventType.TIP, EventType.FOLLOW, EventType.CHAT_MESSAGE],
)
async def test_handler_failure_does_not_stop_execution(
    router: Router,
    method: EventType,
) -> None:
    """Handlers after a failing one should still run."""
    handler_one = AsyncMock(side_effect=ValueError("Handler 1 failed"))
    handler_two = AsyncMock()
    handler_three = AsyncMock()
    router.on(method)(handler_one)
    router.on(method)(handler_two)
    router.on(method)(handler_three)

    event = Event.model_validate({
        "method": method.value,
        "id": "test",
        "object": {},
    })
    await router.dispatch(event)

    handler_one.assert_called_once_with(event)
    handler_two.assert_called_once_with(event)
    handler_three.assert_called_once_with(event)


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


@pytest.mark.parametrize(
    "method",
    [EventType.TIP, EventType.FOLLOW, EventType.CHAT_MESSAGE],
)
def test_reject_partial_sync_handler(router: Router, method: EventType) -> None:
    """Partial objects wrapping sync handlers should be rejected."""

    def sync_handler(event: Event, *, flag: bool) -> None:
        pass

    with pytest.raises(TypeError, match="must be async"):
        router.on(method)(partial(sync_handler, flag=True))  # pyright: ignore[reportArgumentType]


@pytest.mark.parametrize(
    "method",
    [EventType.TIP, EventType.FOLLOW, EventType.CHAT_MESSAGE],
)
async def test_accept_partial_async_handler(
    router: Router,
    method: EventType,
) -> None:
    """Async handlers wrapped in functools.partial should register."""
    seen: list[str] = []

    async def handler(event: Event, *, results: list[str]) -> None:  # noqa: RUF029
        results.append(event.id)

    router.on(method)(partial(handler, results=seen))
    event = Event.model_validate(
        {"method": method.value, "id": "test", "object": {}},
    )

    await router.dispatch(event)

    assert seen == [event.id]


@pytest.mark.parametrize(
    "method",
    [EventType.TIP, EventType.FOLLOW, EventType.CHAT_MESSAGE],
)
async def test_accept_async_callable_object(
    router: Router,
    method: EventType,
) -> None:
    """Callable objects with async __call__ should register."""
    seen: list[str] = []

    class AsyncCallable:
        async def __call__(self, event: Event) -> None:
            seen.append(event.id)

    router.on(method)(AsyncCallable())
    event = Event.model_validate(
        {"method": method.value, "id": "test", "object": {}},
    )

    await router.dispatch(event)

    assert seen == [event.id]


@pytest.mark.parametrize(
    "method",
    [EventType.TIP, EventType.FOLLOW, EventType.CHAT_MESSAGE],
)
async def test_cancelled_error_propagates(
    router: Router,
    method: EventType,
) -> None:
    """Dispatch should not swallow CancelledError from handlers."""

    async def cancel_handler(event: Event) -> None:  # noqa: RUF029
        raise asyncio.CancelledError

    router.on(method)(cancel_handler)
    event = Event.model_validate(
        {"method": method.value, "id": "test", "object": {}},
    )

    with pytest.raises(asyncio.CancelledError):
        await router.dispatch(event)
