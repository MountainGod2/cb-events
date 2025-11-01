# pyright: reportMissingParameterType=false
# pyright: reportUnknownParameterType=false
# pyright: reportUnknownArgumentType=false
# pyright: reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false

"""Dispatch tests for :class:`cb_events.EventRouter`."""

import asyncio
from unittest.mock import AsyncMock

import pytest

from cb_events import Event, EventRouter, EventType

pytestmark = pytest.mark.asyncio


async def test_dispatch_to_specific_handler(
    router: EventRouter,
    mock_handler: AsyncMock,
    simple_tip_event: Event,
) -> None:
    """An event should reach the handler registered for its type."""
    router.on(EventType.TIP)(mock_handler)

    await router.dispatch(simple_tip_event)

    mock_handler.assert_called_once_with(simple_tip_event)


async def test_dispatch_to_any_handler(
    router: EventRouter,
    mock_handler: AsyncMock,
    sample_event: Event,
) -> None:
    """Handlers registered via ``on_any`` should receive events irrespective of type."""
    router.on_any()(mock_handler)

    await router.dispatch(sample_event)

    mock_handler.assert_called_once_with(sample_event)


async def test_multiple_handlers_for_same_event(
    router: EventRouter,
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
    router: EventRouter,
    simple_tip_event: Event,
) -> None:
    """Dispatching without handlers should simply no-op."""
    await router.dispatch(simple_tip_event)


async def test_any_handlers_called_before_specific(
    router: EventRouter,
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


async def test_handler_exception_propagates(
    router: EventRouter,
    simple_tip_event: Event,
) -> None:
    """Handler exceptions should surface."""

    async def failing_handler(event: Event) -> None:
        await asyncio.sleep(0)
        msg = "Handler failed"
        raise ValueError(msg)

    router.on(EventType.TIP)(failing_handler)

    with pytest.raises(ValueError, match="Handler failed"):
        await router.dispatch(simple_tip_event)


async def test_first_handler_failure_stops_execution(
    router: EventRouter,
    simple_tip_event: Event,
) -> None:
    """Handlers queued after a failing one should not run."""
    handler_one = AsyncMock(side_effect=ValueError("Handler 1 failed"))
    handler_two = AsyncMock()
    handler_three = AsyncMock()
    router.on(EventType.TIP)(handler_one)
    router.on(EventType.TIP)(handler_two)
    router.on(EventType.TIP)(handler_three)

    with pytest.raises(ValueError, match="Handler 1 failed"):
        await router.dispatch(simple_tip_event)

    handler_one.assert_called_once_with(simple_tip_event)
    handler_two.assert_not_called()
    handler_three.assert_not_called()
