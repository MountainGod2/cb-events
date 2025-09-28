"""Tests for EventRouter and dispatch logic."""

from unittest.mock import AsyncMock

import pytest

from cb_events import Event, EventRouter, EventType


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "event_type",
    [EventType.TIP, EventType.CHAT_MESSAGE, EventType.BROADCAST_START, EventType.USER_ENTER],
)
async def test_router_basic_dispatch(
    event_type: EventType, event_router: EventRouter, mock_handler: AsyncMock
) -> None:
    """Test EventRouter event dispatching to registered handlers."""
    event_router.on(event_type)(mock_handler)

    event = Event.model_validate({"method": event_type.value, "id": "test_event", "object": {}})
    await event_router.dispatch(event)
    mock_handler.assert_called_once_with(event)


@pytest.mark.asyncio
async def test_router_any_handler(
    event_router: EventRouter, mock_handler: AsyncMock, sample_event: Event
) -> None:
    """Test EventRouter global 'any' event handler."""
    event_router.on_any()(mock_handler)
    await event_router.dispatch(sample_event)
    mock_handler.assert_called_once_with(sample_event)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("setup_scenario", "event_type", "expected_calls"),
    [
        ("multiple_specific", EventType.TIP, 2),
        ("no_handlers", EventType.FOLLOW, 0),
        ("mixed_handlers", EventType.TIP, 2),
    ],
)
async def test_router_advanced_scenarios(
    setup_scenario: str,
    event_type: EventType,
    expected_calls: int,
    event_router: EventRouter,
) -> None:
    """Test various EventRouter dispatching scenarios."""
    handlers = []

    if setup_scenario == "multiple_specific":
        handler1, handler2 = AsyncMock(), AsyncMock()
        event_router.on(event_type)(handler1)
        event_router.on(event_type)(handler2)
        handlers = [handler1, handler2]

    elif setup_scenario == "mixed_handlers":
        specific_handler, global_handler = AsyncMock(), AsyncMock()
        event_router.on(event_type)(specific_handler)
        event_router.on_any()(global_handler)
        handlers = [specific_handler, global_handler]

    event = Event.model_validate({"method": event_type.value, "id": "test", "object": {}})
    await event_router.dispatch(event)

    total_calls = sum(handler.call_count for handler in handlers)
    assert total_calls == expected_calls


def test_router_decorator_functionality(event_router: EventRouter) -> None:
    """Test EventRouter decorator registration functionality."""
    tip_handler = AsyncMock()
    decorated_handler = event_router.on(EventType.TIP)(tip_handler)
    assert decorated_handler is tip_handler
    assert EventType.TIP in event_router._handlers
    assert tip_handler in event_router._handlers[EventType.TIP]

    global_handler = AsyncMock()
    decorated_global = event_router.on_any()(global_handler)
    assert decorated_global is global_handler
    assert global_handler in event_router._global_handlers
