"""Tests for EventRouter and dispatch logic."""

from unittest.mock import AsyncMock

import pytest

from chaturbate_events import Event, EventRouter, EventType


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "event_type",
    [EventType.TIP, EventType.CHAT_MESSAGE, EventType.BROADCAST_START],
)
async def test_router_basic_dispatch(event_type: EventType) -> None:
    """Test EventRouter event dispatching to registered handlers."""
    router = EventRouter()
    handler = AsyncMock()
    router.on(event_type)(handler)

    event = Event.model_validate({"method": event_type.value, "id": "x", "object": {}})
    await router.dispatch(event)
    handler.assert_called_once_with(event)

    any_handler = AsyncMock()
    router.on_any()(any_handler)
    await router.dispatch(event)
    any_handler.assert_called_once_with(event)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("setup_func", "event_type", "expected_calls"),
    [
        ("setup_multiple_handlers", EventType.TIP, {"handler1": 1, "handler2": 1}),
        ("setup_no_handlers", EventType.TIP, {}),
        (
            "setup_global_and_specific",
            EventType.TIP,
            {"global_handler": 1, "tip_handler": 1, "follow_handler": 0},
        ),
    ],
)
async def test_router_advanced_scenarios(
    setup_func: str, event_type: EventType, expected_calls: dict[str, int]
) -> None:
    """Test various EventRouter dispatching scenarios."""
    router = EventRouter()
    handlers = {}

    if setup_func == "setup_multiple_handlers":
        handlers["handler1"] = AsyncMock()
        handlers["handler2"] = AsyncMock()
        router.on(event_type)(handlers["handler1"])
        router.on(event_type)(handlers["handler2"])
    elif setup_func == "setup_no_handlers":
        pass
    elif setup_func == "setup_global_and_specific":
        handlers["global_handler"] = AsyncMock()
        handlers["tip_handler"] = AsyncMock()
        handlers["follow_handler"] = AsyncMock()
        router.on_any()(handlers["global_handler"])
        router.on(EventType.TIP)(handlers["tip_handler"])
        router.on(EventType.FOLLOW)(handlers["follow_handler"])

    event = Event.model_validate({
        "method": event_type.value,
        "id": "test",
        "object": {},
    })
    await router.dispatch(event)

    for handler_name, expected_count in expected_calls.items():
        if handler_name in handlers:
            assert handlers[handler_name].call_count == expected_count
