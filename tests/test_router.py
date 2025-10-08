"""Tests for EventRouter functionality."""

from unittest.mock import AsyncMock

import pytest

from cb_events import Event, EventType


class TestEventRouter:
    async def test_basic_dispatch(self, router, mock_handler, simple_tip_event):
        router.on(EventType.TIP)(mock_handler)
        await router.dispatch(simple_tip_event)
        mock_handler.assert_called_once_with(simple_tip_event)

    async def test_any_handler(self, router, mock_handler, sample_event):
        router.on_any()(mock_handler)
        await router.dispatch(sample_event)
        mock_handler.assert_called_once_with(sample_event)

    async def test_multiple_handlers_same_event(self, router, simple_tip_event):
        handler1 = AsyncMock()
        handler2 = AsyncMock()

        router.on(EventType.TIP)(handler1)
        router.on(EventType.TIP)(handler2)

        await router.dispatch(simple_tip_event)

        handler1.assert_called_once_with(simple_tip_event)
        handler2.assert_called_once_with(simple_tip_event)

    async def test_no_handlers_registered(self, router):
        follow_event = Event.model_validate({
            "method": EventType.FOLLOW.value,
            "id": "test_event",
            "object": {},
        })

        await router.dispatch(follow_event)

    async def test_mixed_specific_and_any_handlers(self, router, simple_tip_event):
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

    @pytest.mark.parametrize(
        "event_type",
        [
            EventType.TIP,
            EventType.CHAT_MESSAGE,
            EventType.BROADCAST_START,
            EventType.USER_ENTER,
            EventType.FOLLOW,
        ],
    )
    async def test_all_event_types(self, router, mock_handler, event_type):
        router.on(event_type)(mock_handler)

        event = Event.model_validate({"method": event_type.value, "id": "test_event", "object": {}})

        await router.dispatch(event)
        mock_handler.assert_called_once_with(event)

    def test_decorator_registration(self, router):
        assert len(router._handlers) == 0

        @router.on(EventType.TIP)
        async def handler1(event):
            pass

        @router.on_any()
        async def handler2(event):
            pass

        assert EventType.TIP in router._handlers
        assert len(router._handlers[EventType.TIP]) == 1
        assert len(router._global_handlers) == 1
