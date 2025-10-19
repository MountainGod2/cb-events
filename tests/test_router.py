"""Tests for EventRouter functionality."""

from unittest.mock import AsyncMock

import pytest

from cb_events import Event, EventType, RouterError


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

    async def test_no_handlers_registered(self, router, simple_tip_event):
        # Should not raise an error
        await router.dispatch(simple_tip_event)

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

    async def test_handler_exception_wrapped(self, router, simple_tip_event):
        async def failing_handler(event):  # noqa: RUF029
            msg = "Handler failed"
            raise ValueError(msg)

        router.on(EventType.TIP)(failing_handler)

        with pytest.raises(RouterError) as exc_info:
            await router.dispatch(simple_tip_event)

        assert exc_info.value.event_type == EventType.TIP  # ty: ignore[unresolved-attribute]
        assert exc_info.value.handler_name == "failing_handler"  # ty: ignore[unresolved-attribute]
        assert isinstance(exc_info.value.__cause__, ValueError)

    async def test_system_exit_not_caught(self, router, simple_tip_event):
        async def exit_handler(event):  # noqa: RUF029
            raise SystemExit(1)

        router.on(EventType.TIP)(exit_handler)

        with pytest.raises(SystemExit):
            await router.dispatch(simple_tip_event)
