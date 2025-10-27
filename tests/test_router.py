"""Tests for EventRouter functionality."""

from unittest.mock import AsyncMock

import pytest

from cb_events import Event, EventType, RouterError


class TestEventRouter:
    """Test EventRouter event dispatching and handler registration."""

    async def test_dispatch_to_specific_handler(self, router, mock_handler, simple_tip_event):
        """Event should be dispatched to handler registered for its type."""
        router.on(EventType.TIP)(mock_handler)

        await router.dispatch(simple_tip_event)

        mock_handler.assert_called_once_with(simple_tip_event)

    async def test_dispatch_to_any_handler(self, router, mock_handler, sample_event):
        """Event should be dispatched to handlers registered for any type."""
        router.on_any()(mock_handler)

        await router.dispatch(sample_event)

        mock_handler.assert_called_once_with(sample_event)

    async def test_multiple_handlers_for_same_event(self, router, simple_tip_event):
        """All handlers for an event type should be called."""
        handler1 = AsyncMock()
        handler2 = AsyncMock()
        router.on(EventType.TIP)(handler1)
        router.on(EventType.TIP)(handler2)

        await router.dispatch(simple_tip_event)

        handler1.assert_called_once_with(simple_tip_event)
        handler2.assert_called_once_with(simple_tip_event)

    async def test_no_error_when_no_handlers(self, router, simple_tip_event):
        """Dispatching without handlers should not raise error."""
        await router.dispatch(simple_tip_event)

    async def test_any_handlers_called_before_specific(self, router, simple_tip_event):
        """'on_any' handlers should be called before specific handlers."""
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

    async def test_handler_exception_wrapped_in_router_error(self, router, simple_tip_event):
        """Handler exceptions should be wrapped in RouterError with context."""

        async def failing_handler(event):  # noqa: RUF029
            _ = event
            msg = "Handler failed"
            raise ValueError(msg)

        router.on(EventType.TIP)(failing_handler)

        with pytest.raises(RouterError) as exc_info:
            await router.dispatch(simple_tip_event)

        assert exc_info.value.event_type == EventType.TIP
        assert exc_info.value.handler_name == "failing_handler"
        assert isinstance(exc_info.value.__cause__, ValueError)

    async def test_all_handlers_execute_despite_failures(self, router, simple_tip_event):
        """All handlers should execute even if some fail."""
        handler1 = AsyncMock(side_effect=ValueError("Handler 1 failed"))
        handler2 = AsyncMock()
        handler3 = AsyncMock(side_effect=RuntimeError("Handler 3 failed"))
        handler4 = AsyncMock()
        router.on(EventType.TIP)(handler1)
        router.on(EventType.TIP)(handler2)
        router.on(EventType.TIP)(handler3)
        router.on(EventType.TIP)(handler4)

        with pytest.raises(RouterError) as exc_info:
            await router.dispatch(simple_tip_event)

        handler1.assert_called_once_with(simple_tip_event)
        handler2.assert_called_once_with(simple_tip_event)
        handler3.assert_called_once_with(simple_tip_event)
        handler4.assert_called_once_with(simple_tip_event)
        assert "2 handlers failed" in str(exc_info.value)
        assert exc_info.value.event_type == EventType.TIP

    async def test_system_exit_not_caught(self, router, simple_tip_event):
        """SystemExit should propagate without being caught."""

        async def exit_handler(event):  # noqa: RUF029
            _ = event
            raise SystemExit(1)

        router.on(EventType.TIP)(exit_handler)

        with pytest.raises(SystemExit):
            await router.dispatch(simple_tip_event)
