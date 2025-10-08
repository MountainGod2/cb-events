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

    async def test_handler_error_default_behavior(self, router, simple_tip_event):
        """Test that handler errors are logged but don't stop dispatch by default."""
        successful_handler = AsyncMock()
        failing_handler = AsyncMock(side_effect=ValueError("Test error"))
        another_handler = AsyncMock()

        router.on(EventType.TIP)(successful_handler)
        router.on(EventType.TIP)(failing_handler)
        router.on(EventType.TIP)(another_handler)

        # Should not raise, continues to other handlers
        await router.dispatch(simple_tip_event)

        successful_handler.assert_called_once_with(simple_tip_event)
        failing_handler.assert_called_once_with(simple_tip_event)
        another_handler.assert_called_once_with(simple_tip_event)

    async def test_handler_error_with_raise_on_error(self, router, simple_tip_event):
        """Test that raise_on_error=True raises RouterError on handler failure."""
        successful_handler = AsyncMock()
        failing_handler = AsyncMock(side_effect=ValueError("Test error"))
        never_called = AsyncMock()

        router.on(EventType.TIP)(successful_handler)
        router.on(EventType.TIP)(failing_handler)
        router.on(EventType.TIP)(never_called)

        with pytest.raises(RouterError) as exc_info:
            await router.dispatch(simple_tip_event, raise_on_error=True)

        # Verify error details
        assert exc_info.value.event_type == EventType.TIP.value
        assert exc_info.value.handler_name is not None
        assert isinstance(exc_info.value.original_error, ValueError)
        assert "Test error" in str(exc_info.value.original_error)

        # First handler should have been called
        successful_handler.assert_called_once_with(simple_tip_event)
        failing_handler.assert_called_once_with(simple_tip_event)
        # Third handler should not be called due to error
        never_called.assert_not_called()

    async def test_global_handler_error_with_raise_on_error(self, router, simple_tip_event):
        """Test that global handler errors are properly wrapped in RouterError."""
        failing_global = AsyncMock(side_effect=RuntimeError("Global handler failed"))
        specific_handler = AsyncMock()

        router.on_any()(failing_global)
        router.on(EventType.TIP)(specific_handler)

        with pytest.raises(RouterError) as exc_info:
            await router.dispatch(simple_tip_event, raise_on_error=True)

        assert exc_info.value.event_type == EventType.TIP.value
        assert isinstance(exc_info.value.original_error, RuntimeError)

        failing_global.assert_called_once_with(simple_tip_event)
        # Specific handler should not be called due to global handler error
        specific_handler.assert_not_called()

    async def test_global_handler_error_default_behavior(self, router, simple_tip_event):
        """Test that global handler errors don't stop specific handlers by default."""
        failing_global = AsyncMock(side_effect=RuntimeError("Global handler failed"))
        specific_handler = AsyncMock()

        router.on_any()(failing_global)
        router.on(EventType.TIP)(specific_handler)

        # Should not raise, continues to specific handlers
        await router.dispatch(simple_tip_event)

        failing_global.assert_called_once_with(simple_tip_event)
        specific_handler.assert_called_once_with(simple_tip_event)

    async def test_router_error_repr(self, router, simple_tip_event):
        """Test RouterError string representation."""
        failing_handler = AsyncMock(side_effect=ValueError("Test error"))
        failing_handler.__name__ = "test_handler"

        router.on(EventType.TIP)(failing_handler)

        with pytest.raises(RouterError) as exc_info:
            await router.dispatch(simple_tip_event, raise_on_error=True)

        error_repr = repr(exc_info.value)
        assert "RouterError" in error_repr
        assert "test_handler" in error_repr
        assert EventType.TIP.value in error_repr
        assert "ValueError" in error_repr
