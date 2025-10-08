"""Tests for exceptions and error handling."""

import pytest

from cb_events import AuthError, EventsError, RouterError


class TestExceptions:
    def test_events_error_creation(self):
        error = EventsError("Test error message")
        assert str(error) == "Test error message"
        assert isinstance(error, Exception)

    def test_auth_error_creation(self):
        error = AuthError("Authentication failed")
        assert str(error) == "Authentication failed"
        assert isinstance(error, EventsError)
        assert isinstance(error, Exception)

    def test_auth_error_inheritance(self):
        error = AuthError("Test auth error")
        assert isinstance(error, AuthError)
        assert isinstance(error, EventsError)

    def test_exception_repr(self):
        events_error = EventsError("Generic error")
        auth_error = AuthError("Auth error")

        assert "EventsError" in repr(events_error)
        assert "AuthError" in repr(auth_error)

    def test_exception_equality(self):
        error1 = EventsError("Same message")
        error2 = EventsError("Same message")
        error3 = EventsError("Different message")

        assert str(error1) == str(error2)
        assert str(error1) != str(error3)

    @pytest.mark.parametrize(
        ("error_class", "message"),
        [
            (EventsError, "Generic events error"),
            (AuthError, "Authentication failure"),
            (EventsError, ""),
            (AuthError, ""),
        ],
    )
    def test_error_messages(self, error_class, message):
        error = error_class(message)
        assert str(error) == message


class TestRouterError:
    def test_router_error_creation(self):
        error = RouterError("Handler failed")
        assert str(error) == "Handler failed"
        assert isinstance(error, EventsError)
        assert isinstance(error, Exception)

    def test_router_error_with_details(self):
        original = ValueError("Original error")
        error = RouterError(
            "Handler execution failed",
            event_type="tip",
            handler_name="handle_tip",
            original_error=original,
        )

        assert error.message == "Handler execution failed"
        assert error.event_type == "tip"
        assert error.handler_name == "handle_tip"
        assert error.original_error is original

    def test_router_error_repr(self):
        original = ValueError("Test error")
        error = RouterError(
            "Handler failed",
            event_type="chatMessage",
            handler_name="test_handler",
            original_error=original,
        )

        error_repr = repr(error)
        assert "RouterError" in error_repr
        assert "Handler failed" in error_repr
        assert "chatMessage" in error_repr
        assert "test_handler" in error_repr
        assert "ValueError" in error_repr

    def test_router_error_minimal(self):
        error = RouterError("Simple error")
        assert error.event_type is None
        assert error.handler_name is None
        assert error.original_error is None

    def test_router_error_inheritance(self):
        error = RouterError("Test error")
        assert isinstance(error, RouterError)
        assert isinstance(error, EventsError)
        assert isinstance(error, Exception)

    def test_router_error_chaining(self):
        """Test that RouterError properly chains exceptions."""
        original = ValueError("Original error")

        def raise_router_error():
            try:
                raise original
            except ValueError as e:
                msg = "Handler failed"
                raise RouterError(
                    msg,
                    event_type="tip",
                    handler_name="handle_tip",
                    original_error=e,
                ) from e

        with pytest.raises(RouterError) as exc_info:
            raise_router_error()

        router_error = exc_info.value
        assert router_error.original_error is original
        assert router_error.__cause__ is original
