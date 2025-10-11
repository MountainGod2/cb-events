"""Tests for exceptions and error handling."""

import pytest

from cb_events import AuthError, EventsError, RouterError
from cb_events.models import EventType


class TestEventsError:
    def test_events_error_creation(self):
        error = EventsError("Test error message")
        assert str(error) == "Test error message"
        assert isinstance(error, Exception)

    def test_events_error_with_status_code(self):
        error = EventsError("Request failed", status_code=500)
        assert str(error) == "Request failed (HTTP 500)"
        assert error.status_code == 500

    def test_events_error_with_response_text(self):
        error = EventsError("Invalid response", status_code=400, response_text="Bad Request")
        assert str(error) == "Invalid response (HTTP 400)"
        assert error.response_text == "Bad Request"

    def test_events_error_repr(self):
        error = EventsError("Test", status_code=404, response_text="Not Found")
        repr_str = repr(error)
        assert "EventsError" in repr_str
        assert "message='Test'" in repr_str
        assert "status_code=404" in repr_str
        assert "response_text='Not Found'" in repr_str


class TestAuthError:
    def test_auth_error_creation(self):
        error = AuthError("Authentication failed")
        assert str(error) == "Authentication failed"
        assert isinstance(error, EventsError)
        assert isinstance(error, Exception)

    def test_auth_error_with_status_code(self):
        error = AuthError("Invalid token", status_code=401)
        assert str(error) == "Invalid token (HTTP 401)"
        assert error.status_code == 401

    def test_auth_error_inheritance(self):
        error = AuthError("Test auth error")
        assert isinstance(error, AuthError)
        assert isinstance(error, EventsError)

    def test_auth_error_repr(self):
        error = AuthError("Auth failed", status_code=403)
        assert "AuthError" in repr(error)
        assert "message='Auth failed'" in repr(error)
        assert "status_code=403" in repr(error)


class TestRouterError:
    def test_router_error_with_details(self):
        error = RouterError(
            "Handler execution failed",
            event_type=EventType.TIP,
            handler_name="handle_tip",
        )

        assert error.message == "Handler execution failed"
        assert error.event_type == EventType.TIP
        assert error.handler_name == "handle_tip"

    def test_router_error_str(self):
        error = RouterError(
            "Handler failed",
            event_type=EventType.TIP,
            handler_name="handle_tip",
        )
        error_str = str(error)
        assert "Handler failed" in error_str
        assert "event_type=tip" in error_str
        assert "handler=handle_tip" in error_str

    def test_router_error_str_minimal(self):
        error = RouterError("Simple error")
        assert str(error) == "Simple error"

    def test_router_error_repr(self):
        error = RouterError(
            "Handler failed",
            event_type=EventType.FOLLOW,
            handler_name="handle_follow",
        )
        repr_str = repr(error)
        assert "RouterError" in repr_str
        assert "message='Handler failed'" in repr_str
        assert "event_type=follow" in repr_str
        assert "handler_name='handle_follow'" in repr_str


class TestExceptionCompatibility:
    """Test backward compatibility and general exception behavior."""

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
        # Empty message edge case
        if message:
            assert message in str(error)
