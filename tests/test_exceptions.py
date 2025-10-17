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
