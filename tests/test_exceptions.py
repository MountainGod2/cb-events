"""Tests for exceptions and error handling."""

from cb_events import AuthError, EventsError, RouterError
from cb_events.models import EventType


class TestEventsError:
    def test_basic_error(self):
        error = EventsError("Test error message")
        assert str(error) == "Test error message"
        assert isinstance(error, Exception)

    def test_error_with_status_code(self):
        error = EventsError("Request failed", status_code=500)
        assert str(error) == "Request failed (HTTP 500)"
        assert error.status_code == 500


class TestAuthError:
    def test_auth_error_inherits_events_error(self):
        error = AuthError("Authentication failed")
        assert isinstance(error, EventsError)
        assert str(error) == "Authentication failed"


class TestRouterError:
    def test_router_error_with_details(self):
        error = RouterError(
            "Handler execution failed",
            event_type=EventType.TIP,
            handler_name="handle_tip",
        )

        assert error.args[0] == "Handler execution failed"
        assert error.event_type == EventType.TIP
        assert error.handler_name == "handle_tip"
        assert "tip" in str(error)
        assert "handle_tip" in str(error)
