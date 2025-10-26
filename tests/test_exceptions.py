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

    def test_error_repr(self):
        error = EventsError("Test error", status_code=404, response_text="Not found response")
        repr_str = repr(error)
        assert "EventsError" in repr_str
        assert "Test error" in repr_str
        assert "status_code=404" in repr_str
        assert "response_text=" in repr_str

    def test_error_repr_without_optional_fields(self):
        error = EventsError("Simple error")
        repr_str = repr(error)
        assert "EventsError" in repr_str
        assert "Simple error" in repr_str
        assert "status_code" not in repr_str


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

    def test_router_error_repr(self):
        error = RouterError(
            "Handler failed",
            event_type=EventType.FOLLOW,
            handler_name="my_handler",
        )
        repr_str = repr(error)
        assert "RouterError" in repr_str
        assert "Handler failed" in repr_str
        assert "event_type=" in repr_str
        assert "handler_name=" in repr_str

    def test_router_error_repr_without_optional_fields(self):
        error = RouterError("Generic error")
        repr_str = repr(error)
        assert "RouterError" in repr_str
        assert "Generic error" in repr_str
