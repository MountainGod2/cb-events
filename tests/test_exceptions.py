"""Tests for exception classes and error handling."""

from cb_events import AuthError, EventsError, RouterError
from cb_events.models import EventType


class TestEventsError:
    """Test EventsError base exception class."""

    def test_basic_error_message(self):
        """Error message should be accessible as string."""
        error = EventsError("Test error message")

        assert str(error) == "Test error message"
        assert isinstance(error, Exception)

    def test_error_with_status_code(self):
        """Status code should be included in string representation."""
        error = EventsError("Request failed", status_code=500)

        assert str(error) == "Request failed (HTTP 500)"
        assert error.status_code == 500

    def test_repr_with_all_fields(self):
        """Repr should include all available error details."""
        error = EventsError("Test error", status_code=404, response_text="Not found response")
        repr_str = repr(error)

        assert "EventsError" in repr_str
        assert "Test error" in repr_str
        assert "status_code=404" in repr_str
        assert "response_text=" in repr_str

    def test_repr_with_minimal_fields(self):
        """Repr should work with only message."""
        error = EventsError("Simple error")
        repr_str = repr(error)

        assert "EventsError" in repr_str
        assert "Simple error" in repr_str
        assert "status_code" not in repr_str


class TestAuthError:
    """Test AuthError exception class."""

    def test_inherits_events_error(self):
        """AuthError should inherit from EventsError."""
        error = AuthError("Authentication failed")

        assert isinstance(error, EventsError)
        assert str(error) == "Authentication failed"


class TestRouterError:
    """Test RouterError exception class."""

    def test_error_with_context(self):
        """Error should store event type and handler name."""
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

    def test_repr_with_context(self):
        """Repr should include event type and handler name."""
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

    def test_repr_without_context(self):
        """Repr should work without optional fields."""
        error = RouterError("Generic error")
        repr_str = repr(error)

        assert "RouterError" in repr_str
        assert "Generic error" in repr_str
