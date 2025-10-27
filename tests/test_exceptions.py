"""Tests for exception classes."""

from cb_events import AuthError, EventsError


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
