"""Tests for exception hierarchy and messaging."""

from cb_events import AuthError, EventsError


def test_events_error_message_round_trip() -> None:
    """Error messages should be preserved verbatim."""
    error = EventsError("Test error message")

    assert str(error) == "Test error message"
    assert isinstance(error, Exception)


def test_events_error_with_status_code() -> None:
    """Status codes should appear in the string representation."""
    error = EventsError("Request failed", status_code=500)

    assert str(error) == "Request failed (HTTP 500)"
    assert error.status_code == 500


def test_events_error_attributes() -> None:
    """Error attributes should be accessible."""
    error = EventsError(
        "Test error", status_code=404, response_text="Not found response"
    )

    assert error.status_code == 404
    assert error.response_text == "Not found response"
    assert str(error) == "Test error (HTTP 404)"


def test_events_error_minimal() -> None:
    """Error should work with only message."""
    error = EventsError("Simple error")

    assert error.status_code is None
    assert error.response_text is None
    assert str(error) == "Simple error"


def test_auth_error_inherits_events_error() -> None:
    """AuthError should subclass EventsError."""
    error = AuthError("Authentication failed")

    assert isinstance(error, EventsError)
    assert str(error) == "Authentication failed"
