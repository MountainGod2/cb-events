# pyright: reportMissingParameterType=false
# pyright: reportUnknownParameterType=false
# pyright: reportUnknownArgumentType=false
# pyright: reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false

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


def test_events_error_repr_includes_details() -> None:
    """``repr`` should include all relevant fields when present."""
    error = EventsError("Test error", status_code=404, response_text="Not found response")
    repr_str = repr(error)

    assert "EventsError" in repr_str
    assert "Test error" in repr_str
    assert "status_code=404" in repr_str
    assert "response_text=" in repr_str


def test_events_error_repr_minimal() -> None:
    """``repr`` should also work when only the message is provided."""
    error = EventsError("Simple error")
    repr_str = repr(error)

    assert "EventsError" in repr_str
    assert "Simple error" in repr_str
    assert "status_code" not in repr_str


def test_auth_error_inherits_events_error() -> None:
    """AuthError should subclass EventsError."""
    error = AuthError("Authentication failed")

    assert isinstance(error, EventsError)
    assert str(error) == "Authentication failed"
