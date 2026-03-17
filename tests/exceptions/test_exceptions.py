"""Tests for exception hierarchy and messaging."""

import pytest

from cb_events import AuthError, EventsError


@pytest.mark.parametrize(
    ("message", "status_code", "response_text", "expected_str"),
    [
        ("Test error message", None, None, "Test error message"),
        ("Request failed", 500, None, "Request failed (HTTP 500)"),
        ("Test error", 404, "Not found response", "Test error (HTTP 404)"),
    ],
)
def test_events_error_properties_and_str(
    message: str,
    status_code: int | None,
    response_text: str | None,
    expected_str: str,
) -> None:
    """EventsError should include message, status code, and response text in its
    string representation."""
    error = EventsError(
        message, status_code=status_code, response_text=response_text
    )

    assert str(error) == expected_str
    assert error.status_code == status_code
    assert error.response_text == response_text
    assert isinstance(error, Exception)


def test_auth_error_inherits_events_error() -> None:
    """AuthError should subclass EventsError."""
    error = AuthError("Authentication failed")

    assert isinstance(error, EventsError)
    assert str(error) == "Authentication failed"
