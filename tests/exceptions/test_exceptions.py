"""Tests for exception hierarchy and messaging."""

import pytest

from cb_events import AuthError, EventsError


@pytest.mark.parametrize(
    ("message", "status_code", "response_text", "expected_str"),
    [
        ("Test error message", None, None, "Test error message"),
        ("Request failed", 500, None, "Request failed (HTTP 500)"),
        ("Test error", 404, "Not found response", "Test error (HTTP 404)"),
        ("Body-only message", None, "Some response body", "Body-only message"),
    ],
)
def test_events_error_properties_and_str(
    message: str,
    status_code: int | None,
    response_text: str | None,
    expected_str: str,
) -> None:
    """EventsError should include message and optional HTTP status in its string
    representation, and store status_code and response_text as attributes."""
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


@pytest.mark.parametrize("status_code", [401, 403])
def test_auth_error_with_status_codes(status_code: int) -> None:
    """AuthError should include HTTP status code in its string representation
    when provided."""
    error = AuthError("Unauthorized", status_code=status_code)

    assert str(error) == f"Unauthorized (HTTP {status_code})"
    assert error.status_code == status_code
    assert isinstance(error, EventsError)
