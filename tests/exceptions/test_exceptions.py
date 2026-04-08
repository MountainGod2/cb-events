"""Tests for exception hierarchy and messaging."""

import pytest

from cb_events import (
    AuthError,
    ClientRequestError,
    EventsError,
    HttpStatusError,
    RateLimitError,
    ServerError,
)
from cb_events.exceptions import build_http_error


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
    """EventsError should include message and optional HTTP status in its string representation, and store status_code and response_text as attributes."""
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


@pytest.mark.parametrize(
    ("status_code", "expected_type"),
    [
        (401, AuthError),
        (403, AuthError),
        (429, RateLimitError),
        (400, ClientRequestError),
        (404, ClientRequestError),
        (500, ServerError),
        (521, ServerError),
    ],
)
def test_build_http_error_returns_specific_subclasses(
    status_code: int,
    expected_type: type[EventsError],
) -> None:
    """HTTP statuses should map to targeted error subclasses."""
    error = build_http_error(
        "Request failed",
        status_code=status_code,
        response_text="response",
    )

    assert isinstance(error, expected_type)
    assert isinstance(error, EventsError)
    assert error.status_code == status_code


def test_build_http_error_returns_base_http_status_error_for_other_codes() -> (
    None
):
    """Unexpected statuses should fall back to HttpStatusError."""
    error = build_http_error("Request failed", status_code=302)

    assert type(error) is HttpStatusError
    assert error.status_code == 302


def test_events_error_truncates_long_response_text() -> None:
    """EventsError should truncate response_text longer than 200 chars to 203 characters (200 chars + '...')."""
    long_text = "x" * 300
    error = EventsError("Test", response_text=long_text)

    assert error.response_text is not None
    assert len(error.response_text) == 203
    assert error.response_text.endswith("...")


@pytest.mark.parametrize("status_code", [401, 403])
def test_auth_error_with_status_codes(status_code: int) -> None:
    """AuthError should include HTTP status code in its string representation when provided."""
    error = AuthError("Unauthorized", status_code=status_code)

    assert str(error) == f"Unauthorized (HTTP {status_code})"
    assert error.status_code == status_code
    assert isinstance(error, EventsError)
