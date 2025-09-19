"""Tests for EventsError, AuthError, and exception handling."""

from typing import Any

import pytest

from chaturbate_events.exceptions import AuthError, EventsError


@pytest.mark.parametrize(
    ("error_class", "args", "kwargs", "expected_checks"),
    [
        (
            EventsError,
            ("Basic error message",),
            {},
            [
                ("message", "Basic error message"),
                ("status_code", None),
                ("response_text", None),
            ],
        ),
        (
            EventsError,
            ("Full error",),
            {
                "status_code": 500,
                "response_text": "Server error response",
            },
            [
                ("message", "Full error"),
                ("status_code", 500),
                ("response_text", "Server error response"),
            ],
        ),
        (
            AuthError,
            ("Authentication failed",),
            {"status_code": 401, "response_text": "Unauthorized"},
            [
                ("message", "Authentication failed"),
                ("status_code", 401),
                ("response_text", "Unauthorized"),
                ("isinstance_EventsError", True),
            ],
        ),
    ],
)
def test_exception_handling_comprehensive(
    error_class: type,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    expected_checks: list[tuple[str, Any]],
) -> None:
    """Test comprehensive exception handling for EventsError and AuthError."""
    error_instance = error_class(*args, **kwargs)

    for check_name, expected_value in expected_checks:
        if check_name == "isinstance_EventsError":
            assert isinstance(error_instance, EventsError)
        else:
            actual_value = getattr(error_instance, check_name, None)
            assert actual_value == expected_value

    if error_class == EventsError and kwargs:
        repr_str = repr(error_instance)
        message = getattr(error_instance, "message", None)
        if message is not None:
            assert message in repr_str
        status_code = getattr(error_instance, "status_code", None)
        if status_code is not None:
            assert (f"status_code={status_code}") in repr_str


def test_exception_repr_coverage() -> None:
    """Test __repr__ method coverage for different exception scenarios."""
    error_short_response = EventsError(
        "Test error", status_code=400, response_text="Short response"
    )
    repr_short = repr(error_short_response)
    assert "response_text='Short response'" in repr_short

    long_text = "A" * 100
    error_long_response = EventsError(
        "Test error", status_code=500, response_text=long_text
    )
    repr_long = repr(error_long_response)
    assert "..." in repr_long
    assert "AAAAAAAAAAAAAAAAAAAAAA" in repr_long

    error_no_response = EventsError("Test error", status_code=404)
    repr_no_response = repr(error_no_response)
    assert "response_text=" not in repr_no_response

    error_no_status = EventsError("Test error")
    repr_no_status = repr(error_no_status)
    assert "status_code=" not in repr_no_status
