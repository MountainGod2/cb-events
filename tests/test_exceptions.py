"""Tests for EventsError, AuthError, and exception handling."""

from typing import Any

import pytest

from chaturbate_events import AuthError, EventsError


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
                "request_id": "12345",
                "timeout": 30.0,
            },
            [
                ("message", "Full error"),
                ("status_code", 500),
                ("response_text", "Server error response"),
                ("extra_info", {"request_id": "12345", "timeout": 30.0}),
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
        elif check_name == "extra_info":
            assert getattr(error_instance, "extra_info", None) == expected_value
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
