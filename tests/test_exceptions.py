"""Tests for exceptions and error handling."""

import pytest

from cb_events.exceptions import AuthError, EventsError


class TestExceptions:
    def test_events_error_creation(self):
        error = EventsError("Test error message")
        assert str(error) == "Test error message"
        assert isinstance(error, Exception)

    def test_auth_error_creation(self):
        error = AuthError("Authentication failed")
        assert str(error) == "Authentication failed"
        assert isinstance(error, EventsError)
        assert isinstance(error, Exception)

    def test_auth_error_inheritance(self):
        error = AuthError("Test auth error")
        assert isinstance(error, AuthError)
        assert isinstance(error, EventsError)

    def test_exception_repr(self):
        events_error = EventsError("Generic error")
        auth_error = AuthError("Auth error")

        assert "EventsError" in repr(events_error)
        assert "AuthError" in repr(auth_error)

    def test_exception_equality(self):
        error1 = EventsError("Same message")
        error2 = EventsError("Same message")
        error3 = EventsError("Different message")

        assert str(error1) == str(error2)
        assert str(error1) != str(error3)

    @pytest.mark.parametrize(
        ("error_class", "message"),
        [
            (EventsError, "Generic events error"),
            (AuthError, "Authentication failure"),
            (EventsError, ""),
            (AuthError, ""),
        ],
    )
    def test_error_messages(self, error_class, message):
        error = error_class(message)
        assert str(error) == message
