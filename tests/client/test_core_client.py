"""Core tests for client initialization, configuration and utils."""

from urllib.parse import quote

import pytest
from pydantic import ValidationError

from cb_events import ClientConfig, EventClient
from cb_events.client import (
    TOKEN_VISIBLE_CHARS,
    _mask_token,
    _mask_url,
    _parse_events,
)
from cb_events.exceptions import AuthError


def test_token_masking_in_repr() -> None:
    """Token should be fully masked in repr."""
    full_token = "secret_token_1234"
    client = EventClient("user", full_token)
    repr_str = str(client)

    assert full_token not in repr_str
    assert "*" * len(full_token) in repr_str
    assert TOKEN_VISIBLE_CHARS == 0


@pytest.mark.parametrize(
    ("username", "token", "message"),
    [
        ("", "token", "Username must not be empty or contain"),
        (" user ", "token", "Username must not be empty or contain"),
        ("user", "", "Token must not be empty or contain"),
        ("user", " token ", "Token must not be empty or contain"),
    ],
)
def test_reject_invalid_credentials(
    username: str, token: str, message: str
) -> None:
    """Invalid credentials should raise an ``AuthError`` with guidance."""
    with pytest.raises(AuthError, match=message):
        EventClient(username, token)


def test_mask_url_replaces_raw_and_encoded_token() -> None:
    """_mask_url should mask both plain and percent-encoded tokens in URLs.

    When TOKEN_VISIBLE_CHARS == 0 the token is fully redacted and no trailing
    characters are preserved in the masked output.
    """
    token = "super_secret_token_1234"
    encoded = quote(token, safe="")
    url = (
        f"https://events.testbed.cb.dev/events/user/{token}/"
        f"?t={token}&encoded={encoded}"
    )

    masked = _mask_url(url, token)

    assert token not in masked
    assert encoded not in masked
    assert TOKEN_VISIBLE_CHARS == 0


def test_mask_token_various_lengths() -> None:
    """_mask_token should mask tokens and preserve last visible chars.

    - If visible <= 0 or visible >= len(token), entire token is masked.
    - Otherwise, the last visible characters should be preserved.
    """
    token = "abcd1234"
    assert _mask_token(token, visible=20) == "*" * len(token)
    assert _mask_token(token, visible=0) == "*" * len(token)
    masked = _mask_token(token)
    assert masked == "*" * len(token)
    assert TOKEN_VISIBLE_CHARS == 0


def test_parse_events_strict_and_lenient(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """_parse_events should raise in strict mode and skip invalid events in
    lenient mode while logging a warning.
    """
    caplog.set_level("WARNING")
    valid = {"method": "tip", "id": "1", "object": {}}
    invalid = {"method": "tip", "object": {}}
    invalid_non_mapping = 123

    with pytest.raises(ValidationError):
        _parse_events([valid, invalid], strict=True)

    events = _parse_events([valid, invalid, invalid_non_mapping], strict=False)
    assert len(events) == 1
    assert events[0].id == "1"
    assert "Skipping invalid event" in caplog.text
    assert "<unknown>" in caplog.text


def test_parse_events_logs_invalid_fields(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Report nested invalid fields are logged when parsing events."""
    caplog.set_level("WARNING")
    invalid_nested = {
        "method": "tip",
        "id": "evt-xyz",
        "object": {"tip": {"tokens": "abc"}},
    }
    events = _parse_events([invalid_nested], strict=False)
    assert len(events) == 1
    assert events[0].tip is None
    assert "tokens" in caplog.text


def test_eventclient_build_url_and_repr() -> None:
    """Ensure the EventClient's private URL builder and repr mask token.

    We don't initialize an HTTP session here; we only inspect the constructed
    URL and the returned representation string.
    """
    token = "super_secret_token_1234"
    username = "username"
    client = EventClient(username, token, config=ClientConfig(use_testbed=True))

    url = client._build_url()
    assert quote(username, safe="") in url
    assert quote(token, safe="") in url

    r = repr(client)
    assert token not in r
    assert "*" * len(token) in r
    assert TOKEN_VISIBLE_CHARS == 0
