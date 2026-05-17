"""Core tests for client initialization, configuration and utils."""

from unittest.mock import AsyncMock
from urllib.parse import quote

import pytest
from aiohttp.client_exceptions import ClientError
from pydantic import ValidationError

from cb_events import AuthError, ClientConfig, EventClient
from cb_events.client import (
    _mask_token,
    _mask_url,
    _parse_events,
)
from tests.helpers import make_events_url


def test_token_masking_in_repr() -> None:
    """Token should be fully masked in repr."""
    full_token = "secret_token_1234"
    client = EventClient(make_events_url("user", full_token))
    repr_str = str(client)

    assert full_token not in repr_str
    assert "*" * len(full_token) in repr_str


@pytest.mark.parametrize(
    ("events_url", "message"),
    [
        ("", "Events URL must not be empty or contain"),
        (
            "http://eventsapi.chaturbate.com/events/user/token/",
            "Events URL must use https",
        ),
        (
            "https://example.com/events/user/token/",
            "Events URL host is not supported",
        ),
        (
            "https://eventsapi.chaturbate.com/events/user/",
            "Events URL must match",
        ),
        (
            "https://eventsapi.chaturbate.com/events/user/token/?timeout=10",
            "must not include query parameters",
        ),
    ],
)
def test_reject_invalid_credentials(events_url: str, message: str) -> None:
    """Invalid URLs should raise an ``AuthError`` with guidance."""
    with pytest.raises(AuthError, match=message):
        EventClient(events_url)


def test_mask_url_replaces_raw_and_encoded_token() -> None:
    """_mask_url should mask both plain and percent-encoded tokens in URLs."""
    token = "super_secret_token_1234"
    encoded = quote(token, safe="")
    url = f"https://events.testbed.cb.dev/events/user/{token}/?t={token}&encoded={encoded}"

    masked = _mask_url(url, token)

    assert token not in masked
    assert encoded not in masked


def test_mask_token_various_lengths() -> None:
    """_mask_token should mask tokens and preserve last visible chars.

    - If visible <= 0 or visible >= len(token), entire token is masked.
    - Otherwise, the last visible characters should be preserved.
    """
    token = "abcd1234"
    assert _mask_token(token, visible=20) == "*" * len(token)
    assert _mask_token(token, visible=4) == "****1234"
    assert _mask_token(token, visible=0) == "*" * len(token)
    masked = _mask_token(token)
    assert masked == "*" * len(token)


def test_parse_events_strict_and_lenient(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """`_parse_events` should raise in strict mode and skip invalid events in lenient mode."""
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
    client = EventClient(
        make_events_url(username, token),
        config=ClientConfig(),
    )

    url = client._build_url()
    assert quote(username, safe="") in url
    assert quote(token, safe="") in url

    r = repr(client)
    assert token not in r
    assert "*" * len(token) in r


async def test_close_called_twice_does_not_raise() -> None:
    """Calling close() twice should be a no-op on the second call."""
    client = EventClient(make_events_url("user", "test_token"))
    await client.close()
    await client.close()


async def test_properties_accessible_after_close() -> None:
    """Username and session state should remain accessible after close()."""
    client = EventClient(make_events_url("user", "test_token"))
    await client.close()
    assert client.username == "user"
    assert client.session is None


@pytest.mark.parametrize(
    "exc_instance",
    [
        ClientError("connection reset"),
        OSError("broken pipe"),
        RuntimeError("event loop closed"),
    ],
    ids=["ClientError", "OSError", "RuntimeError"],
)
async def test_close_logs_warning_when_session_close_raises(
    exc_instance: Exception,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Errors raised by session.close() should log warnings, not propagate."""
    client = EventClient(make_events_url("user", "test_token"))

    mock_session = AsyncMock()
    mock_session.close = AsyncMock(side_effect=exc_instance)
    client.session = mock_session  # type: ignore[assignment]

    with caplog.at_level("WARNING"):
        await client.close()

    assert client.session is None
    assert "Error closing session" in caplog.text
    assert str(exc_instance) in caplog.text
