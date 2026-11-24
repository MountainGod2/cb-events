"""Core tests for client initialization, configuration and utils."""

import asyncio
from unittest.mock import AsyncMock
from urllib.parse import quote

import pytest
from aiohttp import ClientSession
from aiohttp.client_exceptions import ClientError
from yarl import URL

from cb_events import ClientConfig, EventClient, EventsError, EventsUrlError
from cb_events._client import (
    TESTBED_URL,
    _mask_token,
    _mask_url,
    _parse_events_url,
)
from cb_events._parser import _parse_events
from tests.helpers import make_events_url


def test_token_masking_in_repr() -> None:
    """Token should be fully masked in repr."""
    full_token = "secret_token_1234"
    client = EventClient(make_events_url("user", full_token))
    repr_str = str(client)

    assert full_token not in repr_str
    assert "token='***'" in repr_str


def test_mask_url_preserves_host_when_token_is_short() -> None:
    """Masking a URL should not replace host characters when a short token is present."""
    token = "abc"
    url = "https://events.testbed.cb.dev/events/user/abc/"

    masked = _mask_url(url, token)

    assert "events.testbed.cb.dev" in masked
    assert token not in masked


def test_mask_url_keeps_non_token_path_and_query_names_for_short_token() -> None:
    """Short tokens should only mask the actual token value, not unrelated path or key names."""
    token = "e"
    url = "https://events.testbed.cb.dev/events/user/e/?state=live&token=e&name=e"

    masked = _mask_url(url, token)

    assert "events.testbed.cb.dev" in masked
    assert "/events/user/" in masked
    assert "/*v*nts/us*r/" not in masked
    assert "state=live" in masked
    assert "name=" in masked
    assert "token=" in masked
    assert "name=e" not in masked
    assert "token=e" not in masked


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
            "Events URL must not include query parameters",
        ),
        (
            "https://eventsapi.chaturbate.com:8443/events/user/token/",
            "Events URL must not include a custom port",
        ),
        (
            "https://[]/events/user/token/",
            "Events URL must match",
        ),
        (
            "https://eventsapi.chaturbate.com:abc/events/user/token/",
            "Events URL must match",
        ),
    ],
)
def test_reject_invalid_credentials(events_url: str, message: str) -> None:
    """Invalid URLs should raise an ``EventsUrlError`` with guidance."""
    with pytest.raises(EventsUrlError, match=message):
        EventClient(events_url)


def test_reject_malformed_ipv6_does_not_claim_custom_port() -> None:
    """Malformed IPv6 URLs should surface as malformed, not port-specific."""
    with pytest.raises(EventsUrlError) as exc_info:
        EventClient("https://[::1/events/user/token/")

    message = str(exc_info.value)
    assert "custom port" not in message
    assert "must match" in message


@pytest.mark.parametrize(
    "events_url",
    [
        "https://username@eventsapi.chaturbate.com/events/user/token/",
        "https://username:password@eventsapi.chaturbate.com/events/user/token/",
    ],
)
def test_reject_constructor_url_user_info(events_url: str) -> None:
    """Constructor URLs must not contain URL usernames or passwords."""
    with pytest.raises(EventsUrlError, match="must not include user information"):
        EventClient(events_url)


@pytest.mark.parametrize(
    ("username", "token", "field"),
    [
        ("%20user", "token", "Username"),
        ("user%20", "token", "Username"),
        ("user", "%20token", "Token"),
        ("user", "token%20", "Token"),
    ],
)
def test_reject_whitespace_in_url_fields(username: str, token: str, field: str) -> None:
    """Encoded leading or trailing whitespace in credentials should be rejected."""
    events_url = f"https://events.testbed.cb.dev/events/{username}/{token}/"

    with pytest.raises(EventsUrlError, match=rf"{field} must not.*whitespace"):
        EventClient(events_url)


@pytest.mark.parametrize(
    ("username", "token"),
    [
        ("user/name", "token/with/slash"),
        ("user/name", "token with space"),
        ("user/name", "token%value"),
        ("user/name", "token?value#frag"),
        ("user/name", "a/b%c?d#e f"),
    ],
)
def test_opaque_segments_round_trip_and_masking(
    username: str,
    token: str,
) -> None:
    """Opaque username/token segments should round-trip and mask consistently."""
    events_url = (
        f"https://events.testbed.cb.dev/events/{quote(username, safe='')}/{quote(token, safe='')}/"
    )

    parsed_base_url, parsed_username, parsed_token = _parse_events_url(events_url)
    assert parsed_base_url == TESTBED_URL
    assert parsed_username == username
    assert parsed_token == token

    client = EventClient(events_url)
    poll_url = client._build_url()
    parsed_poll_url = URL(poll_url)
    assert parsed_poll_url.parts[-3] == username
    assert parsed_poll_url.parts[-2] == token
    assert quote(username, safe="") in poll_url
    assert quote(token, safe="") in poll_url

    log_url = f"{poll_url}&raw={token}&encoded={quote(token, safe='')}"
    masked = _mask_url(log_url, token)
    assert token not in masked
    assert quote(token, safe="") not in masked


def test_mask_url_replaces_raw_and_encoded_token() -> None:
    """_mask_url should mask both plain and percent-encoded tokens in URLs."""
    token = "super_secret_token_1234"
    encoded = quote(token, safe="")
    url = f"https://events.testbed.cb.dev/events/user/{token}/?t={token}&encoded={encoded}"

    masked = _mask_url(url, token)

    assert token not in masked
    assert encoded not in masked
    assert "%252A" not in masked


def test_mask_url_replaces_only_percent_encoded_token_value() -> None:
    """Percent-encoded token values should be masked even when raw token differs."""
    token = "a/b"
    encoded = quote(token, safe="")
    url = f"https://events.testbed.cb.dev/events/user/{encoded}/?encoded={encoded}"

    masked = _mask_url(url, token)

    assert encoded not in masked
    assert token not in masked


def test_mask_url_replaces_token_inside_larger_query_values() -> None:
    """Only complete query values should be interpreted as token fields."""
    token = "tok123"
    url = f"https://events.testbed.cb.dev/events/user/{token}/?next=xx-{token}-yy"

    masked = _mask_url(url, token)
    assert "xx-" in masked
    assert "-yy" in masked
    assert f"xx-{token}-yy" in masked


@pytest.mark.parametrize("token", ["a", "xy", "secret"])
def test_mask_url_masks_raw_and_percent_encoded_tokens_at_any_length(token: str) -> None:
    """Exact raw and encoded token components should always be masked."""
    encoded = quote(token, safe="")
    url = (
        "https://events.testbed.cb.dev/"
        f"{encoded}/path?raw={token}&encoded={encoded}&state=unchanged"
        f"&embedded=prefix-{token}-suffix"
    )

    masked = _mask_url(url, token)

    assert "events.testbed.cb.dev" in masked
    assert "state=unchanged" in masked
    parsed = URL(masked)
    assert token not in parsed.parts
    assert parsed.query["raw"] != token
    assert parsed.query["encoded"] != token
    assert f"embedded=prefix-{token}-suffix" in masked


def test_mask_url_decodes_path_token_with_encoded_slash_colon_and_at_sign() -> None:
    """Debug masking should conceal decoded opaque path segments without corrupting URL encoding."""
    token = "a/b:c@d"
    encoded = quote(token, safe="")
    url = f"https://events.testbed.cb.dev/events/user/{encoded}/prefix-{encoded}-suffix/unrelated"

    masked = _mask_url(url, token)
    parsed = URL(masked)

    assert "a/b:c@d" not in masked
    assert encoded not in masked
    assert parsed.raw_parts[-1] == "unrelated"
    assert parsed.host == "events.testbed.cb.dev"
    assert "prefix-" in parsed.raw_path
    assert "-suffix" in parsed.raw_path


def test_mask_token_various_lengths() -> None:
    """_mask_token should use a fixed marker that does not reveal length."""
    assert _mask_token("a") == _mask_token("abcd1234") == "***"


def test_parse_events_strict_and_lenient(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """`_parse_events` should raise in strict mode and skip invalid events in lenient mode."""
    caplog.set_level("WARNING")
    valid = {"method": "tip", "id": "1", "object": {}}
    invalid = {"method": "tip", "object": {}}
    invalid_non_mapping = 123

    with pytest.raises(EventsError):
        _parse_events([valid, invalid], strict=True)

    events = _parse_events(
        [valid, invalid, invalid_non_mapping],
        strict=False,
    )
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


def test_parse_events_strict_rejects_invalid_nested_payload() -> None:
    """Strict parsing should propagate validation failure from the model path."""
    invalid_nested = {
        "method": "tip",
        "id": "evt-strict",
        "object": {"tip": {"tokens": "abc"}},
    }

    with pytest.raises(EventsError, match="Strict validation failed"):
        _parse_events([invalid_nested], strict=True)


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
    assert "token='***'" in r


def test_eventclient_public_state_is_read_only() -> None:
    """Callers should not be able to replace identity or runtime state fields."""
    client = EventClient(make_events_url("user", "test_token"))

    with pytest.raises(AttributeError):
        client.username = "other"  # pyright: ignore[reportAttributeAccessIssue]
    with pytest.raises(AttributeError):
        client.base_url = "https://example.com"  # pyright: ignore[reportAttributeAccessIssue]
    with pytest.raises(AttributeError):
        client.config = ClientConfig(timeout=1)  # pyright: ignore[reportAttributeAccessIssue]
    with pytest.raises(AttributeError):
        client.session = None  # pyright: ignore[reportAttributeAccessIssue]


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


async def test_poll_after_close_raises_terminal_state() -> None:
    """Polling after close should fail with a terminal lifecycle error."""
    client = EventClient(make_events_url("user", "test_token"))
    await client.close()

    with pytest.raises(EventsError, match="closing or closed"):
        await client.poll()


async def test_enter_after_close_raises_terminal_state() -> None:
    """A closed client should not support re-entry."""
    client = EventClient(make_events_url("user", "test_token"))

    async with client:
        pass

    with pytest.raises(EventsError, match="cannot be reopened"):
        async with client:
            pass


async def test_reentering_open_client_raises() -> None:
    """Re-entering an already open client should be rejected."""
    client = EventClient(make_events_url("user", "test_token"))

    async with client:
        with pytest.raises(EventsError, match="already open"):
            async with client:
                pass


def test_config_property_returns_original_config() -> None:
    """Config property should expose the same immutable config instance."""
    config = ClientConfig(timeout=7, retry_attempts=3)
    client = EventClient(make_events_url("user", "test_token"), config=config)
    assert client.config is config


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
    client._session = mock_session  # type: ignore[assignment]

    with caplog.at_level("WARNING"):
        await client.close()

    assert client.session is None
    assert "Error closing session" in caplog.text


async def test_close_uses_one_shutdown_task_even_if_cancelled() -> None:
    """A cancellation during shutdown should not restart session cleanup."""
    client = EventClient(make_events_url("user", "test_token"))
    close_calls = 0
    started = asyncio.Event()
    completed = asyncio.Event()

    class _Session:
        def __init__(self) -> None:
            self.closed = False

        async def close(self) -> None:
            nonlocal close_calls
            close_calls += 1
            started.set()
            await asyncio.sleep(0.05)
            self.closed = True
            completed.set()

    session = _Session()
    client._session = session  # type: ignore[assignment]

    close_task = asyncio.create_task(client.close())
    await started.wait()
    close_task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await close_task

    assert close_calls == 1
    assert completed.is_set()
    assert session.closed


async def test_injected_session_remains_caller_owned() -> None:
    """EventClient should use but not close an injected aiohttp session."""
    session = ClientSession()
    client = EventClient(
        make_events_url("user", "test_token"),
        session=session,
    )

    try:
        async with client:
            assert client.session is session
        assert client.session is None
        assert not session.closed
    finally:
        await session.close()
