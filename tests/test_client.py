"""Tests for EventClient (polling, error handling, session, retry functionality, etc.)."""

import re
from typing import Any
from unittest.mock import patch

import aiohttp
import pytest

from cb_events import (
    Event,
    EventClient,
    EventClientConfig,
    EventType,
)
from cb_events.exceptions import AuthError, EventsError


def create_url_pattern(username: str, token: str) -> re.Pattern[str]:
    """Create URL pattern for matching EventClient requests.

    Args:
        username: The username for the URL pattern.
        token: The token for the URL pattern.

    Returns:
        re.Pattern[str]: Compiled regex pattern for matching URLs.
    """
    return re.compile(
        f"https://events\\.testbed\\.cb\\.dev/events/{username}/{token}/.*",
    )


@pytest.mark.asyncio
async def test_client_successful_polling(
    credentials: dict[str, Any],
    api_response: dict[str, Any],
    mock_aioresponse: Any,
) -> None:
    """Test successful event polling returns Event instances."""
    url_pattern = create_url_pattern(credentials["username"], credentials["token"])
    mock_aioresponse.get(url_pattern, payload=api_response)

    async with EventClient(
        username=credentials["username"],
        token=credentials["token"],
        config=EventClientConfig(use_testbed=credentials["use_testbed"]),
    ) as client:
        events = await client.poll()
        assert events
        assert isinstance(events[0], Event)


@pytest.mark.asyncio
async def test_client_authentication_error(
    credentials: dict[str, Any],
    mock_aioresponse: Any,
) -> None:
    """Test authentication error handling during polling."""
    url_pattern = create_url_pattern(credentials["username"], credentials["token"])
    mock_aioresponse.get(url_pattern, status=401, payload={})

    async with EventClient(
        username=credentials["username"],
        token=credentials["token"],
        config=EventClientConfig(use_testbed=credentials["use_testbed"]),
    ) as client:
        with pytest.raises(AuthError, match="Authentication failed for"):
            await client.poll()


@pytest.mark.asyncio
async def test_client_multiple_events_processing(
    credentials: dict[str, Any],
    multiple_events: list[dict[str, Any]],
    mock_aioresponse: Any,
) -> None:
    """Test client processing of multiple events in a single API response."""
    api_response = {"events": multiple_events, "nextUrl": "url"}
    url_pattern = create_url_pattern(credentials["username"], credentials["token"])
    mock_aioresponse.get(url_pattern, payload=api_response)

    async with EventClient(
        username=credentials["username"],
        token=credentials["token"],
        config=EventClientConfig(use_testbed=credentials["use_testbed"]),
    ) as client:
        events = await client.poll()
        types = [e.type for e in events]
        assert types == [EventType.TIP, EventType.FOLLOW, EventType.CHAT_MESSAGE]


@pytest.mark.asyncio
async def test_client_resource_cleanup(credentials: dict[str, Any]) -> None:
    """Test proper cleanup of client resources and session management."""
    client = EventClient(
        username=credentials["username"],
        token=credentials["token"],
        config=EventClientConfig(use_testbed=credentials["use_testbed"]),
    )
    async with client:
        pass
    await client.close()


@pytest.mark.parametrize(
    ("username", "token", "expected_error"),
    [
        ("", "token", "Username cannot be empty"),
        (" ", "token", "Username cannot be empty"),
        ("user", "", "Token cannot be empty"),
        ("user", " ", "Token cannot be empty"),
    ],
)
def test_client_input_validation(username: str, token: str, expected_error: str) -> None:
    """Test input validation for EventClient initialization."""
    with pytest.raises(ValueError, match=expected_error):
        EventClient(username=username, token=token)


def test_client_token_masking() -> None:
    """Test token masking in client representation and URL masking."""
    client = EventClient(username="testuser", token="abcdef12345")
    repr_str = repr(client)
    assert "abcdef12345" not in repr_str
    assert "*******2345" in repr_str

    short_client = EventClient(username="user", token="abc")
    short_repr = repr(short_client)
    assert "abc" not in short_repr
    assert "***" in short_repr

    test_url = "https://example.com?token=abcdef12345"
    masked_url = client._mask_url(test_url)
    assert "abcdef12345" not in masked_url
    assert "2345" in masked_url


@pytest.mark.asyncio
@pytest.mark.slow
@pytest.mark.parametrize(
    ("mock_response", "expected_error", "error_match"),
    [
        (
            {"exception": aiohttp.ClientConnectionError("Network down")},
            EventsError,
            "Network error",
        ),
        (
            {"exception": TimeoutError("Request timeout")},
            EventsError,
            "Request timeout after",
        ),
        (
            {"exception": aiohttp.ClientPayloadError("Payload error")},
            EventsError,
            "Network error",
        ),
        ({"status": 401, "payload": {}}, AuthError, "Authentication failed for"),
        (
            {"status": 400, "payload": {"status": "waited too long", "nextUrl": "url"}},
            None,
            None,
        ),
        ({"status": 500, "payload": {}}, EventsError, "Network error"),
        ({"status": 200, "body": "not json"}, EventsError, "Invalid JSON response"),
    ],
)
async def test_client_error_handling(
    credentials: dict[str, Any],
    mock_aioresponse: Any,
    mock_response: dict[str, Any],
    expected_error: type | None,
    error_match: str | None,
) -> None:
    """Test handling of various error conditions in client polling."""
    url_pattern = create_url_pattern(credentials["username"], credentials["token"])

    if "exception" in mock_response:
        mock_aioresponse.get(url_pattern, exception=mock_response["exception"])
    else:
        mock_kwargs = {"status": mock_response.get("status", 200)}
        if "payload" in mock_response:
            mock_kwargs["payload"] = mock_response["payload"]
        if "body" in mock_response:
            mock_kwargs["body"] = mock_response["body"]
        mock_aioresponse.get(url_pattern, **mock_kwargs)

    async with EventClient(
        username=str(credentials["username"]),
        token=str(credentials["token"]),
        config=EventClientConfig(use_testbed=bool(credentials["use_testbed"])),
    ) as client:
        if expected_error:
            with pytest.raises(expected_error, match=error_match):
                await client.poll()
        else:
            events = await client.poll()
            assert events == []
            if "nextUrl" in mock_response.get("payload", {}):
                assert client._next_url == mock_response["payload"]["nextUrl"]


@pytest.mark.asyncio
async def test_client_session_not_initialized(credentials: dict[str, Any]) -> None:
    """Test polling without initializing session raises error."""
    client = EventClient(
        username=str(credentials["username"]),
        token=str(credentials["token"]),
        config=EventClientConfig(use_testbed=bool(credentials["use_testbed"])),
    )
    with pytest.raises(EventsError, match="Session not initialized"):
        await client.poll()


@pytest.mark.asyncio
async def test_client_continuous_polling(
    credentials: dict[str, Any], mock_aioresponse: Any
) -> None:
    """Test continuous polling with async iteration."""
    url_pattern = create_url_pattern(credentials["username"], credentials["token"])

    responses = [
        {"events": [{"method": "tip", "id": "1", "object": {}}], "nextUrl": "url1"},
        {"events": [{"method": "follow", "id": "2", "object": {}}], "nextUrl": "url2"},
        {"events": [], "nextUrl": "url3"},
    ]

    # Mock the initial URL
    mock_aioresponse.get(url_pattern, payload=responses[0])

    # Mock the subsequent URLs from nextUrl
    mock_aioresponse.get("url1", payload=responses[1])
    mock_aioresponse.get("url2", payload=responses[2])

    async with EventClient(
        username=str(credentials["username"]),
        token=str(credentials["token"]),
        config=EventClientConfig(use_testbed=bool(credentials["use_testbed"])),
    ) as client:
        event_count = 0
        async for event in client:
            assert isinstance(event, Event)
            event_count += 1
            if event_count >= 2:
                break


@pytest.mark.asyncio
async def test_client_retry_configuration(credentials: dict[str, Any]) -> None:
    """Test EventClient initializes with custom retry configuration."""
    async with EventClient(
        username=credentials["username"],
        token=credentials["token"],
        config=EventClientConfig(
            retry_attempts=5,
            retry_backoff=2.0,
            retry_max_delay=60.0,
            retry_exponential_base=3.0,
        ),
    ) as client:
        assert client._retry_options.attempts == 5
        assert client.retry_client is not None


@pytest.mark.asyncio
async def test_client_default_retry_configuration(credentials: dict[str, Any]) -> None:
    """Test EventClient uses default retry configuration."""
    async with EventClient(
        username=credentials["username"],
        token=credentials["token"],
    ) as client:
        assert client._retry_options.attempts == 8
        assert client.retry_client is not None


@pytest.mark.slow
@pytest.mark.asyncio
async def test_client_retry_on_server_errors(
    credentials: dict[str, Any],
    api_response: dict[str, Any],
    mock_aioresponse: Any,
) -> None:
    """Test client retries on server errors and succeeds on retry."""
    url_pattern = create_url_pattern(credentials["username"], credentials["token"])

    mock_aioresponse.get(url_pattern, status=500, payload={"error": "server error"})
    mock_aioresponse.get(url_pattern, payload=api_response)

    async with EventClient(
        username=credentials["username"],
        token=credentials["token"],
        config=EventClientConfig(
            use_testbed=credentials["use_testbed"],
            retry_attempts=2,
        ),
    ) as client:
        events = await client.poll()
        assert events


@pytest.mark.slow
@pytest.mark.asyncio
async def test_client_retry_exhaustion(
    credentials: dict[str, Any],
    mock_aioresponse: Any,
) -> None:
    """Test client raises exception after retry attempts are exhausted."""
    url_pattern = create_url_pattern(credentials["username"], credentials["token"])

    for _ in range(5):
        mock_aioresponse.get(url_pattern, status=500, payload={"error": "server error"})

    async with EventClient(
        username=credentials["username"],
        token=credentials["token"],
        config=EventClientConfig(
            use_testbed=credentials["use_testbed"],
            retry_attempts=2,
        ),
    ) as client:
        with pytest.raises(EventsError):
            await client.poll()


@pytest.mark.asyncio
async def test_client_no_retry_on_auth_errors(
    credentials: dict[str, Any],
    mock_aioresponse: Any,
) -> None:
    """Test client does not retry on authentication errors."""
    url_pattern = create_url_pattern(credentials["username"], credentials["token"])

    mock_aioresponse.get(url_pattern, status=401, payload={"error": "unauthorized"})

    async with EventClient(
        username=credentials["username"],
        token=credentials["token"],
        config=EventClientConfig(
            use_testbed=credentials["use_testbed"],
            retry_attempts=3,
        ),
    ) as client:
        with pytest.raises(AuthError):
            await client.poll()


@pytest.mark.slow
@pytest.mark.asyncio
async def test_client_retry_on_rate_limit(
    credentials: dict[str, Any],
    api_response: dict[str, Any],
    mock_aioresponse: Any,
) -> None:
    """Test client retries on rate limit errors."""
    url_pattern = create_url_pattern(credentials["username"], credentials["token"])

    mock_aioresponse.get(url_pattern, status=429, payload={"error": "rate limited"})
    mock_aioresponse.get(url_pattern, payload=api_response)

    async with EventClient(
        username=credentials["username"],
        token=credentials["token"],
        config=EventClientConfig(
            use_testbed=credentials["use_testbed"],
            retry_attempts=2,
        ),
    ) as client:
        events = await client.poll()
        assert events


@pytest.mark.asyncio
async def test_client_retry_backoff_timing(
    credentials: dict[str, Any],
    mock_aioresponse: Any,
) -> None:
    """Test retry backoff timing configuration."""
    url_pattern = create_url_pattern(credentials["username"], credentials["token"])

    for _ in range(3):
        mock_aioresponse.get(url_pattern, status=500, payload={"error": "server error"})

    async with EventClient(
        username=credentials["username"],
        token=credentials["token"],
        config=EventClientConfig(
            use_testbed=credentials["use_testbed"],
            retry_attempts=3,
            retry_backoff=0.1,
            retry_max_delay=1.0,
        ),
    ) as client:
        with pytest.raises(EventsError):
            with patch("asyncio.sleep"):
                await client.poll()


@pytest.mark.slow
@pytest.mark.asyncio
async def test_client_retry_on_cloudflare_errors(
    credentials: dict[str, Any],
    api_response: dict[str, Any],
    mock_aioresponse: Any,
) -> None:
    """Test client retries on Cloudflare errors (521, 522, 523, 524)."""
    url_pattern = create_url_pattern(credentials["username"], credentials["token"])

    # Test each Cloudflare error code
    cloudflare_errors = [521, 522, 523, 524]

    for error_code in cloudflare_errors:
        # Mock the error response followed by success
        mock_aioresponse.get(
            url_pattern, status=error_code, payload={"error": f"cloudflare error {error_code}"}
        )
        mock_aioresponse.get(url_pattern, payload=api_response)

        async with EventClient(
            username=credentials["username"],
            token=credentials["token"],
            config=EventClientConfig(
                use_testbed=credentials["use_testbed"],
                retry_attempts=2,
            ),
        ) as client:
            events = await client.poll()
            assert events, f"Should retry and succeed for Cloudflare error {error_code}"


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
    error_long_response = EventsError("Test error", status_code=500, response_text=long_text)
    repr_long = repr(error_long_response)
    assert "..." in repr_long
    assert "AAAAAAAAAAAAAAAAAAAAAA" in repr_long

    error_no_response = EventsError("Test error", status_code=404)
    repr_no_response = repr(error_no_response)
    assert "response_text=" not in repr_no_response

    error_no_status = EventsError("Test error")
    repr_no_status = repr(error_no_status)
    assert "status_code=" not in repr_no_status
