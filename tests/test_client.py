"""Tests for EventClient (polling, error handling, session, etc.)."""

from typing import Any
from unittest.mock import AsyncMock

import aiohttp
import pytest

from chaturbate_events import (
    AuthError,
    Event,
    EventClient,
    EventsError,
    EventType,
)
from tests.conftest import create_url_pattern


@pytest.mark.asyncio
async def test_client_poll_and_auth(
    credentials: dict[str, Any],
    api_response: dict[str, Any],
    mock_aioresponse: Any,
) -> None:
    """Test event polling and authentication error handling."""
    url_pattern = create_url_pattern(credentials["username"], credentials["token"])
    mock_aioresponse.get(url_pattern, payload=api_response)
    async with EventClient(
        username=credentials["username"],
        token=credentials["token"],
        use_testbed=credentials["use_testbed"],
    ) as client:
        events = await client.poll()
        assert events
        assert isinstance(events[0], Event)

    mock_aioresponse.clear()
    mock_aioresponse.get(url_pattern, status=401, payload={})
    async with EventClient(
        username=credentials["username"],
        token=credentials["token"],
        use_testbed=credentials["use_testbed"],
    ) as client:
        with pytest.raises(AuthError, match="Authentication failed for"):
            await client.poll()


@pytest.mark.asyncio
async def test_client_multiple_events(
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
        use_testbed=credentials["use_testbed"],
    ) as client:
        events = await client.poll()
        types = [e.type for e in events]
        assert types == [EventType.TIP, EventType.FOLLOW, EventType.CHAT_MESSAGE]


@pytest.mark.asyncio
async def test_client_cleanup(credentials: dict[str, Any]) -> None:
    """Test proper cleanup of client resources and session management."""
    client = EventClient(
        username=credentials["username"],
        token=credentials["token"],
        use_testbed=credentials["use_testbed"],
    )
    async with client:
        pass
    await client.close()


@pytest.mark.parametrize(
    ("username", "token", "err"),
    [
        ("", "t", "Username cannot be empty"),
        (" ", "t", "Username cannot be empty"),
        ("u", "", "Token cannot be empty"),
        ("u", " ", "Token cannot be empty"),
    ],
)
def test_client_validation(username: str, token: str, err: str) -> None:
    """Test input validation for EventClient initialization."""
    with pytest.raises(ValueError, match=err):
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
@pytest.mark.parametrize(
    ("mock_response", "expected_error", "error_match"),
    [
        # Network error
        (
            {"exception": aiohttp.ClientConnectionError("Network down")},
            EventsError,
            "Network error",
        ),
        # Timeout error
        (
            {"exception": TimeoutError("Request timeout")},
            EventsError,
            "Request timeout after",
        ),
        # Generic aiohttp ClientError
        (
            {"exception": aiohttp.ClientPayloadError("Payload error")},
            EventsError,
            "Network error",
        ),
        # HTTP 401 Unauthorized
        ({"status": 401, "payload": {}}, AuthError, "Authentication failed for"),
        # HTTP 400 with nextUrl (timeout)
        (
            {"status": 400, "payload": {"status": "waited too long", "nextUrl": "url"}},
            None,
            None,
        ),
        # HTTP 500 error
        ({"status": 500, "payload": {}}, EventsError, "HTTP 500"),
        # Invalid JSON
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
        use_testbed=bool(credentials["use_testbed"]),
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
        use_testbed=bool(credentials["use_testbed"]),
    )
    with pytest.raises(EventsError, match="Session not initialized"):
        await client.poll()


@pytest.mark.asyncio
async def test_client_continuous_polling(
    credentials: dict[str, Any], mocker: Any
) -> None:
    """Test continuous polling with async iteration."""
    responses = [
        {"events": [{"method": "tip", "id": "1", "object": {}}], "nextUrl": "url1"},
        {"events": [{"method": "follow", "id": "2", "object": {}}], "nextUrl": "url2"},
        {"events": [], "nextUrl": "url3"},
    ]
    call_count = 0

    def mock_response(*_args: object, **_kwargs: object) -> Any:
        nonlocal call_count
        response_mock = AsyncMock(status=200)
        response_mock.json = AsyncMock(
            return_value=responses[call_count % len(responses)]
        )
        response_mock.text = AsyncMock(return_value="")
        context_mock = AsyncMock(
            __aenter__=AsyncMock(return_value=response_mock),
            __aexit__=AsyncMock(return_value=None),
        )
        call_count += 1
        return context_mock

    mocker.patch("aiohttp.ClientSession.get", side_effect=mock_response)
    async with EventClient(
        username=str(credentials["username"]),
        token=str(credentials["token"]),
        use_testbed=bool(credentials["use_testbed"]),
    ) as client:
        event_count = 0
        async for event in client:
            assert isinstance(event, Event)
            event_count += 1
            if event_count >= 2:
                break


def test_extract_next_url_edge_cases() -> None:
    """Test _extract_next_url with various response formats."""
    timeout_json = '{"status": "waited too long", "nextUrl": "http://example.com"}'
    assert EventClient._extract_next_url(timeout_json) == "http://example.com"

    timeout_json_caps = '{"status": "WAITED TOO LONG", "nextUrl": "http://example.com"}'
    assert EventClient._extract_next_url(timeout_json_caps) == "http://example.com"

    no_next_url = '{"status": "waited too long"}'
    assert EventClient._extract_next_url(no_next_url) is None
    assert EventClient._extract_next_url("invalid json") is None

    different_status = '{"status": "different error", "nextUrl": "http://example.com"}'
    assert EventClient._extract_next_url(different_status) is None
    assert EventClient._extract_next_url("") is None
