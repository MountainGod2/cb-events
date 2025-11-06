"""Tests for EventClient polling and iteration."""

import re
from typing import Any
from unittest.mock import patch

import pytest
from aiohttp.client_exceptions import ClientError
from aioresponses import aioresponses
from pydantic import ValidationError

from cb_events import EventClient
from cb_events.config import ClientConfig
from cb_events.exceptions import AuthError, EventsError
from cb_events.models import EventType
from tests.conftest import EventClientFactory

pytestmark = pytest.mark.asyncio


async def test_poll_returns_events(
    api_response: dict[str, Any],
    event_client_factory: EventClientFactory,
    mock_response: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """Successful poll should return validated events."""
    mock_response.get(testbed_url_pattern, payload=api_response)

    async with event_client_factory() as client:
        events = await client.poll()

    assert len(events) == 1
    assert events[0].type is EventType.TIP


async def test_poll_raises_auth_error_on_401(
    event_client_factory: EventClientFactory,
    mock_response: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """HTTP 401 responses should raise :class:`AuthError`."""
    mock_response.get(testbed_url_pattern, status=401)

    async with event_client_factory() as client:
        with pytest.raises(AuthError):
            await client.poll()


async def test_poll_handles_multiple_events(
    event_client_factory: EventClientFactory,
    mock_response: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """Multiple events in the response should be parsed in order."""
    events_data = [
        {"method": "tip", "id": "1", "object": {}},
        {"method": "follow", "id": "2", "object": {}},
        {"method": "chatMessage", "id": "3", "object": {}},
    ]
    response: dict[str, Any] = {"events": events_data, "nextUrl": "url"}
    mock_response.get(testbed_url_pattern, payload=response)

    async with event_client_factory() as client:
        events = await client.poll()

    assert [event.type for event in events] == [
        EventType.TIP,
        EventType.FOLLOW,
        EventType.CHAT_MESSAGE,
    ]


async def test_async_iteration_yields_events(
    event_client_factory: EventClientFactory,
    mock_response: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """The client should support async iteration for continuous polling."""
    response: dict[str, Any] = {
        "events": [{"method": "tip", "id": "1", "object": {}}],
        "nextUrl": None,
    }
    mock_response.get(testbed_url_pattern, payload=response)

    async with event_client_factory() as client:
        events = []
        async for event in client:
            events.append(event)
            if len(events) >= 1:
                break

    assert len(events) == 1
    assert events[0].type is EventType.TIP


async def test_aiter_yields_events(
    event_client_factory: EventClientFactory,
    mock_response: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """``__aiter__`` should yield events continuously."""
    response: dict[str, Any] = {
        "events": [{"method": "tip", "id": "1", "object": {}}],
        "nextUrl": None,
    }
    mock_response.get(testbed_url_pattern, payload=response)

    async with event_client_factory() as client:
        event = await anext(aiter(client))

    assert event.type is EventType.TIP


async def test_rate_limit_error(
    event_client_factory: EventClientFactory,
    mock_response: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """HTTP 429 responses should surface as :class:`EventsError`."""
    mock_response.get(
        testbed_url_pattern, status=429, repeat=True, body="Rate limit exceeded"
    )
    config = ClientConfig(use_testbed=True, retry_attempts=1, retry_backoff=0.0)

    async with event_client_factory(config=config) as client:
        with pytest.raises(EventsError, match="HTTP 429: Rate limit exceeded"):
            await client.poll()


async def test_invalid_json_response(
    event_client_factory: EventClientFactory,
    mock_response: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """Invalid JSON payloads should raise :class:`EventsError`."""
    mock_response.get(testbed_url_pattern, status=200, body="Not valid JSON")

    async with event_client_factory() as client:
        with pytest.raises(EventsError, match="Invalid JSON response"):
            await client.poll()


async def test_timeout_payload_not_mapping(
    event_client_factory: EventClientFactory,
    mock_response: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """Timeout payloads that are not JSON objects should raise EventsError."""
    mock_response.get(testbed_url_pattern, status=400, payload=["unexpected"])

    async with event_client_factory() as client:
        with pytest.raises(EventsError, match="HTTP 400"):
            await client.poll()


async def test_events_payload_not_list(
    event_client_factory: EventClientFactory,
    mock_response: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """Responses with non-list ``events`` should raise EventsError."""
    response: dict[str, Any] = {"events": None, "nextUrl": None}
    mock_response.get(testbed_url_pattern, payload=response)

    async with event_client_factory() as client:
        with pytest.raises(EventsError, match="events' must be a list"):
            await client.poll()


async def test_network_error_wrapped(
    event_client_factory: EventClientFactory,
    mock_response: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """Transport errors are wrapped inside :class:`EventsError`."""
    mock_response.get(
        testbed_url_pattern, exception=ClientError("network down")
    )
    config = ClientConfig(use_testbed=True, retry_attempts=0)

    async with event_client_factory(config=config) as client:
        with pytest.raises(EventsError, match="Failed to fetch events"):
            await client.poll()


async def test_session_creation_fails(
    credentials: tuple[str, str],
) -> None:
    """Session creation failure should raise EventsError with guidance."""
    username, token = credentials
    config = ClientConfig(use_testbed=True)
    client = EventClient(username, token, config=config)

    with (
        patch(
            "cb_events.client.ClientSession",
            side_effect=OSError("Mock error"),
        ),
        pytest.raises(
            EventsError,
            match=r"Failed to create HTTP session.*network configuration",
        ),
    ):
        async with client:
            pass

    assert client.session is None


async def test_timeout_with_next_url(
    event_client_factory: EventClientFactory,
    mock_response: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """Timeout responses with nextUrl should be handled gracefully."""
    timeout_response = {
        "status": "waited too long for events",
        "nextUrl": "https://events.testbed.cb.dev/events/next_batch_token",
        "events": [],
    }
    mock_response.get(testbed_url_pattern, status=400, payload=timeout_response)

    next_url_pattern = re.compile(
        r"https://events\.testbed\.cb\.dev/events/next_batch_token"
    )
    success_response = {
        "events": [{"method": "tip", "id": "1", "object": {}}],
        "nextUrl": None,
    }
    mock_response.get(next_url_pattern, payload=success_response)

    async with event_client_factory() as client:
        events = await client.poll()
        assert len(events) == 0  # Timeout returns empty list

        events = await client.poll()
        assert len(events) == 1
        assert events[0].type is EventType.TIP


async def test_network_errors_exhaust_retries(
    event_client_factory: EventClientFactory,
    mock_response: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """Different network error types should exhaust retries properly."""
    mock_response.get(
        testbed_url_pattern,
        exception=TimeoutError("Connection timeout"),
        repeat=True,
    )
    config = ClientConfig(
        use_testbed=True,
        retry_attempts=2,
        retry_backoff=0.01,
        retry_factor=1.0,
    )

    async with event_client_factory(config=config) as client:
        with pytest.raises(
            EventsError,
            match=(
                r"Failed to fetch events after 2 attempts.*"
                r"network connectivity"
            ),
        ):
            await client.poll()


async def test_network_errors_with_oserror(
    event_client_factory: EventClientFactory,
    mock_response: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """OSError during requests should be retried and eventually raise."""
    mock_response.get(
        testbed_url_pattern,
        exception=OSError("Network unreachable"),
        repeat=True,
    )
    config = ClientConfig(
        use_testbed=True,
        retry_attempts=3,
        retry_backoff=0.01,
        retry_factor=1.5,
    )

    async with event_client_factory(config=config) as client:
        with pytest.raises(
            EventsError,
            match=r"Failed to fetch events after 3 attempts",
        ):
            await client.poll()


async def test_strict_validation_raises_on_invalid_event(
    event_client_factory: EventClientFactory,
    mock_response: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """Strict mode should surface validation failures."""
    response: dict[str, Any] = {
        "events": [{"method": "tip", "object": {}}],
        "nextUrl": None,
    }
    mock_response.get(testbed_url_pattern, payload=response)
    config = ClientConfig(use_testbed=True, strict_validation=True)

    async with event_client_factory(config=config) as client:
        with pytest.raises(ValidationError):
            await client.poll()


async def test_lenient_validation_skips_invalid_events(
    event_client_factory: EventClientFactory,
    mock_response: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """Lenient mode should skip invalid events and return the rest."""
    response: dict[str, Any] = {
        "events": [
            {"method": "tip", "object": {}},
            {"method": "follow", "id": "valid", "object": {}},
        ],
        "nextUrl": None,
    }
    mock_response.get(testbed_url_pattern, payload=response)
    config = ClientConfig(use_testbed=True, strict_validation=False)

    async with event_client_factory(config=config) as client:
        events = await client.poll()

    assert len(events) == 1
    assert events[0].id == "valid"
    assert events[0].type is EventType.FOLLOW
