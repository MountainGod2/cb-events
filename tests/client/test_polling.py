# pyright: reportMissingParameterType=false
# pyright: reportUnknownParameterType=false
# pyright: reportUnknownArgumentType=false
# pyright: reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false

"""Polling behaviour tests for :class:`cb_events.EventClient`."""

import re
from contextlib import aclosing
from typing import Any

import pytest
from aiohttp.client_exceptions import ClientError
from aioresponses import aioresponses

from cb_events import EventClientConfig, EventType
from cb_events.exceptions import AuthError, EventsError
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


async def test_stream_method_yields_events(
    event_client_factory: EventClientFactory,
    mock_response: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """``stream`` should expose the same async iterator as ``__aiter__``."""
    response: dict[str, Any] = {
        "events": [{"method": "tip", "id": "1", "object": {}}],
        "nextUrl": None,
    }
    mock_response.get(testbed_url_pattern, payload=response)

    async with (
        event_client_factory() as client,
        aclosing(client.stream()) as stream,
    ):
        event = await anext(stream)

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
    config = EventClientConfig(
        use_testbed=True, retry_attempts=1, retry_backoff=0.0
    )

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


async def test_network_error_wrapped(
    event_client_factory: EventClientFactory,
    mock_response: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """Transport errors are wrapped inside :class:`EventsError`."""
    mock_response.get(
        testbed_url_pattern, exception=ClientError("network down")
    )
    config = EventClientConfig(use_testbed=True, retry_attempts=0)

    async with event_client_factory(config=config) as client:
        with pytest.raises(EventsError, match="Failed to fetch events"):
            await client.poll()
