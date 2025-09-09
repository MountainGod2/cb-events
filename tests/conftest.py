"""Pytest configuration and fixtures for Chaturbate Events API tests."""

from collections.abc import AsyncGenerator
from typing import Any
from unittest.mock import AsyncMock

import pytest
from pytest_mock import MockerFixture

from chaturbate_events import Event, EventClient, EventType


@pytest.fixture
def credentials() -> dict[str, Any]:
    """Provide test credentials for EventClient initialization.

    Returns:
        dict[str, Any]: The test credentials.
    """
    return {
        "username": "test_user",
        "token": "test_token",
        "use_testbed": True,
    }


@pytest.fixture
def event_data() -> dict[str, Any]:
    """Provide sample event data for testing Event model validation.

    Returns:
        dict[str, Any]: The sample event data.
    """
    return {
        "method": EventType.TIP.value,
        "id": "event_123",
        "object": {
            "tip": {"tokens": 100},
            "user": {"username": "test_tipper"},
            "message": {"message": "Great show!"},
        },
    }


@pytest.fixture
def test_event(event_data: dict[str, Any]) -> Event:
    """Create a validated Event instance for testing.

    Returns:
        Event: The validated Event instance.
    """
    return Event.model_validate(event_data)


@pytest.fixture
def api_response(event_data: dict[str, Any]) -> dict[str, Any]:
    """Provide sample API response structure for testing client polling.

    Returns:
        dict[str, Any]: The sample API response.
    """
    return {
        "events": [event_data],
        "nextUrl": "https://events.testbed.cb.dev/events/next_page_token",
    }


@pytest.fixture
def multiple_events() -> list[dict[str, Any]]:
    """Provide multiple event dictionaries for testing batch processing.

    Returns:
        list[dict[str, Any]]: The multiple event dictionaries.
    """
    return [
        {"method": "tip", "id": "event_1", "object": {}},
        {"method": "follow", "id": "event_2", "object": {}},
        {"method": "chatMessage", "id": "event_3", "object": {}},
    ]


@pytest.fixture
async def test_client(
    credentials: dict[str, Any],
) -> AsyncGenerator[EventClient]:
    """Provide an EventClient instance with automatic cleanup for testing.

    Yields:
        AsyncGenerator[EventClient]: The EventClient instance.
    """
    client = EventClient(
        username=credentials["username"],
        token=credentials["token"],
        use_testbed=credentials["use_testbed"],
    )
    yield client
    await client.close()


@pytest.fixture
def mock_http_get(mocker: MockerFixture, api_response: dict[str, Any]) -> AsyncMock:
    """Mock aiohttp ClientSession.get for testing HTTP interactions.

    Returns:
        AsyncMock: The mocked HTTP GET response.
    """
    response_mock = AsyncMock()
    response_mock.status = 200
    response_mock.json = AsyncMock(return_value=api_response)
    response_mock.text = AsyncMock(return_value="")

    context_mock = AsyncMock()
    context_mock.__aenter__ = AsyncMock(return_value=response_mock)
    context_mock.__aexit__ = AsyncMock(return_value=None)

    return mocker.patch("aiohttp.ClientSession.get", return_value=context_mock)
