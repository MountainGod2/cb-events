"""Pytest configuration and fixtures for Chaturbate Events API tests."""

import re
from collections.abc import AsyncGenerator, Generator
from typing import Any

import pytest
from aioresponses import aioresponses

from chaturbate_events import EventClient, EventType


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
def mock_aioresponse() -> Generator[aioresponses, None, None]:
    """Provide aioresponses mock for testing HTTP interactions.

    Yields:
        aioresponses: The aioresponses mock instance.
    """
    with aioresponses() as m:
        yield m


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
