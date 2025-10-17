"""Test configuration and shared fixtures."""

import re
from collections.abc import AsyncGenerator
from typing import Any
from unittest.mock import AsyncMock

import pytest
from aioresponses import aioresponses

from cb_events import Event, EventClient, EventClientConfig, EventRouter, EventType


@pytest.fixture
def credentials() -> dict[str, str]:
    return {
        "username": "test_user",
        "token": "test_token_1234",
    }


@pytest.fixture
def testbed_config() -> EventClientConfig:
    return EventClientConfig(use_testbed=True)


@pytest.fixture
def testbed_url_pattern():
    return re.compile(r"https://events\.testbed\.cb\.dev/events/.*/.*")


@pytest.fixture
def sample_event_data() -> dict[str, Any]:
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
def simple_tip_event_data() -> dict[str, Any]:
    return {
        "method": EventType.TIP.value,
        "id": "test_event",
        "object": {},
    }


@pytest.fixture
def api_response(sample_event_data: dict[str, Any]) -> dict[str, Any]:
    return {
        "events": [sample_event_data],
        "nextUrl": "https://events.testbed.cb.dev/events/next_page_token",
    }


@pytest.fixture
def sample_event(sample_event_data: dict[str, Any]) -> Event:
    return Event.model_validate(sample_event_data)


@pytest.fixture
def simple_tip_event(simple_tip_event_data: dict[str, Any]) -> Event:
    return Event.model_validate(simple_tip_event_data)


@pytest.fixture
async def client(
    credentials: dict[str, str], testbed_config: EventClientConfig
) -> AsyncGenerator[EventClient, None]:
    client = EventClient(
        username=credentials["username"],
        token=credentials["token"],
        config=testbed_config,
    )
    yield client
    await client.close()


@pytest.fixture
def router() -> EventRouter:
    return EventRouter()


@pytest.fixture
def mock_handler() -> AsyncMock:
    return AsyncMock()


@pytest.fixture
def mock_response():
    with aioresponses() as m:
        yield m
