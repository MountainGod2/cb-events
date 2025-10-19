"""Test configuration and shared fixtures."""

import re
from typing import Any
from unittest.mock import AsyncMock

import pytest
from aioresponses import aioresponses

from cb_events import Event, EventClientConfig, EventRouter, EventType


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
        },
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
def simple_tip_event() -> Event:
    return Event.model_validate({
        "method": EventType.TIP.value,
        "id": "test_event",
        "object": {},
    })


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
