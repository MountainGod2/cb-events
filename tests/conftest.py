"""Test configuration and shared fixtures."""

import re
from collections.abc import AsyncIterator, Iterator
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import Any, Protocol
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from aioresponses import aioresponses

from cb_events import (
    Event,
    EventClient,
    EventClientConfig,
    EventRouter,
    EventType,
)


class EventClientFactory(Protocol):
    def __call__(
        self,
        *,
        username_override: str | None = ...,
        token_override: str | None = ...,
        config: EventClientConfig | None = ...,
        use_testbed: bool = ...,
        **config_overrides: Any,
    ) -> AbstractAsyncContextManager[EventClient]: ...


@pytest.fixture
def testbed_config() -> EventClientConfig:
    return EventClientConfig(use_testbed=True)


@pytest.fixture
def credentials() -> tuple[str, str]:
    return "test_user", "test_token"


@pytest.fixture
def testbed_url_pattern() -> re.Pattern[str]:
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
def mock_response() -> Iterator[aioresponses]:
    with aioresponses() as mock:
        yield mock


@pytest_asyncio.fixture
async def event_client(
    credentials: tuple[str, str],
    testbed_config: EventClientConfig,
) -> AsyncIterator[EventClient]:
    username, token = credentials
    async with EventClient(username, token, config=testbed_config) as client:
        yield client


@pytest.fixture
def event_client_factory(credentials: tuple[str, str]) -> EventClientFactory:
    username, token = credentials

    @asynccontextmanager
    async def _factory(
        *,
        username_override: str | None = None,
        token_override: str | None = None,
        config: EventClientConfig | None = None,
        use_testbed: bool = True,
        **config_overrides: Any,
    ) -> AsyncIterator[EventClient]:
        if config is not None and config_overrides:
            msg = "Provide either `config` or keyword overrides, not both."
            raise ValueError(msg)

        client_username = username_override or username
        client_token = token_override or token

        if config is None:
            config_kwargs = {"use_testbed": use_testbed, **config_overrides}
            config = EventClientConfig(**config_kwargs)

        async with EventClient(
            client_username, client_token, config=config
        ) as client:
            yield client

    return _factory
