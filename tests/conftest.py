"""Test configuration and shared fixtures."""

import re
from collections.abc import AsyncIterator, Iterator
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import Protocol
from unittest.mock import AsyncMock

import pytest
import stamina
from aioresponses import aioresponses

from cb_events import (
    ClientConfig,
    EventClient,
    Router,
)


class EventClientFactory(Protocol):
    def __call__(
        self,
        *,
        username_override: str | None = ...,
        token_override: str | None = ...,
        config: ClientConfig | None = ...,
        use_testbed: bool = ...,
        **config_overrides: object,
    ) -> AbstractAsyncContextManager[EventClient]: ...


@pytest.fixture(autouse=True)
def reset_stamina_state() -> Iterator[None]:
    stamina.set_active(True)
    stamina.set_testing(False)
    yield
    stamina.set_active(True)
    stamina.set_testing(False)


@pytest.fixture
def credentials() -> tuple[str, str]:
    return "test_user", "test_token"


@pytest.fixture
def testbed_url_pattern() -> re.Pattern[str]:
    return re.compile(r"https://events\.testbed\.cb\.dev/events/.*/.*")


@pytest.fixture
def router() -> Router:
    return Router()


@pytest.fixture
def mock_handler() -> AsyncMock:
    return AsyncMock()


@pytest.fixture
def aioresponses_mock() -> Iterator[aioresponses]:
    with aioresponses() as mock:
        yield mock


@pytest.fixture
def event_client_factory(credentials: tuple[str, str]) -> EventClientFactory:
    username, token = credentials

    @asynccontextmanager
    async def _factory(
        *,
        username_override: str | None = None,
        token_override: str | None = None,
        config: ClientConfig | None = None,
        use_testbed: bool = True,
        **config_overrides: object,
    ) -> AsyncIterator[EventClient]:
        if config is not None and config_overrides:
            msg = "Provide either `config` or keyword overrides, not both."
            raise ValueError(msg)

        client_username = username_override or username
        client_token = token_override or token

        if config is None:
            config_kwargs = {"use_testbed": use_testbed, **config_overrides}
            config = ClientConfig.model_validate(config_kwargs)

        async with EventClient(
            client_username, client_token, config=config
        ) as client:
            yield client

    return _factory
