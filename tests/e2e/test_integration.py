"""End-to-end integration tests for the public surface."""

import asyncio
import os
import re
from importlib.metadata import version
from typing import Any

import pytest
from aioresponses import aioresponses

from cb_events import (
    AuthError,
    ClientConfig,
    Event,
    EventClient,
    EventType,
    Router,
    __version__,
)
from tests.conftest import EventClientFactory

pytestmark = [pytest.mark.e2e]


async def test_client_router_workflow(
    event_client_factory: EventClientFactory,
    aioresponses_mock: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """Sanity check that polling feeds into the router dispatch pipeline."""
    router = Router()
    events_received: list[Any] = []

    @router.on(EventType.TIP)
    async def handle_tip(event: Event) -> None:
        await asyncio.sleep(0)
        events_received.append(event)

    @router.on_any()
    async def handle_any(event: Event) -> None:
        await asyncio.sleep(0)
        events_received.append(f"any:{event.type}")

    event_data = {
        "events": [
            {"method": "tip", "id": "1", "object": {"tip": {"tokens": 100}}},
            {"method": "follow", "id": "2", "object": {}},
            {"method": "broadcastStart", "id": "3", "object": {}},
        ],
        "nextUrl": None,
    }
    aioresponses_mock.get(testbed_url_pattern, payload=event_data)

    async with event_client_factory() as client:
        events = await client.poll()
        for event in events:
            await router.dispatch(event)

    assert len(events_received) == 4
    assert events_received[0] == "any:tip"
    assert events_received[1].type == EventType.TIP
    assert events_received[2] == "any:follow"
    assert events_received[3] == "any:broadcastStart"


async def test_client_context_manager_lifecycle() -> None:
    """Context manager should open and close the internal session."""
    client = EventClient("test_user", "test_token")
    assert client.session is None

    async with client:
        if client.session is None:
            pytest.fail("Session should be initialized inside context manager")


async def test_authentication_error_propagation(
    event_client_factory: EventClientFactory,
    aioresponses_mock: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """Authentication failures should raise :class:`AuthError`."""
    aioresponses_mock.get(testbed_url_pattern, status=401)

    async with event_client_factory(token_override="bad_token") as client:
        with pytest.raises(AuthError):
            await client.poll()


async def test_version_attribute() -> None:
    """Package should expose a ``__version__`` attribute matching metadata."""
    await asyncio.sleep(0)
    assert isinstance(__version__, str)
    assert version("cb-events") == __version__


@pytest.mark.slow
@pytest.mark.skipif(
    not (os.getenv("CB_USERNAME") and os.getenv("CB_TOKEN")),
    reason="CB_USERNAME and CB_TOKEN must be set for live testbed test",
)
async def test_live_testbed_polling() -> None:
    """Test against the live testbed using environment credentials."""
    username = os.environ["CB_USERNAME"]
    token = os.environ["CB_TOKEN"]
    config = ClientConfig(
        use_testbed=True,
        strict_validation=False,
        retry_attempts=3,
        retry_backoff=1.0,
        retry_factor=1.5,
        retry_max_delay=5.0,
    )

    async with EventClient(username, token, config=config) as client:
        events = await client.poll()

    assert isinstance(events, list)
    for event in events:
        assert isinstance(event, Event)
