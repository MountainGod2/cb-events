"""End-to-end integration tests for the public surface."""

import asyncio
import re
from importlib.metadata import version
from typing import Any

import pytest
from aioresponses import aioresponses

from cb_events import (
    AuthError,
    Event,
    EventClient,
    EventType,
    Router,
    __version__,
)
from tests.conftest import EventClientFactory

pytestmark = [pytest.mark.e2e, pytest.mark.asyncio]


async def test_client_router_workflow(
    event_client_factory: EventClientFactory,
    mock_response: aioresponses,
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
        ],
        "nextUrl": None,
    }
    mock_response.get(testbed_url_pattern, payload=event_data)

    async with event_client_factory() as client:
        events = await client.poll()
        for event in events:
            await router.dispatch(event)

    assert len(events_received) == 3
    assert events_received[0] == "any:tip"
    assert events_received[1].type is EventType.TIP
    assert events_received[2] == "any:follow"


async def test_client_context_manager_lifecycle() -> None:
    """Context manager should open and close the internal session."""
    client = EventClient("test_user", "test_token")
    assert client.session is None

    async with client:
        if client.session is None:
            pytest.fail("Session should be initialized inside context manager")


async def test_authentication_error_propagation(
    event_client_factory: EventClientFactory,
    mock_response: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """Authentication failures should raise :class:`AuthError`."""
    mock_response.get(testbed_url_pattern, status=401)

    async with event_client_factory(token_override="bad_token") as client:
        with pytest.raises(AuthError):
            await client.poll()


async def test_version_attribute() -> None:
    """Package should expose a ``__version__`` attribute matching metadata."""
    await asyncio.sleep(0)
    assert isinstance(__version__, str)
    assert version("cb-events") == __version__
