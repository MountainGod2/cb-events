"""End-to-end integration tests for the public surface."""

import asyncio
import os
import re
from importlib.metadata import version

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
from tests.helpers import make_event, make_response

pytestmark = [pytest.mark.e2e]


async def test_client_router_workflow(
    event_client_factory: EventClientFactory,
    aioresponses_mock: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """Test the end-to-end workflow of receiving events and dispatching them through the router."""
    router = Router()
    events_received: list[str | Event] = []

    @router.on(EventType.TIP)
    async def handle_tip(event: Event) -> None:
        await asyncio.sleep(0)
        events_received.append(event)

    @router.on_any()
    async def handle_any(event: Event) -> None:
        await asyncio.sleep(0)
        events_received.append(f"any:{event.type}")

    event_data = make_response([
        make_event(EventType.TIP, event_id="1", data={"tip": {"tokens": 100}}),
        make_event(EventType.FOLLOW, event_id="2"),
        make_event(EventType.BROADCAST_START, event_id="3"),
    ])
    aioresponses_mock.get(testbed_url_pattern, payload=event_data)

    async with event_client_factory() as client:
        events = await client.poll()
        for event in events:
            await router.dispatch(event)

    assert len(events_received) == 4

    wildcard_calls = [e for e in events_received if isinstance(e, str)]
    specific_calls = [e for e in events_received if isinstance(e, Event)]

    assert wildcard_calls == ["any:tip", "any:follow", "any:broadcastStart"]
    assert len(specific_calls) == 1
    assert specific_calls[0].type == EventType.TIP


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


def test_version_attribute() -> None:
    """Package should expose a ``__version__`` attribute matching metadata."""
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
