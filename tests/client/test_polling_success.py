"""Success-path polling tests for EventClient."""

import re

import pytest
from aioresponses import aioresponses
from pydantic import ValidationError

from cb_events import ClientConfig, EventType
from tests.conftest import EventClientFactory
from tests.helpers import CORE_EVENT_TYPES, make_event, make_response


@pytest.mark.parametrize("method", CORE_EVENT_TYPES)
async def test_poll_returns_events(
    method: EventType,
    event_client_factory: EventClientFactory,
    aioresponses_mock: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """Successful poll should return validated events."""
    response = make_response([make_event(method, event_id="1")])
    aioresponses_mock.get(testbed_url_pattern, payload=response)

    async with event_client_factory() as client:
        events = await client.poll()

    assert len(events) == 1
    assert events[0].type == method


async def test_poll_handles_multiple_events(
    event_client_factory: EventClientFactory,
    aioresponses_mock: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """Multiple events in the response should be parsed in order."""
    events_data = [
        make_event(EventType.TIP, event_id="1"),
        make_event(EventType.FOLLOW, event_id="2"),
        make_event(EventType.CHAT_MESSAGE, event_id="3"),
        make_event(EventType.BROADCAST_START, event_id="4"),
        make_event(EventType.PRIVATE_MESSAGE, event_id="5"),
    ]
    response = make_response(events_data, next_url="url")
    aioresponses_mock.get(testbed_url_pattern, payload=response)

    async with event_client_factory() as client:
        events = await client.poll()

    assert [event.type for event in events] == [
        EventType.TIP,
        EventType.FOLLOW,
        EventType.CHAT_MESSAGE,
        EventType.BROADCAST_START,
        EventType.PRIVATE_MESSAGE,
    ]


async def test_aiter_protocol_yields_events(
    event_client_factory: EventClientFactory,
    aioresponses_mock: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """Events should be available via the async-iterator protocol."""
    response = make_response([make_event(EventType.TIP, event_id="1")])
    aioresponses_mock.get(testbed_url_pattern, payload=response, repeat=True)

    async with event_client_factory() as client:
        event = await anext(aiter(client))

    assert event.type == EventType.TIP


async def test_async_for_loop_yields_events(
    event_client_factory: EventClientFactory,
    aioresponses_mock: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """Events should be yielded correctly via async for loops."""
    response = make_response([make_event(EventType.TIP, event_id="1")])
    aioresponses_mock.get(testbed_url_pattern, payload=response, repeat=True)

    events = []
    async with event_client_factory() as client:
        async for evt in client:
            events.append(evt)
            break

    assert len(events) == 1
    assert events[0].type == EventType.TIP


async def test_strict_validation_raises_on_invalid_event(
    event_client_factory: EventClientFactory,
    aioresponses_mock: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """Strict mode should surface validation failures."""
    response = {
        "events": [{"method": "tip", "object": {}}],
        "nextUrl": None,
    }
    aioresponses_mock.get(testbed_url_pattern, payload=response)
    config = ClientConfig(strict_validation=True)

    async with event_client_factory(config=config) as client:
        with pytest.raises(ValidationError):
            await client.poll()


async def test_lenient_validation_skips_invalid_events(
    event_client_factory: EventClientFactory,
    aioresponses_mock: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """Lenient mode should skip invalid events and return the rest."""
    response = {
        "events": [
            {"method": "tip", "object": {}},
            make_event(EventType.FOLLOW, event_id="valid"),
        ],
        "nextUrl": None,
    }
    aioresponses_mock.get(testbed_url_pattern, payload=response)
    config = ClientConfig(strict_validation=False)

    async with event_client_factory(config=config) as client:
        events = await client.poll()

    assert len(events) == 1
    assert events[0].id == "valid"
    assert events[0].type == EventType.FOLLOW
