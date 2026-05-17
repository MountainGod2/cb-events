"""Concurrency tests for EventClient polling."""

import asyncio
import re

from aioresponses import aioresponses

from cb_events import EventType
from tests.conftest import EventClientFactory
from tests.helpers import TESTBED_POLL_URL, make_event, make_response


async def test_concurrent_polls_serialized(
    event_client_factory: EventClientFactory,
    aioresponses_mock: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """Concurrent ``poll`` calls should run serially via the internal lock."""
    base_url = TESTBED_POLL_URL
    next_url_1 = f"{base_url}&next=1"
    next_url_2 = f"{base_url}&next=2"

    responses = [
        make_response([make_event(EventType.TIP, event_id="1")], next_url=next_url_1),
        make_response([make_event(EventType.TIP, event_id="2")], next_url=next_url_2),
        make_response([make_event(EventType.TIP, event_id="3")], next_url=base_url),
    ]

    aioresponses_mock.get(testbed_url_pattern, payload=responses[0])
    aioresponses_mock.get(next_url_1, payload=responses[1])
    aioresponses_mock.get(next_url_2, payload=responses[2])

    async with event_client_factory() as client:
        results = await asyncio.gather(client.poll(), client.poll(), client.poll())

    assert len(results) == 3
    assert all(len(events) == 1 and events[0].type == EventType.TIP for events in results)
    assert [events[0].id for events in results] == ["1", "2", "3"]
