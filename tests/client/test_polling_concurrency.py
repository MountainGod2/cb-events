"""Concurrency tests for EventClient polling."""

import asyncio
import re

import pytest
from aioresponses import aioresponses

from cb_events import EventClient, EventsError, EventType
from tests.conftest import EventClientFactory
from tests.helpers import make_event, make_response

TESTBED_POLL_URL = "https://events.testbed.cb.dev/events/test_user/test_token/?timeout=10"


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
        results = await asyncio.gather(client._poll(), client._poll(), client._poll())

    assert len(results) == 3
    assert all(len(events) == 1 and events[0].type == EventType.TIP for events in results)
    assert [events[0].id for events in results] == ["1", "2", "3"]


async def test_close_cancels_inflight_poll(
    event_client_factory: EventClientFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Close should cancel a running poll and finish without waiting for long I/O."""
    started = asyncio.Event()
    release = asyncio.Event()

    async def _slow_request(_self: EventClient, _url: str) -> tuple[int, str]:
        started.set()
        await release.wait()
        return 200, '{"events": [], "nextUrl": null}'

    monkeypatch.setattr(EventClient, "_request", _slow_request)

    async with event_client_factory() as client:
        poll_task = asyncio.create_task(client._poll())
        await started.wait()

        await client.close()

        with pytest.raises(EventsError, match="client is closing"):
            await poll_task

        assert client.session is None
