"""Concurrency tests for :class:`cb_events.EventClient`."""

import asyncio
import re
from typing import Any

import pytest
from aioresponses import aioresponses

from cb_events import EventType
from tests.conftest import EventClientFactory
from tests.helpers import (
    ALL_EVENT_TYPES,
    CORE_EVENT_TYPES,
    TESTBED_BASE_URL,
    make_event,
    make_response,
)


@pytest.mark.parametrize("method", ALL_EVENT_TYPES)
async def test_concurrent_polls_serialized(
    event_client_factory: EventClientFactory,
    aioresponses_mock: aioresponses,
    testbed_url_pattern: re.Pattern[str],
    method: EventType,
) -> None:
    """Concurrent ``poll`` calls should run serially via the internal lock."""
    base_url = TESTBED_BASE_URL
    next_url_1 = f"{base_url}&next=1"
    next_url_2 = f"{base_url}&next=2"

    responses: list[dict[str, Any]] = [
        make_response([make_event(method, event_id="1")], next_url=next_url_1),
        make_response([make_event(method, event_id="2")], next_url=next_url_2),
        make_response([make_event(method, event_id="3")], next_url=base_url),
    ]

    for response in responses:
        aioresponses_mock.get(testbed_url_pattern, payload=response)

    async with event_client_factory() as client:
        results = await asyncio.gather(
            client.poll(), client.poll(), client.poll()
        )

    assert len(results) == 3
    assert all(
        len(events) == 1 and events[0].type == method for events in results
    )


@pytest.mark.parametrize("method", CORE_EVENT_TYPES)
async def test_state_protection_during_concurrency(
    event_client_factory: EventClientFactory,
    aioresponses_mock: aioresponses,
    testbed_url_pattern: re.Pattern[str],
    method: EventType,
) -> None:
    """Concurrent calls should not corrupt the stored ``_next_url`` value."""
    base_url = TESTBED_BASE_URL
    next_url = f"{base_url}&next=1"

    responses: list[dict[str, Any]] = [
        make_response([make_event(method, event_id="1")], next_url=next_url),
        make_response([make_event(method, event_id="2")], next_url=base_url),
    ]

    for response in responses:
        aioresponses_mock.get(testbed_url_pattern, payload=response)

    async with event_client_factory() as client:
        results = await asyncio.gather(client.poll(), client.poll())

    assert len(results) == 2
    assert all(len(events) == 1 for events in results)
