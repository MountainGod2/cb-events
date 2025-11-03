# pyright: reportMissingParameterType=false
# pyright: reportUnknownParameterType=false
# pyright: reportUnknownArgumentType=false
# pyright: reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false

"""Concurrency tests for :class:`cb_events.EventClient`."""

import asyncio
import re
from typing import Any

import pytest
from aioresponses import aioresponses

from cb_events import EventType
from tests.conftest import EventClientFactory

pytestmark = pytest.mark.asyncio


async def test_concurrent_polls_serialized(
    event_client_factory: EventClientFactory,
    mock_response: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """Concurrent ``poll`` calls should run serially via the internal lock."""
    base_url = (
        "https://events.testbed.cb.dev/events/test_user/test_token/?timeout=10"
    )
    next_url_1 = f"{base_url}&next=1"
    next_url_2 = f"{base_url}&next=2"

    responses: list[dict[str, Any]] = [
        {
            "events": [{"method": "tip", "id": "1", "object": {}}],
            "nextUrl": next_url_1,
        },
        {
            "events": [{"method": "tip", "id": "2", "object": {}}],
            "nextUrl": next_url_2,
        },
        {
            "events": [{"method": "tip", "id": "3", "object": {}}],
            "nextUrl": base_url,
        },
    ]

    for response in responses:
        mock_response.get(testbed_url_pattern, payload=response)

    async with event_client_factory() as client:
        results = await asyncio.gather(
            client.poll(), client.poll(), client.poll()
        )

    assert len(results) == 3
    assert all(
        len(events) == 1 and events[0].type is EventType.TIP
        for events in results
    )


async def test_state_protection_during_concurrency(
    event_client_factory: EventClientFactory,
    mock_response: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """Concurrent calls should not corrupt the stored ``_next_url`` value."""
    base_url = (
        "https://events.testbed.cb.dev/events/test_user/test_token/?timeout=10"
    )
    next_url = f"{base_url}&next=1"

    responses: list[dict[str, Any]] = [
        {
            "events": [{"method": "tip", "id": "1", "object": {}}],
            "nextUrl": next_url,
        },
        {
            "events": [{"method": "tip", "id": "2", "object": {}}],
            "nextUrl": base_url,
        },
    ]

    for response in responses:
        mock_response.get(testbed_url_pattern, payload=response)

    async with event_client_factory() as client:
        results = await asyncio.gather(client.poll(), client.poll())

    assert len(results) == 2
    assert all(len(events) == 1 for events in results)
