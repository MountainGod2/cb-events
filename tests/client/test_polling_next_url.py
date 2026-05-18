"""nextUrl handling tests for EventClient polling."""

import re
from typing import Any

import pytest
from aioresponses import aioresponses

from cb_events import EventsError, EventType
from tests.conftest import EventClientFactory
from tests.helpers import make_event, make_response, make_timeout_payload


async def test_next_url_followed_after_timeout(
    event_client_factory: EventClientFactory,
    aioresponses_mock: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """When a timeout response returns a base-host ``nextUrl``, follow it."""
    timeout_response = make_timeout_payload("https://events.testbed.cb.dev/events/next_batch_token")
    aioresponses_mock.get(testbed_url_pattern, status=400, payload=timeout_response)

    next_url_pattern = re.compile(r"https://events\.testbed\.cb\.dev/events/next_batch_token")
    success_response = make_response([make_event(EventType.TIP, event_id="1")])
    aioresponses_mock.get(next_url_pattern, payload=success_response)

    async with event_client_factory() as client:
        events = await client.poll()
        assert not events

        events = await client.poll()
        assert len(events) == 1
    assert events[0].type == EventType.TIP


async def test_disallowed_next_url_host_raises(
    event_client_factory: EventClientFactory,
    aioresponses_mock: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """Timeout responses with off-host nextUrl should raise an error."""
    timeout_response = make_timeout_payload("https://evil.example.com/events/next_batch_token")
    aioresponses_mock.get(testbed_url_pattern, status=400, payload=timeout_response)

    async with event_client_factory() as client:
        with pytest.raises(EventsError, match=r"Invalid nextUrl host"):
            await client.poll()


async def test_relative_next_url_resolved_to_absolute(
    event_client_factory: EventClientFactory,
    aioresponses_mock: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """Relative nextUrl values should resolve against the base host."""
    relative_next = "/events/test_user/test_token/?timeout=10&next=relative"
    initial_response = make_response([], next_url=relative_next)
    next_absolute = (
        "https://events.testbed.cb.dev/events/test_user/test_token/?timeout=10&next=relative"
    )
    success_response = make_response([make_event(EventType.TIP, event_id="1")])

    aioresponses_mock.get(testbed_url_pattern, payload=initial_response)
    aioresponses_mock.get(next_absolute, payload=success_response)

    async with event_client_factory() as client:
        events = await client.poll()
        assert not events

        events = await client.poll()
        assert len(events) == 1
    assert events[0].type == EventType.TIP


@pytest.mark.parametrize("is_timeout", [False, True])
@pytest.mark.parametrize(
    ("invalid_next_url", "expected_pattern"),
    [
        ("   ", r"Invalid API response: 'nextUrl' must be"),
        ({}, r"Invalid API response: 'nextUrl' must be"),
        ("javascript:alert(1)", r"Invalid nextUrl scheme"),
        (
            "http://events.testbed.cb.dev/events/test_user/test_token/",
            r"Invalid nextUrl scheme",
        ),
        ("https:///nohost", r"Invalid nextUrl host"),
        ("//evil.com/path", r"Invalid nextUrl host"),
    ],
)
async def test_invalid_next_url_handling(
    is_timeout: bool,
    invalid_next_url: str | dict[str, Any],
    expected_pattern: str,
    event_client_factory: EventClientFactory,
    aioresponses_mock: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """Invalid nextUrl values, schemes, or hosts should raise EventsError."""
    if is_timeout:
        response = {
            "status": "waited too long for events",
            "events": [],
            "nextUrl": invalid_next_url,
        }
        aioresponses_mock.get(testbed_url_pattern, status=400, payload=response)
    else:
        response = {
            "events": [],
            "nextUrl": invalid_next_url,
        }
        aioresponses_mock.get(testbed_url_pattern, payload=response)

    async with event_client_factory() as client:
        with pytest.raises(EventsError, match=expected_pattern):
            await client.poll()
