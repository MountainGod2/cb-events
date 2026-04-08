"""Tests for EventClient polling and iteration."""

import asyncio
import re
from typing import Any

import pytest
from aiohttp.client_exceptions import ClientError
from aioresponses import aioresponses
from pydantic import ValidationError

from cb_events.config import ClientConfig
from cb_events.exceptions import (
    AuthError,
    EventsError,
    RateLimitError,
    ServerError,
)
from cb_events.models import EventType
from tests.conftest import EventClientFactory
from tests.helpers import (
    CORE_EVENT_TYPES,
    TESTBED_BASE_URL,
    make_event,
    make_response,
    make_timeout_payload,
)


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


async def test_poll_raises_auth_error_on_401(
    event_client_factory: EventClientFactory,
    aioresponses_mock: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """HTTP 401 responses should raise :class:`AuthError`."""
    aioresponses_mock.get(testbed_url_pattern, status=401)

    async with event_client_factory() as client:
        with pytest.raises(AuthError):
            await client.poll()


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
    """Events should be accessible via the async iterator protocol directly."""
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


async def test_rate_limit_error(
    event_client_factory: EventClientFactory,
    aioresponses_mock: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """HTTP 429 responses should surface as :class:`RateLimitError`."""
    aioresponses_mock.get(
        testbed_url_pattern, status=429, repeat=True, body="Rate limit exceeded"
    )
    config = ClientConfig(use_testbed=True, retry_attempts=1, retry_backoff=0.0)

    async with event_client_factory(config=config) as client:
        with pytest.raises(RateLimitError, match=r"HTTP 429"):
            await client.poll()


@pytest.mark.parametrize("status_code", [500, 502, 503])
async def test_server_error_after_retry_exhaustion(
    status_code: int,
    event_client_factory: EventClientFactory,
    aioresponses_mock: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """Retryable 5xx failures should raise :class:`ServerError`.

    This should happen after retries are exhausted.
    """
    aioresponses_mock.get(testbed_url_pattern, status=status_code, repeat=True)
    config = ClientConfig(use_testbed=True, retry_attempts=1, retry_backoff=0.0)

    async with event_client_factory(config=config) as client:
        with pytest.raises(ServerError, match=rf"HTTP {status_code}"):
            await client.poll()


async def test_invalid_json_response(
    event_client_factory: EventClientFactory,
    aioresponses_mock: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """Invalid JSON payloads should raise :class:`EventsError`."""
    aioresponses_mock.get(
        testbed_url_pattern, status=200, body="Not valid JSON"
    )

    async with event_client_factory() as client:
        with pytest.raises(EventsError, match="Invalid JSON response"):
            await client.poll()


async def test_timeout_payload_not_mapping(
    event_client_factory: EventClientFactory,
    aioresponses_mock: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """Timeout payloads that are not JSON objects should raise EventsError."""
    aioresponses_mock.get(
        testbed_url_pattern, status=400, payload=["unexpected"]
    )

    async with event_client_factory() as client:
        with pytest.raises(EventsError, match="HTTP 400"):
            await client.poll()


async def test_events_payload_not_list(
    event_client_factory: EventClientFactory,
    aioresponses_mock: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """Responses with non-list ``events`` should raise EventsError."""
    response = {"events": None, "nextUrl": None}
    aioresponses_mock.get(testbed_url_pattern, payload=response)

    async with event_client_factory() as client:
        with pytest.raises(EventsError, match="events' must be a list"):
            await client.poll()


async def test_network_error_wrapped(
    event_client_factory: EventClientFactory,
    aioresponses_mock: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """Network client errors should be wrapped as EventsError.

    This verifies that aiohttp's ClientError is translated into an
    EventsError so callers don't need to depend on aiohttp exception types.
    """
    aioresponses_mock.get(
        testbed_url_pattern,
        exception=ClientError("Connection reset by peer"),
        repeat=True,
    )
    config = ClientConfig(use_testbed=True, retry_attempts=1, retry_backoff=0.0)

    async with event_client_factory(config=config) as client:
        with pytest.raises(
            EventsError, match=r"Failed to fetch events after 1 attempt"
        ):
            await client.poll()


async def test_next_url_followed_after_timeout(
    event_client_factory: EventClientFactory,
    aioresponses_mock: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """When a timeout response returns a base-host ``nextUrl``, follow it.

    This ensures the client follows on-host nextUrl links returned by the
    API and continues fetching events successfully.
    """
    timeout_response = make_timeout_payload(
        "https://events.testbed.cb.dev/events/next_batch_token"
    )
    aioresponses_mock.get(
        testbed_url_pattern, status=400, payload=timeout_response
    )

    next_url_pattern = re.compile(
        r"https://events\.testbed\.cb\.dev/events/next_batch_token"
    )
    success_response = make_response([make_event(EventType.TIP, event_id="1")])
    aioresponses_mock.get(next_url_pattern, payload=success_response)

    async with event_client_factory() as client:
        events = await client.poll()
        assert len(events) == 0  # Timeout returns empty list

        events = await client.poll()
        assert len(events) == 1
    assert events[0].type == EventType.TIP


async def test_unallowed_next_url_host_raises(
    event_client_factory: EventClientFactory,
    aioresponses_mock: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """Timeout responses with off-host nextUrl should raise an error."""
    timeout_response = make_timeout_payload(
        "https://evil.example.com/events/next_batch_token"
    )
    aioresponses_mock.get(
        testbed_url_pattern, status=400, payload=timeout_response
    )

    async with event_client_factory() as client:
        with pytest.raises(EventsError, match=r"Invalid nextUrl host"):
            await client.poll()


@pytest.mark.parametrize(
    "allowed_host",
    ["evil.example.com", "https://evil.example.com"],
)
async def test_allowed_external_next_url_override(
    allowed_host: str,
    event_client_factory: EventClientFactory,
    aioresponses_mock: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """Explicitly allowed external nextUrl domains should be followed."""
    next_url = "https://evil.example.com/events/next_batch_token"
    timeout_response = make_timeout_payload(next_url)

    success_response = make_response([make_event(EventType.TIP, event_id="1")])

    aioresponses_mock.get(
        testbed_url_pattern, status=400, payload=timeout_response
    )
    aioresponses_mock.get(next_url, payload=success_response)

    config = ClientConfig(
        use_testbed=True, next_url_allowed_hosts=[allowed_host]
    )

    async with event_client_factory(config=config) as client:
        events = await client.poll()
        assert len(events) == 0

        events = await client.poll()
        assert len(events) == 1
    assert events[0].type == EventType.TIP


async def test_allowed_hosts_always_include_base_host(
    event_client_factory: EventClientFactory,
    aioresponses_mock: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """Even if the base host is not explicitly included in next_url_allowed_hosts, it should still be followed after timeouts."""
    next_url = "https://events.testbed.cb.dev/events/next_batch_token"
    timeout_response = make_timeout_payload(next_url)

    success_response = make_response([make_event(EventType.TIP, event_id="1")])

    aioresponses_mock.get(
        testbed_url_pattern, status=400, payload=timeout_response
    )
    aioresponses_mock.get(next_url, payload=success_response)

    config = ClientConfig(
        use_testbed=True,
        next_url_allowed_hosts=["evil.example.com"],
    )

    async with event_client_factory(config=config) as client:
        events = await client.poll()
        assert len(events) == 0

        events = await client.poll()
        assert len(events) == 1
    assert events[0].type == EventType.TIP


async def test_relative_next_url_resolved_to_absolute(
    event_client_factory: EventClientFactory,
    aioresponses_mock: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """Relative nextUrl values should resolve against the base host."""
    relative_next = "/events/test_user/test_token/?timeout=10&next=relative"
    initial_response = make_response([], next_url=relative_next)
    next_absolute = (
        "https://events.testbed.cb.dev/events/"
        "test_user/test_token/?timeout=10&next=relative"
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
        ("https:///nohost", r"Invalid nextUrl host"),
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
    """Invalid nextUrl values, schemes, or hosts should raise EventErrors."""
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


@pytest.mark.parametrize(
    ("exc", "retry_attempts", "retry_backoff", "retry_factor", "match"),
    [
        (
            TimeoutError("Connection timeout"),
            2,
            0.01,
            1.0,
            r"Failed to fetch events after 2 attempts",
        ),
        (
            OSError("Network unreachable"),
            3,
            0.01,
            1.5,
            r"Failed to fetch events after 3 attempts",
        ),
    ],
)
async def test_network_errors_exhaust_retries(
    event_client_factory: EventClientFactory,
    aioresponses_mock: aioresponses,
    testbed_url_pattern: re.Pattern[str],
    exc: Exception,
    retry_attempts: int,
    retry_backoff: float,
    retry_factor: float,
    match: str,
) -> None:
    """Different network error types should exhaust retries properly."""
    aioresponses_mock.get(
        testbed_url_pattern,
        exception=exc,
        repeat=True,
    )
    config = ClientConfig(
        use_testbed=True,
        retry_attempts=retry_attempts,
        retry_backoff=retry_backoff,
        retry_factor=retry_factor,
    )

    async with event_client_factory(config=config) as client:
        with pytest.raises(EventsError, match=match):
            await client.poll()


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
    config = ClientConfig(use_testbed=True, strict_validation=True)

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
    config = ClientConfig(use_testbed=True, strict_validation=False)

    async with event_client_factory(config=config) as client:
        events = await client.poll()

    assert len(events) == 1
    assert events[0].id == "valid"
    assert events[0].type == EventType.FOLLOW


async def test_concurrent_polls_serialized(
    event_client_factory: EventClientFactory,
    aioresponses_mock: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """Concurrent ``poll`` calls should run serially via the internal lock."""
    base_url = TESTBED_BASE_URL
    next_url_1 = f"{base_url}&next=1"
    next_url_2 = f"{base_url}&next=2"

    responses = [
        make_response(
            [make_event(EventType.TIP, event_id="1")], next_url=next_url_1
        ),
        make_response(
            [make_event(EventType.TIP, event_id="2")], next_url=next_url_2
        ),
        make_response(
            [make_event(EventType.TIP, event_id="3")], next_url=base_url
        ),
    ]

    aioresponses_mock.get(testbed_url_pattern, payload=responses[0])
    aioresponses_mock.get(next_url_1, payload=responses[1])
    aioresponses_mock.get(next_url_2, payload=responses[2])

    async with event_client_factory() as client:
        results = await asyncio.gather(
            client.poll(), client.poll(), client.poll()
        )

    assert len(results) == 3
    assert all(
        len(events) == 1 and events[0].type == EventType.TIP
        for events in results
    )
    assert [events[0].id for events in results] == ["1", "2", "3"]
