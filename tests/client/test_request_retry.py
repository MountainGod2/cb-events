"""Tests for retry behavior in the EventClient._request path."""

import re

import pytest
import stamina
from aioresponses import aioresponses

from cb_events import ClientConfig, EventsError, EventType
from tests.conftest import EventClientFactory
from tests.helpers import make_event, make_response


async def test_exception_retries_until_success_with_testing_cap(
    event_client_factory: EventClientFactory,
    aioresponses_mock: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """Network exceptions should retry and eventually succeed."""
    success_response = make_response([make_event(EventType.TIP, event_id="1")])
    aioresponses_mock.get(testbed_url_pattern, exception=TimeoutError("first"))
    aioresponses_mock.get(testbed_url_pattern, exception=TimeoutError("second"))
    aioresponses_mock.get(testbed_url_pattern, payload=success_response)

    stamina.set_testing(True, attempts=3)

    config = ClientConfig(
        retry_attempts=10,
        retry_backoff=0.01,
        retry_factor=2.0,
        retry_max_delay=1.0,
    )

    async with event_client_factory(config=config) as client:
        events = await client._poll()

    assert len(events) == 1


@pytest.mark.parametrize("is_exception", [True, False])
async def test_testing_mode_caps_attempts(
    event_client_factory: EventClientFactory,
    aioresponses_mock: aioresponses,
    testbed_url_pattern: re.Pattern[str],
    is_exception: bool,
) -> None:
    """Testing mode should cap retries even when failures keep occurring."""
    if is_exception:
        aioresponses_mock.get(
            testbed_url_pattern,
            exception=TimeoutError("always failing"),
            repeat=True,
        )
    else:
        aioresponses_mock.get(testbed_url_pattern, status=502, repeat=True)

    stamina.set_testing(True, attempts=2)

    config = ClientConfig(
        retry_attempts=10,
        retry_backoff=0.01,
        retry_factor=3.0,
        retry_max_delay=0.02,
    )

    async with event_client_factory(config=config) as client:
        with pytest.raises(
            EventsError,
            match=r"Failed to fetch events after 2 attempts",
        ):
            await client._poll()


async def test_retries_on_retry_status_codes_then_succeeds(
    event_client_factory: EventClientFactory,
    aioresponses_mock: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """Client should retry retryable statuses and eventually succeed."""
    success_response = make_response([make_event(EventType.TIP, event_id="1")])
    aioresponses_mock.get(testbed_url_pattern, status=502)
    aioresponses_mock.get(testbed_url_pattern, payload=success_response)

    config = ClientConfig(retry_attempts=2, retry_backoff=0.0)
    async with event_client_factory(config=config) as client:
        events = await client._poll()

    assert len(events) == 1
    assert events[0].type == EventType.TIP
