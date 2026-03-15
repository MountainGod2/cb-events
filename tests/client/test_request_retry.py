"""Tests for retry behavior in the EventClient._request path."""

import pytest
import stamina

from cb_events import ClientConfig, EventsError


async def test_exponential_backoff_schedule_and_clamping(
    event_client_factory,
) -> None:
    """Verify exponential backoff calculation and max-clamping."""
    stamina.set_testing(True, attempts=4)

    config = ClientConfig(
        use_testbed=True,
        retry_attempts=10,
        retry_backoff=0.01,
        retry_factor=2.0,
        retry_max_delay=0.03,
    )

    async with event_client_factory(config=config) as client:
        assert client._next_sleep_for_attempt(1) == pytest.approx(0.01)
        assert client._next_sleep_for_attempt(2) == pytest.approx(0.02)
        assert client._next_sleep_for_attempt(3) == pytest.approx(0.03)
        assert client._next_sleep_for_attempt(4) == pytest.approx(0.03)


async def test_exception_retries_until_success_with_testing_cap(
    event_client_factory,
    aioresponses_mock,
    testbed_url_pattern,
    api_response,
) -> None:
    """Network exceptions should retry and eventually succeed."""
    aioresponses_mock.get(testbed_url_pattern, exception=TimeoutError("first"))
    aioresponses_mock.get(testbed_url_pattern, exception=TimeoutError("second"))
    aioresponses_mock.get(testbed_url_pattern, payload=api_response)

    stamina.set_testing(True, attempts=3)

    config = ClientConfig(
        use_testbed=True,
        retry_attempts=10,
        retry_backoff=0.01,
        retry_factor=2.0,
        retry_max_delay=1.0,
    )

    async with event_client_factory(config=config) as client:
        events = await client.poll()

    assert len(events) == 1


async def test_testing_mode_caps_attempts_for_exceptions(
    event_client_factory,
    aioresponses_mock,
    testbed_url_pattern,
) -> None:
    """Stamina testing mode should cap retries for exception paths."""
    aioresponses_mock.get(
        testbed_url_pattern,
        exception=TimeoutError("always failing"),
        repeat=True,
    )

    stamina.set_testing(True, attempts=2)

    config = ClientConfig(
        use_testbed=True,
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
            await client.poll()


async def test_testing_mode_caps_attempts_for_status_retries(
    event_client_factory,
    aioresponses_mock,
    testbed_url_pattern,
) -> None:
    """Stamina testing mode should cap retries for retryable status codes."""
    aioresponses_mock.get(testbed_url_pattern, status=502, repeat=True)

    stamina.set_testing(True, attempts=3)

    config = ClientConfig(
        use_testbed=True,
        retry_attempts=10,
        retry_backoff=0.02,
        retry_factor=2.0,
        retry_max_delay=0.15,
    )

    async with event_client_factory(config=config) as client:
        with pytest.raises(
            EventsError,
            match=r"Failed to fetch events after 3 attempts",
        ):
            await client.poll()
