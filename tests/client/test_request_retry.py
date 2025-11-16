"""Tests for retry/backoff behavior in the EventClient._request path.

These tests patch asyncio.sleep to intercept backoff values and assert the
client uses the configured values, factors, and caps for successive retries.
"""

import types

import cb_events.client as client_module
from cb_events import ClientConfig


async def test_exception_based_backoff_increases(
    event_client_factory,
    aioresponses_mock,
    testbed_url_pattern,
    api_response,
    monkeypatch,
) -> None:
    """Retries caused by network exceptions should backup by retry_factor.

    We patch asyncio.sleep in the client module to capture the backoff sleep
    durations and assert they increase based on the configured factor.
    """
    aioresponses_mock.get(testbed_url_pattern, exception=TimeoutError("first"))
    aioresponses_mock.get(testbed_url_pattern, exception=TimeoutError("second"))
    aioresponses_mock.get(testbed_url_pattern, payload=api_response)

    config = ClientConfig(
        use_testbed=True,
        retry_attempts=3,
        retry_backoff=0.01,
        retry_factor=2.0,
        retry_max_delay=1.0,
    )

    sleep_calls: list[float] = []

    def fake_sleep(sec: float):
        sleep_calls.append(sec)

        @types.coroutine
        def _noop():
            if False:
                yield

        return _noop()

    monkeypatch.setattr(client_module.asyncio, "sleep", fake_sleep)

    async with event_client_factory(config=config) as client:
        events = await client.poll()

    assert len(events) == 1
    assert len(sleep_calls) == 2
    assert sleep_calls[0] == 0.01
    assert sleep_calls[1] == 0.02


async def test_backoff_clamped_by_max_delay(
    event_client_factory,
    aioresponses_mock,
    testbed_url_pattern,
    api_response,
    monkeypatch,
) -> None:
    """Verify retry backoff respects retry_max_delay cap."""
    aioresponses_mock.get(testbed_url_pattern, exception=TimeoutError("a"))
    aioresponses_mock.get(testbed_url_pattern, exception=TimeoutError("b"))
    aioresponses_mock.get(testbed_url_pattern, payload=api_response)

    config = ClientConfig(
        use_testbed=True,
        retry_attempts=3,
        retry_backoff=0.01,
        retry_factor=3.0,
        retry_max_delay=0.02,
    )

    sleep_calls: list[float] = []

    def fake_sleep(sec: float):
        sleep_calls.append(sec)

        @types.coroutine
        def _noop():
            if False:
                yield

        return _noop()

    monkeypatch.setattr(client_module.asyncio, "sleep", fake_sleep)

    async with event_client_factory(config=config) as client:
        events = await client.poll()

    assert len(events) == 1
    assert sleep_calls[0] == 0.01
    assert sleep_calls[1] == 0.02


async def test_status_based_retry_backoff_increases(
    event_client_factory,
    aioresponses_mock,
    testbed_url_pattern,
    api_response,
    monkeypatch,
) -> None:
    """Status-based (eg 502) retries should use the same backoff scale."""
    aioresponses_mock.get(testbed_url_pattern, status=502)
    aioresponses_mock.get(testbed_url_pattern, status=502)
    aioresponses_mock.get(testbed_url_pattern, payload=api_response)

    config = ClientConfig(
        use_testbed=True,
        retry_attempts=4,
        retry_backoff=0.02,
        retry_factor=2.0,
        retry_max_delay=0.15,
    )

    sleep_calls: list[float] = []

    def fake_sleep(sec: float):
        sleep_calls.append(sec)

        @types.coroutine
        def _noop():
            if False:
                yield

        return _noop()

    monkeypatch.setattr(client_module.asyncio, "sleep", fake_sleep)

    async with event_client_factory(config=config) as client:
        events = await client.poll()

    assert len(events) == 1
    assert sleep_calls[0] == 0.02
    assert sleep_calls[1] == 0.04
