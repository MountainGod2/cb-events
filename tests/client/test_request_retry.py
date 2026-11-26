"""Tests for retry behavior in the EventClient._request path."""

import asyncio
import re

import pytest
from aioresponses import aioresponses

from cb_events import ClientConfig, EventsError, EventType
from cb_events import _client as client_module
from cb_events import _models as models_module
from cb_events import _parser as parser_module
from cb_events import _request as request_module
from tests.helpers import EventClientFactory, make_event, make_response


async def test_exception_retries_until_success(
    event_client_factory: EventClientFactory,
    aioresponses_mock: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """Network exceptions should retry and eventually succeed."""
    success_response = make_response([make_event(EventType.TIP, event_id="1")])
    aioresponses_mock.get(testbed_url_pattern, exception=TimeoutError("first"))
    aioresponses_mock.get(testbed_url_pattern, exception=TimeoutError("second"))
    aioresponses_mock.get(testbed_url_pattern, payload=success_response)

    config = ClientConfig(
        retry_attempts=3,
        retry_backoff=0.01,
        retry_factor=2.0,
        retry_max_delay=1.0,
    )

    async with event_client_factory(config=config) as client:
        events = await client.poll()

    assert len(events) == 1


@pytest.mark.parametrize("is_exception", [True, False])
async def test_config_caps_attempts(
    event_client_factory: EventClientFactory,
    aioresponses_mock: aioresponses,
    testbed_url_pattern: re.Pattern[str],
    is_exception: bool,
) -> None:
    """Configuration should cap retries when failures keep occurring."""
    if is_exception:
        aioresponses_mock.get(
            testbed_url_pattern,
            exception=TimeoutError("always failing"),
            repeat=True,
        )
    else:
        aioresponses_mock.get(testbed_url_pattern, status=502, repeat=True)

    config = ClientConfig(
        retry_attempts=2,
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


async def test_retries_on_retry_status_codes_then_succeeds(
    event_client_factory: EventClientFactory,
    aioresponses_mock: aioresponses,
    testbed_url_pattern: re.Pattern[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Client should retry retryable statuses and log retry details via cb_events logger."""
    success_response = make_response([make_event(EventType.TIP, event_id="1")])
    aioresponses_mock.get(testbed_url_pattern, status=502)
    aioresponses_mock.get(testbed_url_pattern, payload=success_response)

    config = ClientConfig(retry_attempts=2, retry_backoff=0.0)
    caplog.set_level("WARNING", logger="cb_events._request")
    async with event_client_factory(config=config) as client:
        events = await client.poll()

    assert len(events) == 1
    assert events[0].type == EventType.TIP
    retry_records = [
        record
        for record in caplog.records
        if record.name == "cb_events._request"
        and record.getMessage().startswith("Retrying events request for user")
    ]
    assert len(retry_records) == 1
    retry_message = retry_records[0].getMessage()
    assert "test_user" in retry_message
    assert "attempt 1/2" in retry_message
    assert "HTTP 502" in retry_message


async def test_auth_retry_warning_includes_username(
    event_client_factory: EventClientFactory,
    aioresponses_mock: aioresponses,
    testbed_url_pattern: re.Pattern[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Auth retry warnings should include the username in message text."""
    success_response = make_response([make_event(EventType.TIP, event_id="1")])
    aioresponses_mock.get(testbed_url_pattern, status=401)
    aioresponses_mock.get(testbed_url_pattern, payload=success_response)

    config = ClientConfig(auth_retry_attempts=2, auth_retry_status_codes=frozenset({401}))
    caplog.set_level("WARNING", logger="cb_events._request")

    async with event_client_factory(config=config) as client:
        events = await client.poll()

    assert len(events) == 1
    auth_retry_records = [
        record
        for record in caplog.records
        if record.name == "cb_events._request"
        and record.getMessage().startswith("Auth check attempt")
    ]
    assert len(auth_retry_records) == 1
    assert "test_user" in auth_retry_records[0].getMessage()


def test_config_rejects_invalid_auth_retry_status_codes() -> None:
    """Auth retry configuration should only allow the supported 401/403 subset."""
    with pytest.raises(ValueError, match=r"401|403"):
        ClientConfig(auth_retry_status_codes=frozenset({401, 429}), auth_retry_attempts=2)


def test_config_accepts_supported_auth_retry_status_codes() -> None:
    """The supported auth retry set should be accepted without complaint."""
    config = ClientConfig(
        auth_retry_status_codes=frozenset({401, 403}),
        auth_retry_attempts=2,
    )
    assert config.auth_retry_status_codes == frozenset({401, 403})


async def test_rate_limit_retry_after_controls_delay(
    monkeypatch: pytest.MonkeyPatch,
    event_client_factory: EventClientFactory,
    aioresponses_mock: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """HTTP 429 responses should use a valid Retry-After delay."""
    aioresponses_mock.get(testbed_url_pattern, status=429, headers={"Retry-After": "0.25"})
    aioresponses_mock.get(
        testbed_url_pattern,
        payload=make_response([make_event(EventType.TIP, event_id="1")]),
    )
    sleeps: list[float] = []

    async def _record_sleep(delay: float) -> None:
        sleeps.append(delay)
        await asyncio.sleep(0)

    monkeypatch.setattr(request_module, "_retry_sleep", _record_sleep)
    async with event_client_factory(
        config=ClientConfig(retry_attempts=2, retry_backoff=5.0)
    ) as client:
        assert len(await client.poll()) == 1

    assert sleeps == [0.25]


async def test_auth_and_network_retries_use_independent_budgets(
    event_client_factory: EventClientFactory,
    aioresponses_mock: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """Auth retries should not consume the network/server retry budget."""
    aioresponses_mock.get(testbed_url_pattern, status=401)
    aioresponses_mock.get(testbed_url_pattern, status=502)
    aioresponses_mock.get(
        testbed_url_pattern,
        payload=make_response([make_event(EventType.TIP, event_id="1")]),
    )

    config = ClientConfig(
        auth_retry_attempts=2,
        auth_retry_status_codes=frozenset({401}),
        retry_attempts=2,
        retry_backoff=0.0,
    )
    async with event_client_factory(config=config) as client:
        assert len(await client.poll()) == 1


def test_internal_logger_names_are_stable() -> None:
    """Private implementation logger names are part of diagnostic configuration."""
    assert client_module._logger.name == "cb_events._client"
    assert models_module._logger.name == "cb_events._models"
    assert parser_module._logger.name == "cb_events._parser"
    assert request_module._logger.name == "cb_events._request"
