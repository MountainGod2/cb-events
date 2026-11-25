"""Tests for retry behavior in the EventClient._request path."""

import re

import pytest
import stamina
from aioresponses import aioresponses

from cb_events import ClientConfig, EventsError, EventType
from cb_events import _client as client_module
from cb_events import _models as models_module
from cb_events import _parser as parser_module
from cb_events import _request as request_module
from cb_events._request import AuthRetryOptions
from tests.conftest import EventClientFactory
from tests.helpers import make_event, make_response


def test_auth_retry_options_reject_zero_attempts() -> None:
    """Direct users of retry options should get the same invariant as config."""
    with pytest.raises(ValueError, match="must be >= 1"):
        AuthRetryOptions(attempts=0)


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
        events = await client.poll()

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


def test_auth_retry_options_reject_invalid_status_codes() -> None:
    """Auth retry options should only allow the supported 401/403 subset."""
    with pytest.raises(ValueError, match=r"401|403"):
        AuthRetryOptions(status_codes=frozenset({401, 429}), attempts=2)


def test_auth_retry_options_accept_supported_status_codes() -> None:
    """The supported auth retry set should be accepted without complaint."""
    options = AuthRetryOptions(status_codes=frozenset({401, 403}), attempts=2)
    assert options.status_codes == frozenset({401, 403})


def test_internal_logger_names_are_stable() -> None:
    """Private implementation logger names are part of diagnostic configuration."""
    assert client_module._logger.name == "cb_events._client"
    assert models_module._logger.name == "cb_events._models"
    assert parser_module._logger.name == "cb_events._parser"
    assert request_module._logger.name == "cb_events._request"
