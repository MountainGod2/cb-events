"""Error-path polling tests for EventClient."""

import re

import pytest
from aiohttp.client_exceptions import ClientError
from aioresponses import aioresponses

from cb_events import (
    AuthError,
    ClientConfig,
    EventsError,
    RateLimitError,
    ServerError,
)
from tests.conftest import EventClientFactory


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


async def test_rate_limit_error(
    event_client_factory: EventClientFactory,
    aioresponses_mock: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """HTTP 429 responses should surface as :class:`RateLimitError`."""
    aioresponses_mock.get(testbed_url_pattern, status=429, repeat=True, body="Rate limit exceeded")
    config = ClientConfig(retry_attempts=1, retry_backoff=0.0)

    async with event_client_factory(config=config) as client:
        with pytest.raises(RateLimitError, match=r"HTTP 429"):
            await client.poll()


@pytest.mark.parametrize("status_code", [500, 502, 503, 504, 521, 522, 523, 524])
async def test_server_error_after_retry_exhaustion(
    status_code: int,
    event_client_factory: EventClientFactory,
    aioresponses_mock: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """Retryable server failures should raise `ServerError` after retries."""
    aioresponses_mock.get(testbed_url_pattern, status=status_code, repeat=True)
    config = ClientConfig(retry_attempts=1, retry_backoff=0.0)

    async with event_client_factory(config=config) as client:
        with pytest.raises(ServerError, match=rf"HTTP {status_code}"):
            await client.poll()


async def test_invalid_json_response(
    event_client_factory: EventClientFactory,
    aioresponses_mock: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """Invalid JSON payloads should raise :class:`EventsError`."""
    aioresponses_mock.get(testbed_url_pattern, status=200, body="Not valid JSON")

    async with event_client_factory() as client:
        with pytest.raises(EventsError, match=r"Invalid JSON: Expecting value."):
            await client.poll()


async def test_timeout_payload_not_mapping(
    event_client_factory: EventClientFactory,
    aioresponses_mock: aioresponses,
    testbed_url_pattern: re.Pattern[str],
) -> None:
    """Timeout payloads that are not JSON objects should raise EventsError."""
    aioresponses_mock.get(testbed_url_pattern, status=400, payload=["unexpected"])

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
    """Network client errors should be wrapped as EventsError."""
    aioresponses_mock.get(
        testbed_url_pattern,
        exception=ClientError("Connection reset by peer"),
        repeat=True,
    )
    config = ClientConfig(retry_attempts=1, retry_backoff=0.0)

    async with event_client_factory(config=config) as client:
        with pytest.raises(EventsError, match=r"Failed to fetch events after 1 attempt"):
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
    aioresponses_mock.get(testbed_url_pattern, exception=exc, repeat=True)
    config = ClientConfig(
        retry_attempts=retry_attempts,
        retry_backoff=retry_backoff,
        retry_factor=retry_factor,
    )

    async with event_client_factory(config=config) as client:
        with pytest.raises(EventsError, match=match):
            await client.poll()
