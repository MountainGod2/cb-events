"""Tests for retry functionality in EventClient."""

from typing import Any
from unittest.mock import patch

import pytest
from aioresponses import aioresponses

from chaturbate_events import EventClient
from chaturbate_events.exceptions import AuthError, EventsError
from tests.conftest import create_url_pattern


@pytest.mark.asyncio
async def test_client_retry_configuration(credentials: dict[str, Any]) -> None:
    """Test EventClient initializes with custom retry configuration."""
    async with EventClient(
        username=credentials["username"],
        token=credentials["token"],
        retry_attempts=5,
        retry_backoff=2.0,
        retry_max_delay=60.0,
        retry_exponential_base=3.0,
    ) as client:
        assert client._retry_options.attempts == 5
        assert client.retry_client is not None


@pytest.mark.asyncio
async def test_client_default_retry_configuration(credentials: dict[str, Any]) -> None:
    """Test EventClient uses default retry configuration."""
    async with EventClient(
        username=credentials["username"],
        token=credentials["token"],
    ) as client:
        assert client._retry_options.attempts == 8  # Default value
        assert client.retry_client is not None


@pytest.mark.slow
@pytest.mark.asyncio
async def test_client_retry_on_server_errors(
    credentials: dict[str, Any],
    api_response: dict[str, Any],
) -> None:
    """Test client retries on server errors and succeeds on retry."""
    url_pattern = create_url_pattern(credentials["username"], credentials["token"])

    with aioresponses() as mock_aioresponse:
        # First request fails with 500, second succeeds
        mock_aioresponse.get(url_pattern, status=500, payload={"error": "server error"})
        mock_aioresponse.get(url_pattern, payload=api_response)

        async with EventClient(
            username=credentials["username"],
            token=credentials["token"],
            use_testbed=credentials["use_testbed"],
            retry_attempts=2,
        ) as client:
            events = await client.poll()
            assert events  # Should succeed on retry


@pytest.mark.slow
@pytest.mark.asyncio
async def test_client_retry_exhaustion(
    credentials: dict[str, Any],
) -> None:
    """Test client raises exception after retry attempts are exhausted."""
    url_pattern = create_url_pattern(credentials["username"], credentials["token"])

    with aioresponses() as mock_aioresponse:
        # All requests fail with 500
        for _ in range(5):  # More than retry attempts
            mock_aioresponse.get(url_pattern, status=500, payload={"error": "server error"})

        async with EventClient(
            username=credentials["username"],
            token=credentials["token"],
            use_testbed=credentials["use_testbed"],
            retry_attempts=2,
        ) as client:
            with pytest.raises(EventsError):
                await client.poll()


@pytest.mark.asyncio
async def test_client_no_retry_on_auth_errors(
    credentials: dict[str, Any],
) -> None:
    """Test client does not retry on authentication errors."""
    url_pattern = create_url_pattern(credentials["username"], credentials["token"])

    with aioresponses() as mock_aioresponse:
        # Auth error should not be retried
        mock_aioresponse.get(url_pattern, status=401, payload={"error": "unauthorized"})

        async with EventClient(
            username=credentials["username"],
            token=credentials["token"],
            use_testbed=credentials["use_testbed"],
            retry_attempts=3,
        ) as client:
            with pytest.raises(AuthError):
                await client.poll()


@pytest.mark.slow
@pytest.mark.asyncio
async def test_client_retry_on_rate_limit(
    credentials: dict[str, Any],
    api_response: dict[str, Any],
) -> None:
    """Test client retries on rate limit errors."""
    url_pattern = create_url_pattern(credentials["username"], credentials["token"])

    with aioresponses() as mock_aioresponse:
        # First request hits rate limit, second succeeds
        mock_aioresponse.get(url_pattern, status=429, payload={"error": "rate limited"})
        mock_aioresponse.get(url_pattern, payload=api_response)

        async with EventClient(
            username=credentials["username"],
            token=credentials["token"],
            use_testbed=credentials["use_testbed"],
            retry_attempts=2,
        ) as client:
            events = await client.poll()
            assert events  # Should succeed on retry


@pytest.mark.asyncio
async def test_client_retry_backoff_timing(credentials: dict[str, Any]) -> None:
    """Test retry backoff timing configuration."""
    url_pattern = create_url_pattern(credentials["username"], credentials["token"])

    with aioresponses() as mock_aioresponse:
        # Configure multiple failures to test backoff
        for _ in range(3):
            mock_aioresponse.get(url_pattern, status=500, payload={"error": "server error"})

        async with EventClient(
            username=credentials["username"],
            token=credentials["token"],
            use_testbed=credentials["use_testbed"],
            retry_attempts=3,
            retry_backoff=0.1,  # Small delay for testing
            retry_max_delay=1.0,
        ) as client:
            with pytest.raises(EventsError):
                with patch("asyncio.sleep"):
                    await client.poll()
                    # Retry logic is handled internally by aiohttp-retry
