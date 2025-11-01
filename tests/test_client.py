# pyright: reportUnknownParameterType=false
# pyright: reportUnknownArgumentType=false
# pyright: reportUnknownMemberType=false

"""Tests for EventClient functionality."""

import asyncio
from typing import Any

import pytest
from aiohttp.client_exceptions import ClientError
from pydantic_core import ValidationError

from cb_events import EventClient, EventClientConfig, EventType
from cb_events.exceptions import AuthError, EventsError


class TestEventClient:
    """Test EventClient initialization and basic functionality."""

    def test_token_masking_in_repr(self):
        """Token should be masked in string representation, showing only last 4 chars."""
        client = EventClient("user", "secret_token_1234")

        assert "1234" in str(client)
        assert "secret_token" not in str(client)

    def test_reject_empty_username(self):
        """Empty username should raise AuthError."""
        with pytest.raises(AuthError, match="Username cannot be empty or contain"):
            EventClient("", "token")

    def test_reject_empty_token(self):
        """Empty token should raise AuthError."""
        with pytest.raises(AuthError, match="Token cannot be empty or contain"):
            EventClient("user", "")

    def test_reject_username_with_whitespace(self):
        """Username with leading/trailing whitespace should raise AuthError."""
        with pytest.raises(AuthError, match="Username cannot be empty or contain"):
            EventClient(" user ", "token")

    def test_reject_token_with_whitespace(self):
        """Token with leading/trailing whitespace should raise AuthError."""
        with pytest.raises(AuthError, match="Token cannot be empty or contain"):
            EventClient("user", " token ")


class TestPolling:
    """Test event polling functionality."""

    async def test_poll_returns_events(
        self,
        api_response: dict[str, Any],
        mock_response: Any,
        testbed_url_pattern: Any,
    ) -> None:
        """Successful poll should return parsed events."""
        mock_response.get(testbed_url_pattern, payload=api_response)

        config = EventClientConfig(use_testbed=True)
        async with EventClient("test_user", "test_token", config=config) as client:
            events = await client.poll()

            assert len(events) == 1
            assert events[0].type == EventType.TIP

    async def test_poll_raises_auth_error_on_401(
        self,
        mock_response: Any,
        testbed_url_pattern: Any,
    ) -> None:
        """HTTP 401 should raise AuthError."""
        mock_response.get(testbed_url_pattern, status=401)

        config = EventClientConfig(use_testbed=True)
        async with EventClient("test_user", "test_token", config=config) as client:
            with pytest.raises(AuthError):
                await client.poll()

    async def test_poll_handles_multiple_events(
        self,
        mock_response: Any,
        testbed_url_pattern: Any,
        testbed_config: EventClientConfig,
    ) -> None:
        """Poll should handle multiple events in single response."""
        events_data: list[dict[str, Any]] = [
            {"method": "tip", "id": "1", "object": {}},
            {"method": "follow", "id": "2", "object": {}},
            {"method": "chatMessage", "id": "3", "object": {}},
        ]
        response: dict[str, Any] = {"events": events_data, "nextUrl": "url"}
        mock_response.get(testbed_url_pattern, payload=response)

        async with EventClient("test_user", "test_token", config=testbed_config) as client:
            events = await client.poll()

        assert len(events) == 3
        assert [e.type for e in events] == [
            EventType.TIP,
            EventType.FOLLOW,
            EventType.CHAT_MESSAGE,
        ]

    async def test_async_iteration(
        self,
        mock_response: Any,
        testbed_url_pattern: Any,
        testbed_config: EventClientConfig,
    ) -> None:
        """Client should support async iteration for continuous polling."""
        response: dict[str, Any] = {
            "events": [{"method": "tip", "id": "1", "object": {}}],
            "nextUrl": None,
        }
        mock_response.get(testbed_url_pattern, payload=response)

        async with EventClient("test_user", "test_token", config=testbed_config) as client:
            events = []
            async for event in client:
                events.append(event)
                if len(events) >= 1:
                    break

        assert len(events) == 1
        assert events[0].type == EventType.TIP

    async def test_rate_limit_error(
        self,
        mock_response: Any,
        testbed_url_pattern: Any,
    ) -> None:
        """HTTP 429 should raise EventsError with rate limit message."""
        mock_response.get(testbed_url_pattern, status=429, repeat=True, body="Rate limit exceeded")
        config = EventClientConfig(use_testbed=True, retry_attempts=1, retry_backoff=0.0)

        async with EventClient("test_user", "test_token", config=config) as client:
            with pytest.raises(EventsError, match="HTTP 429: Rate limit exceeded"):
                await client.poll()

    async def test_invalid_json_response(
        self,
        mock_response: Any,
        testbed_url_pattern: Any,
    ) -> None:
        """Invalid JSON response should raise EventsError."""
        mock_response.get(testbed_url_pattern, status=200, body="Not valid JSON")
        config = EventClientConfig(use_testbed=True)

        async with EventClient("test_user", "test_token", config=config) as client:
            with pytest.raises(EventsError, match="Invalid JSON response"):
                await client.poll()

    async def test_network_error_wrapped(
        self,
        mock_response: Any,
        testbed_url_pattern: Any,
        testbed_config: EventClientConfig,
    ) -> None:
        """Transport errors should be wrapped in EventsError."""
        mock_response.get(testbed_url_pattern, exception=ClientError("network down"))

        config_data: dict[str, Any] = {**testbed_config.model_dump(), "retry_attempts": 0}
        config = EventClientConfig(**config_data)
        async with EventClient("test_user", "test_token", config=config) as client:
            with pytest.raises(EventsError, match="Failed to fetch events"):
                await client.poll()


class TestEventClientConfig:
    """Test EventClientConfig validation and defaults."""

    def test_default_values(self):
        """Config should have sensible defaults."""
        config = EventClientConfig()

        assert config.use_testbed is False
        assert config.timeout == 10
        assert config.retry_attempts == 8

    def test_custom_values(self):
        """Config should accept and store custom values."""
        config = EventClientConfig(
            use_testbed=True,
            timeout=60,
            retry_attempts=5,
            retry_backoff=2.0,
            retry_factor=3.0,
            retry_max_delay=120.0,
        )

        assert config.use_testbed is True
        assert config.timeout == 60
        assert config.retry_attempts == 5
        assert config.retry_backoff == 2.0
        assert config.retry_factor == 3.0
        assert config.retry_max_delay == 120.0

    def test_reject_invalid_timeout(self):
        """Timeout must be greater than zero."""
        with pytest.raises(ValidationError):
            EventClientConfig(timeout=0)

    def test_reject_negative_retry_attempts(self):
        """Retry attempts cannot be negative."""
        with pytest.raises(ValidationError):
            EventClientConfig(retry_attempts=-1)

    def test_reject_max_delay_less_than_backoff(self):
        """Max delay must be >= backoff time."""
        with pytest.raises(ValidationError) as exc_info:
            EventClientConfig(retry_backoff=10.0, retry_max_delay=5.0)

        errors = exc_info.value.errors()
        assert len(errors) == 1
        error_msg = str(errors[0].get("ctx", {}).get("error", ""))
        assert "must be >=" in error_msg or "Retry max delay" in error_msg

    def test_allow_max_delay_equal_to_backoff(self):
        """Max delay can equal backoff time."""
        config = EventClientConfig(retry_backoff=5.0, retry_max_delay=5.0)

        assert config.retry_backoff == 5.0
        assert config.retry_max_delay == 5.0


class TestConcurrentPolling:
    """Test concurrent polling behavior and state protection."""

    async def test_concurrent_polls_serialized(
        self,
        mock_response: Any,
        testbed_url_pattern: Any,
    ) -> None:
        """Concurrent poll() calls should be serialized by internal lock."""
        base_url = "https://events.testbed.cb.dev/events/test_user/test_token/?timeout=10"
        next_url_1 = f"{base_url}&next=1"
        next_url_2 = f"{base_url}&next=2"

        responses: list[dict[str, Any]] = [
            {"events": [{"method": "tip", "id": "1", "object": {}}], "nextUrl": next_url_1},
            {"events": [{"method": "tip", "id": "2", "object": {}}], "nextUrl": next_url_2},
            {"events": [{"method": "tip", "id": "3", "object": {}}], "nextUrl": base_url},
        ]

        for response in responses:
            mock_response.get(testbed_url_pattern, payload=response)

        config = EventClientConfig(use_testbed=True)
        async with EventClient("test_user", "test_token", config=config) as client:
            results = await asyncio.gather(client.poll(), client.poll(), client.poll())

        assert len(results) == 3
        assert all(len(events) == 1 and events[0].type == EventType.TIP for events in results)

    async def test_state_protection(
        self,
        mock_response: Any,
        testbed_url_pattern: Any,
    ) -> None:
        """Lock should prevent _next_url state corruption during concurrent polling."""
        base_url = "https://events.testbed.cb.dev/events/test_user/test_token/?timeout=10"
        next_url = f"{base_url}&next=1"

        responses: list[dict[str, Any]] = [
            {"events": [{"method": "tip", "id": "1", "object": {}}], "nextUrl": next_url},
            {"events": [{"method": "tip", "id": "2", "object": {}}], "nextUrl": base_url},
        ]

        for response in responses:
            mock_response.get(testbed_url_pattern, payload=response)

        config = EventClientConfig(use_testbed=True)
        async with EventClient("test_user", "test_token", config=config) as client:
            results = await asyncio.gather(client.poll(), client.poll())

        assert len(results) == 2
        assert all(len(events) == 1 for events in results)
