"""Tests for EventClient functionality."""

import pytest

from cb_events import EventClient, EventClientConfig, EventType
from cb_events.exceptions import AuthError, EventsError


class TestEventClient:
    def test_token_masking(self):
        client = EventClient("user", "secret_token_1234")
        assert "1234" in str(client)
        assert "secret_token" not in str(client)

    @pytest.mark.parametrize(
        ("username", "token", "error_msg"),
        [
            ("", "token", "Username cannot be empty"),
            ("user", "", "Token cannot be empty"),
            ("   ", "token", "Username cannot be empty"),
            ("user", "   ", "Token cannot be empty"),
        ],
    )
    def test_validation_errors(self, username, token, error_msg):
        with pytest.raises(ValueError, match=error_msg):
            EventClient(username, token)

    async def test_polling_success(self, api_response, mock_response, testbed_url_pattern):
        mock_response.get(testbed_url_pattern, payload=api_response)

        config = EventClientConfig(use_testbed=True)
        async with EventClient("test_user", "test_token", config) as client:
            events = await client.poll()
            assert len(events) == 1
            assert events[0].type == EventType.TIP

    async def test_authentication_failure(self, mock_response, testbed_url_pattern):
        mock_response.get(testbed_url_pattern, status=401)

        config = EventClientConfig(use_testbed=True)
        async with EventClient("test_user", "test_token", config) as client:
            with pytest.raises(AuthError):
                await client.poll()

    async def test_multiple_events(self, mock_response, testbed_url_pattern, testbed_config):
        events_data = [
            {"method": "tip", "id": "1", "object": {}},
            {"method": "follow", "id": "2", "object": {}},
            {"method": "chatMessage", "id": "3", "object": {}},
        ]
        response = {"events": events_data, "nextUrl": "url"}

        mock_response.get(testbed_url_pattern, payload=response)

        async with EventClient("test_user", "test_token", testbed_config) as client:
            events = await client.poll()
        assert len(events) == 3
        expected_types = [EventType.TIP, EventType.FOLLOW, EventType.CHAT_MESSAGE]
        assert [e.type for e in events] == expected_types

    async def test_continuous_polling(self, mock_response, testbed_url_pattern, testbed_config):
        response = {"events": [{"method": "tip", "id": "1", "object": {}}], "nextUrl": None}

        mock_response.get(testbed_url_pattern, payload=response)

        async with EventClient("test_user", "test_token", testbed_config) as client:
            events = []
            count = 0
            async for event in client:
                events.append(event)
                count += 1
                if count >= 1:
                    break

            assert len(events) == 1
            assert events[0].type == EventType.TIP

    async def test_retry_configuration(self, credentials):
        config = EventClientConfig(
            use_testbed=True, retry_attempts=5, retry_backoff=2.0, retry_max_delay=60.0
        )
        client = EventClient(credentials["username"], credentials["token"], config=config)

        assert client.config.retry_attempts == 5
        assert client.config.retry_backoff == 2.0
        assert client.config.retry_max_delay == 60.0

    async def test_rate_limit_handling(self, mock_response, testbed_url_pattern):
        mock_response.get(testbed_url_pattern, status=429, repeat=True, body="Rate limit exceeded")
        config = EventClientConfig(use_testbed=True, retry_attempts=1, retry_backoff=0.0)

        async with EventClient("test_user", "test_token", config=config) as client:
            with pytest.raises(EventsError, match="HTTP 429: Rate limit exceeded"):
                await client.poll()


class TestEventClientConfig:
    def test_default_values(self):
        config = EventClientConfig()
        assert config.use_testbed is False
        assert config.timeout == 10
        assert config.retry_attempts == 8

    def test_custom_values(self):
        config = EventClientConfig(
            use_testbed=True,
            timeout=60,
            retry_attempts=5,
            retry_backoff=2.0,
            retry_exponential_base=3.0,
            retry_max_delay=120.0,
        )

        assert config.use_testbed is True
        assert config.timeout == 60
        assert config.retry_attempts == 5
        assert config.retry_backoff == 2.0
        assert config.retry_exponential_base == 3.0
        assert config.retry_max_delay == 120.0

    @pytest.mark.parametrize(
        ("field", "value", "error"),
        [
            ("timeout", -1, "Timeout must be greater than 0"),
            ("timeout", 0, "Timeout must be greater than 0"),
            ("retry_attempts", -1, "Retry attempts must be non-negative"),
            ("retry_backoff", -1, "Retry backoff must be non-negative"),
            ("retry_exponential_base", 0, "Retry exponential base must be greater than 0"),
            ("retry_exponential_base", -1, "Retry exponential base must be greater than 0"),
            ("retry_max_delay", -1, "Retry max delay must be non-negative"),
        ],
    )
    def test_validation_errors(self, field, value, error):
        with pytest.raises(ValueError, match=error):
            EventClientConfig(**{field: value})
