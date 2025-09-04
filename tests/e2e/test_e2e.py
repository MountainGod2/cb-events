"""End-to-end integration tests for the Chaturbate Events API client."""

import pytest

import chaturbate_events


@pytest.mark.asyncio
async def test_event_client_e2e():
    """Test basic EventClient initialization and configuration."""
    async with chaturbate_events.EventClient(
        token="testtoken1234",
        username="testuser",
    ) as client:
        assert client is not None
        assert client.username == "testuser"
        assert client.token == "testtoken1234"
