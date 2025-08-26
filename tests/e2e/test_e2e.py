"""End-to-end tests for chaturbate_events EventClient."""

import pytest

import chaturbate_events


@pytest.mark.asyncio
async def test_event_client_e2e():
    """Basic E2E test for EventClient (placeholder)."""
    async with chaturbate_events.EventClient(
        token="testtoken1234",
        username="testuser",
    ) as client:
        assert client is not None
        assert client.username == "testuser"
        assert client.token == "testtoken1234"
