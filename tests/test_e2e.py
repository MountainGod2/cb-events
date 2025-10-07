"""Integration tests for cb-events package."""

import pytest

from cb_events import AuthError, EventClient, EventRouter, EventType


@pytest.mark.e2e
class TestIntegration:
    async def test_client_router_integration(
        self, mock_response, testbed_url_pattern, testbed_config
    ):
        """Test complete workflow from client polling to router dispatch."""
        router = EventRouter()
        events_received = []

        @router.on(EventType.TIP)
        async def handle_tip(event):  # noqa: RUF029
            events_received.append(event)

        @router.on_any()
        async def handle_any(event):  # noqa: RUF029
            events_received.append(f"any:{event.type}")

        event_data = {
            "events": [
                {"method": "tip", "id": "1", "object": {"tip": {"tokens": 100}}},
                {"method": "follow", "id": "2", "object": {}},
            ],
            "nextUrl": None,
        }

        mock_response.get(testbed_url_pattern, payload=event_data)

        async with EventClient("test_user", "test_token", config=testbed_config) as client:
            events = await client.poll()
            for event in events:
                await router.dispatch(event)

        assert len(events_received) == 3
        assert events_received[0] == "any:tip"
        assert events_received[1].type == EventType.TIP
        assert events_received[2] == "any:follow"

    async def test_client_lifecycle(self):
        """Test proper client resource management."""
        client = EventClient("test_user", "test_token")
        assert client.session is None

        # Test that we can enter and exit the context manager
        async with client:
            assert client.session is not None

    async def test_error_propagation(self, mock_response, testbed_url_pattern, testbed_config):
        """Test that errors propagate correctly through the stack."""
        mock_response.get(testbed_url_pattern, status=401)

        async with EventClient("test_user", "bad_token", config=testbed_config) as client:
            with pytest.raises(AuthError):
                await client.poll()

    def test_package_imports(self):
        """Test that all public APIs are importable."""
        assert True
