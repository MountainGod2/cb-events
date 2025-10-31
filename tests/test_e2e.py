"""Integration tests for cb-events package."""

from importlib.metadata import version

import pytest

from cb_events import AuthError, EventClient, EventRouter, EventType, __version__


@pytest.mark.e2e
class TestIntegration:
    """End-to-end integration tests."""

    async def test_client_router_workflow(self, mock_response, testbed_url_pattern, testbed_config):
        """Complete workflow from client polling to router dispatch."""
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

    async def test_client_context_manager_lifecycle(self):
        """Client should properly manage session lifecycle."""
        client = EventClient("test_user", "test_token")
        assert client.session is None

        async with client:
            assert client.session is not None

    async def test_authentication_error_propagation(
        self, mock_response, testbed_url_pattern, testbed_config
    ):
        """Authentication errors should propagate correctly."""
        mock_response.get(testbed_url_pattern, status=401)

        async with EventClient("test_user", "bad_token", config=testbed_config) as client:
            with pytest.raises(AuthError):
                await client.poll()

    async def test_version_attribute(self):
        """Package should have a __version__ attribute."""

        assert isinstance(__version__, str)
        assert version("cb-events") == __version__
