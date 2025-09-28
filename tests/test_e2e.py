"""Basic post-build validation tests."""

import asyncio

import pytest

from cb_events import Event, EventClient, EventClientConfig, EventRouter, EventType
from cb_events.constants import TESTBED_URL
from cb_events.exceptions import AuthError


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_client_basic_functionality() -> None:
    """Validate basic client operations work after build."""
    async with EventClient("testuser", "testtoken") as client:
        assert client.username == "testuser"
        assert client.session is not None

        with pytest.raises(AuthError):
            await client.poll()


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_complete_workflow_integration() -> None:
    """Test a complete workflow without making actual API calls."""
    router = EventRouter()

    @router.on("tip")
    async def handle_tip(event: Event) -> None:
        await asyncio.sleep(0)
        assert event.type == EventType.TIP

    @router.on_any()
    async def handle_any(event: Event) -> None:
        pass

    async with EventClient(
        "testuser",
        "testtoken",
        config=EventClientConfig(use_testbed=True),
    ) as client:
        assert client.base_url == TESTBED_URL

        assert "tip" in router._handlers
        assert len(router._global_handlers) == 1
        assert router._global_handlers[0] == handle_any
