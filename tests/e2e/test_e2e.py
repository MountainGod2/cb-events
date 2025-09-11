"""Basic post-build validation tests."""

import asyncio

import pytest

from chaturbate_events import AuthError, Event, EventClient, EventRouter, EventType


@pytest.mark.asyncio
async def test_client_functionality() -> None:
    """Validate basic client operations work after build."""
    async with EventClient("testuser", "testtoken") as client:
        assert client.username == "testuser"
        assert client.session is not None

        with pytest.raises(AuthError):
            await client.poll()


@pytest.mark.asyncio
async def test_full_workflow_integration() -> None:
    """Test a complete workflow without making actual API calls."""
    router = EventRouter()

    @router.on("tip")
    async def handle_tip(event: Event) -> None:
        await asyncio.sleep(0)
        assert event.type == EventType.TIP

    @router.on_any()
    async def handle_any(event: Event) -> None:
        pass

    async with EventClient("testuser", "testtoken", use_testbed=True) as client:
        assert client.base_url == EventClient.TESTBED_URL

        assert "tip" in router._handlers
        assert len(router._global_handlers) == 1
        assert router._global_handlers[0] == handle_any


def test_input_validation() -> None:
    """Test client validates inputs."""
    with pytest.raises(ValueError, match="Username cannot be empty"):
        EventClient("", "token")

    with pytest.raises(ValueError, match="Token cannot be empty"):
        EventClient("user", "")


def test_token_masking() -> None:
    """Test token is masked in string representation."""
    client = EventClient("user", "secrettoken123")
    repr_str = repr(client)
    assert "secrettoken123" not in repr_str
    assert "**********n123" in repr_str
