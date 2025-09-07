"""Basic post-build validation tests."""

import pytest

import chaturbate_events


@pytest.mark.asyncio
async def test_client_functionality():
    """Validate basic client operations work after build."""
    async with chaturbate_events.EventClient("testuser", "testtoken") as client:
        assert client.username == "testuser"
        assert client.session is not None

        with pytest.raises(chaturbate_events.AuthError):
            await client.poll()


@pytest.mark.asyncio
async def test_testbed_client():
    """Test testbed configuration."""
    async with chaturbate_events.EventClient(
        "testuser", "testtoken", use_testbed=True
    ) as client:
        assert client.base_url == chaturbate_events.EventClient.TESTBED_URL


def test_input_validation():
    """Test client validates inputs."""
    with pytest.raises(ValueError, match="Username cannot be empty"):
        chaturbate_events.EventClient("", "token")

    with pytest.raises(ValueError, match="Token cannot be empty"):
        chaturbate_events.EventClient("user", "")


def test_token_masking():
    """Test token is masked in string representation."""
    client = chaturbate_events.EventClient("user", "secrettoken123")
    repr_str = repr(client)
    assert "secrettoken123" not in repr_str
    assert "**********n123" in repr_str


def test_router_registration():
    """Test event router handler registration."""
    router = chaturbate_events.EventRouter()

    @router.on("tip")
    async def tip_handler(event):
        pass

    @router.on_any()
    async def any_handler(event):
        pass

    assert "tip" in router._handlers  # noqa: SLF001
    assert len(router._global_handlers) == 1  # noqa: SLF001
