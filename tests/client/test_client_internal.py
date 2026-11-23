"""Internal branch coverage tests for EventClient internals."""

from __future__ import annotations

import asyncio

import pytest
from aiohttp import ClientSession
from aioresponses import aioresponses

from cb_events import AuthError, ClientConfig, EventClient, EventsError
from cb_events._client import TESTBED_URL
from tests.helpers import make_events_url


async def test_poll_raises_when_client_not_initialized() -> None:
    """Poll should fail fast when called before entering context manager."""
    client = EventClient(make_events_url("user", "token"))

    with pytest.raises(EventsError, match="Client not initialized"):
        await client.poll()


async def test_perform_request_attempt_raises_when_session_missing() -> None:
    """_perform_request_attempt should reject missing sessions."""
    client = EventClient(make_events_url("user", "token"))

    with pytest.raises(EventsError, match="session unexpectedly unavailable"):
        await client._perform_request_attempt("https://events.testbed.cb.dev/events")


async def test_aenter_propagates_session_creation_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Session creation failures should retain their original exception type."""

    def _boom(*_args: object, **_kwargs: object) -> object:
        msg = "socket init failed"
        raise OSError(msg)

    monkeypatch.setattr("cb_events._client.ClientSession", _boom)
    client = EventClient(make_events_url("user", "token"))

    with pytest.raises(OSError, match="socket init failed"):
        async with client:
            pass


async def test_aenter_rejects_closed_injected_session() -> None:
    """A closed caller-owned session cannot be used by the client lifecycle."""
    session = ClientSession()
    await session.close()
    client = EventClient(
        make_events_url("user", "token"),
        session=session,
    )

    with pytest.raises(EventsError, match="already closed"):
        async with client:
            pass


async def test_poll_debug_logs_masked_url(
    caplog: pytest.LogCaptureFixture,
    aioresponses_mock: aioresponses,
) -> None:
    """Poll should emit a debug log with a masked URL when debug is enabled."""
    client = EventClient(
        make_events_url("test_user", "secret_token_123"),
        config=ClientConfig(),
    )

    request_url = f"{TESTBED_URL}/test_user/secret_token_123/?timeout=10"
    aioresponses_mock.get(
        request_url,
        payload={"events": [], "nextUrl": None},
    )

    caplog.set_level("DEBUG", logger="cb_events._client")
    async with client:
        events = await client.poll()

    assert events == []
    assert "Polling https://events.testbed.cb.dev/events/test_user/" in caplog.text
    assert "secret_token_123" not in caplog.text


async def test_poll_uses_injected_session(
    aioresponses_mock: aioresponses,
) -> None:
    """Injected sessions should perform requests and remain caller-owned."""
    request_url = f"{TESTBED_URL}/test_user/test_token/?timeout=10"
    aioresponses_mock.get(
        request_url,
        payload={"events": [], "nextUrl": None},
    )
    session = ClientSession()
    client = EventClient(
        make_events_url("test_user", "test_token"),
        session=session,
    )

    try:
        async with client:
            events = await client.poll()
        assert events == []
        assert not session.closed
    finally:
        await session.close()


async def test_poll_handles_http_status_with_raise_for_status_injected_session(
    aioresponses_mock: aioresponses,
) -> None:
    """Injected sessions with raise_for_status should still return handled HTTP statuses."""
    request_url = f"{TESTBED_URL}/test_user/test_token/?timeout=10"
    aioresponses_mock.get(request_url, status=401, body="Unauthorized")
    session = ClientSession(raise_for_status=True)
    client = EventClient(
        make_events_url("test_user", "test_token"),
        session=session,
    )

    try:
        async with client:
            with pytest.raises(AuthError, match="HTTP 401"):
                await client.poll()
    finally:
        await session.close()


async def test_close_cancels_active_poll_without_wrapping_cancelled_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Close should cancel in-flight polls without converting the cancellation into EventsError."""
    client = EventClient(make_events_url("user", "token"))

    poll_task_started = asyncio.Event()

    async def _slow_request(_self: EventClient, _url: str) -> tuple[int, str]:
        poll_task_started.set()
        await asyncio.sleep(10)
        return 200, '{"events": [], "nextUrl": null}'

    monkeypatch.setattr(EventClient, "_request", _slow_request)

    async with client:
        poll_task = asyncio.create_task(client.poll())
        await poll_task_started.wait()

        await client.close()

        with pytest.raises(asyncio.CancelledError):
            await poll_task


async def test_request_non_retriable_error_is_propagated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Non-retriable exceptions should bypass retry wrapping."""
    client = EventClient(make_events_url("user", "token"))

    async def _boom(_self: EventClient, _url: str) -> tuple[int, str]:
        await asyncio.sleep(0)
        msg = "bad payload"
        raise ValueError(msg)

    monkeypatch.setattr(EventClient, "_perform_request_attempt", _boom)

    async with client:
        with pytest.raises(ValueError, match="bad payload"):
            await client._request("https://events.testbed.cb.dev/events")


async def test_request_raises_unexpected_error_when_retry_context_is_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Empty retry contexts should trigger the defensive fallback error."""
    client = EventClient(make_events_url("user", "token"))

    class _EmptyRetryContext:
        def __aiter__(self) -> _EmptyRetryContext:
            return self

        async def __anext__(self) -> object:
            raise StopAsyncIteration

        def with_name(
            self,
            _name: str,
            _args: tuple[object, ...],
            _kwargs: dict[str, object],
        ) -> _EmptyRetryContext:
            return self

    def _empty_retry_context(**_kwargs: object) -> _EmptyRetryContext:
        return _EmptyRetryContext()

    monkeypatch.setattr(
        "cb_events._request.stamina.retry_context",
        _empty_retry_context,
    )

    async with client:
        with pytest.raises(EventsError, match="Unexpected error in request loop"):
            await client._request("https://events.testbed.cb.dev/events")
