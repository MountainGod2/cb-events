"""Concurrency tests for EventClient polling."""

import asyncio
import json

import pytest

from cb_events import EventClient
from tests.conftest import EventClientFactory
from tests.helpers import make_events_url


async def test_concurrent_polls_are_serialized_per_client(
    event_client_factory: EventClientFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A single client should only have one in-flight poll at a time."""
    entered_first_request = asyncio.Event()
    release_first_request = asyncio.Event()
    in_flight = 0
    max_in_flight = 0

    async def _fake_request(_self: EventClient, _url: str) -> tuple[int, str]:
        nonlocal in_flight, max_in_flight
        in_flight += 1
        max_in_flight = max(max_in_flight, in_flight)
        if max_in_flight == 1:
            entered_first_request.set()
            await release_first_request.wait()
        in_flight -= 1
        constructed_url = make_events_url("user", "token")
        return 200, json.dumps({"events": [], "nextUrl": f"{constructed_url}&next=1"})

    monkeypatch.setattr(EventClient, "_request", _fake_request)

    async with event_client_factory() as client:
        first_poll = asyncio.create_task(client.poll())
        await entered_first_request.wait()

        second_poll = asyncio.create_task(client.poll())
        release_first_request.set()

        await asyncio.gather(first_poll, second_poll)

    assert max_in_flight == 1


async def test_close_cancels_inflight_poll(
    event_client_factory: EventClientFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Close should cancel a running poll and finish without waiting for long I/O."""
    started = asyncio.Event()
    release = asyncio.Event()

    async def _slow_request(_self: EventClient, _url: str) -> tuple[int, str]:
        started.set()
        await release.wait()
        return 200, '{"events": [], "nextUrl": null}'

    monkeypatch.setattr(EventClient, "_request", _slow_request)

    async with event_client_factory() as client:
        poll_task = asyncio.create_task(client.poll())
        await started.wait()

        await client.close()

        with pytest.raises(asyncio.CancelledError):
            await poll_task

        assert client.session is None


async def test_close_propagates_caller_cancellation(
    event_client_factory: EventClientFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A cancellation of the closer itself should not be swallowed during shutdown."""
    started = asyncio.Event()
    release = asyncio.Event()
    poll_cancelled = asyncio.Event()

    async def _slow_request(_self: EventClient, _url: str) -> tuple[int, str]:
        started.set()
        try:
            await release.wait()
        except asyncio.CancelledError:
            poll_cancelled.set()
            raise
        return 200, '{"events": [], "nextUrl": null}'

    monkeypatch.setattr(EventClient, "_request", _slow_request)

    async with event_client_factory() as client:
        poll_task = asyncio.create_task(client.poll())
        await started.wait()

        session = client.session
        assert session is not None

        close_task = asyncio.create_task(client.close())
        await poll_cancelled.wait()
        close_task.cancel()

        with pytest.raises(asyncio.CancelledError):
            await close_task

        with pytest.raises(asyncio.CancelledError):
            await poll_task

        assert session.closed
