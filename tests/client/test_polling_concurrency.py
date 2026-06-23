"""Concurrency tests for EventClient polling."""

import asyncio
import json

import pytest

from cb_events import EventClient, EventsError
from tests.conftest import EventClientFactory
from tests.helpers import make_events_url


async def test_concurrent_polls_release_lock_during_http_call(
    event_client_factory: EventClientFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Concurrent polls should overlap I/O while protecting nextUrl state updates."""
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
        first_poll = asyncio.create_task(client._poll())
        await entered_first_request.wait()

        second_poll = asyncio.create_task(client._poll())
        await asyncio.sleep(0)
        release_first_request.set()

        await asyncio.gather(first_poll, second_poll)

    assert max_in_flight >= 2


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
        poll_task = asyncio.create_task(client._poll())
        await started.wait()

        await client.close()

        with pytest.raises(EventsError, match="client is closing"):
            await poll_task

        assert client.session is None
