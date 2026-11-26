"""Concurrency tests for EventClient polling."""

import asyncio
import json

import pytest

from cb_events import EventClient, EventsError
from cb_events import _client as client_module
from tests.helpers import EventClientFactory, make_events_url


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


async def test_close_stops_inflight_poll_without_cancelling_caller_task(
    event_client_factory: EventClientFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Close should signal the poll and preserve its task ownership."""
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

        with pytest.raises(EventsError, match="stopped because client is closing"):
            await poll_task

        assert client.session is None


async def test_poll_rechecks_state_after_waiting_for_semaphore(
    event_client_factory: EventClientFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A queued poll should fail instead of starting after client shutdown."""
    first_started = asyncio.Event()

    async def _slow_request(_self: EventClient, _url: str) -> tuple[int, str]:
        first_started.set()
        await asyncio.sleep(10)
        return 200, '{"events": [], "nextUrl": null}'

    monkeypatch.setattr(EventClient, "_request", _slow_request)

    async with event_client_factory() as client:
        first_poll = asyncio.create_task(client.poll())
        await first_started.wait()
        queued_poll = asyncio.create_task(client.poll())
        await asyncio.sleep(0)

        await client.close()

        with pytest.raises(EventsError, match="stopped because client is closing"):
            await first_poll
        with pytest.raises(EventsError, match="closing or closed"):
            await queued_poll


async def test_poll_does_not_register_task_when_url_building_fails(
    event_client_factory: EventClientFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A pre-request failure should leave no work behind."""

    def _fail_build(_self: EventClient, next_url: str | None = None) -> str:
        del next_url
        msg = "invalid URL"
        raise ValueError(msg)

    monkeypatch.setattr(EventClient, "_build_url", _fail_build)

    async with event_client_factory() as client:
        with pytest.raises(ValueError, match="invalid URL"):
            await client.poll()

        assert client.session is not None


async def test_poll_skips_url_masking_when_debug_is_disabled(
    event_client_factory: EventClientFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Disabled debug logging should not perform token masking work."""

    async def _empty_response(_self: EventClient, _url: str) -> tuple[int, str]:
        await asyncio.sleep(0)
        return 200, '{"events": [], "nextUrl": null}'

    def _unexpected_mask(_url: str, _token: str) -> str:
        msg = "mask called"
        raise AssertionError(msg)

    monkeypatch.setattr(EventClient, "_request", _empty_response)
    monkeypatch.setattr(client_module, "_mask_url", _unexpected_mask)
    monkeypatch.setattr(client_module._logger, "isEnabledFor", lambda _level: False)

    async with event_client_factory() as client:
        assert await client.poll() == []
