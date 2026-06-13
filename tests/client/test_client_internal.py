"""Internal branch coverage tests for EventClient internals."""

from __future__ import annotations

import asyncio
import json
import logging
from urllib.parse import urlparse

import pytest
from aioresponses import aioresponses

from cb_events import ClientConfig, EventClient, EventsError
from cb_events._client import TESTBED_URL
from cb_events._parser import (
    ParserContext,
    _extract_next_url_from_timeout,
    _parse_json_response,
)
from tests.helpers import make_events_url


def _parser_context(username: str = "user") -> ParserContext:
    return ParserContext(
        username=username,
        base_url=TESTBED_URL,
        parsed_base_url=urlparse(TESTBED_URL),
        logger=logging.getLogger("cb_events._client"),
    )


async def test_request_raises_when_client_not_initialized() -> None:
    """_request should fail fast when called outside context manager."""
    client = EventClient(make_events_url("user", "token"))

    with pytest.raises(EventsError, match="Client not initialized"):
        await client._request("https://events.testbed.cb.dev/events")


async def test_perform_request_attempt_raises_when_session_missing() -> None:
    """_perform_request_attempt should reject missing sessions."""
    client = EventClient(make_events_url("user", "token"))

    with pytest.raises(EventsError, match="session unexpectedly unavailable"):
        await client._perform_request_attempt("https://events.testbed.cb.dev/events")


async def test_aenter_wraps_session_creation_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Session creation failures should be wrapped in EventsError."""

    def _boom(*_args: object, **_kwargs: object) -> object:
        msg = "socket init failed"
        raise OSError(msg)

    monkeypatch.setattr("cb_events._client.ClientSession", _boom)
    client = EventClient(make_events_url("user", "token"))

    with pytest.raises(EventsError, match="Failed to create HTTP session"):
        async with client:
            pass


def test_extract_next_url_timeout_payload_not_mapping() -> None:
    """Non-object timeout payloads should return None."""
    assert (
        _extract_next_url_from_timeout(
            "[]",
            context=_parser_context(),
            log_next_url=lambda _next_url: None,
        )
        is None
    )


def test_extract_next_url_timeout_status_not_string() -> None:
    """Timeout payloads with non-string status should return None."""
    payload = json.dumps({
        "status": 123,
        "nextUrl": "https://events.testbed.cb.dev/events/next",
    })
    assert (
        _extract_next_url_from_timeout(
            payload,
            context=_parser_context(),
            log_next_url=lambda _next_url: None,
        )
        is None
    )


def test_extract_next_url_timeout_status_without_timeout_text() -> None:
    """Timeout parser should ignore unrelated status messages."""
    payload = json.dumps({
        "status": "ok",
        "nextUrl": "https://events.testbed.cb.dev/events/next",
    })
    assert (
        _extract_next_url_from_timeout(
            payload,
            context=_parser_context(),
            log_next_url=lambda _next_url: None,
        )
        is None
    )


def test_extract_next_url_timeout_missing_next_url() -> None:
    """Timeout parser should return None when nextUrl is absent."""
    payload = json.dumps({"status": "waited too long for events"})
    assert (
        _extract_next_url_from_timeout(
            payload,
            context=_parser_context(),
            log_next_url=lambda _next_url: None,
        )
        is None
    )


def test_extract_next_url_timeout_when_validator_returns_none() -> None:
    """Invalid timeout nextUrl should raise with direct validation path."""
    payload = json.dumps({
        "status": "waited too long for events",
        "nextUrl": "",
    })

    with pytest.raises(EventsError, match="nextUrl"):
        _extract_next_url_from_timeout(
            payload,
            context=_parser_context(),
            log_next_url=lambda _next_url: None,
        )


def test_parse_json_response_rejects_non_object() -> None:
    """Top-level JSON arrays should be rejected."""
    with pytest.raises(EventsError, match=r"(?i)expected JSON object"):
        _parse_json_response(
            "[]",
            strict_validation=False,
            context=_parser_context(),
        )


def test_parse_json_response_allows_missing_events_key() -> None:
    """Missing events key should be treated as an empty event list."""
    _parse_json_response(
        '{"nextUrl": null}',
        strict_validation=False,
        context=_parser_context(),
    )


def test_parse_json_response_debug_logs_event_count(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Debug logging should include the number of parsed events."""
    payload = json.dumps({
        "events": [{"method": "tip", "id": "evt-1", "object": {}}],
        "nextUrl": None,
    })

    caplog.set_level("DEBUG", logger="cb_events._client")
    _parse_json_response(
        payload,
        strict_validation=False,
        context=_parser_context(),
    )

    assert "Received 1 events for user user" in caplog.text


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
        events = await client._poll()

    assert events == []
    assert "Polling https://events.testbed.cb.dev/events/test_user/" in caplog.text
    assert "secret_token_123" not in caplog.text


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

    def _empty_retry_context(**_kwargs: object) -> _EmptyRetryContext:
        return _EmptyRetryContext()

    monkeypatch.setattr(
        "cb_events._request.stamina.retry_context",
        _empty_retry_context,
    )

    async with client:
        with pytest.raises(EventsError, match="Unexpected error in request loop"):
            await client._request("https://events.testbed.cb.dev/events")
