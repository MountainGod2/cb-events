"""Parser and nextUrl validation tests for EventClient internals."""

from __future__ import annotations

import json
import logging
from urllib.parse import urlparse

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from cb_events import EventsError
from cb_events._client import TESTBED_URL
from cb_events._parser import (
    ParserContext,
    _extract_next_url_from_timeout,
    _parse_json_response,
    _resolve_absolute_url,
    _validate_next_url,
)

_ALLOWED_HOST = "events.testbed.cb.dev"


def _parser_context(username: str = "user") -> ParserContext:
    return ParserContext(
        username=username,
        base_url=TESTBED_URL,
        logger=logging.getLogger("cb_events._parser"),
    )


@st.composite
def _next_url_cases(draw: st.DrawFn) -> tuple[object, str | None]:  # ruff:ignore[too-many-return-statements]
    kind = draw(
        st.sampled_from(
            [
                "valid_absolute",
                "valid_relative",
                "protocol_relative_allowed",
                "protocol_relative_blocked",
                "bad_scheme",
                "missing_host",
                "custom_port",
                "invalid_port",
                "off_host",
                "empty",
            ],
        ),
    )

    path = draw(
        st.sampled_from(
            [
                "/events/next_batch_token",
                "/events/test_user/test_token/?timeout=10&next=relative",
                "/events/test_user/test_token/",
            ],
        ),
    )

    if kind == "valid_absolute":
        return f"https://{_ALLOWED_HOST}{path}", None
    if kind == "valid_relative":
        relative = draw(st.sampled_from([path.lstrip("/"), path]))
        return relative, None
    if kind == "protocol_relative_allowed":
        return f"//{_ALLOWED_HOST}{path}", None
    if kind == "protocol_relative_blocked":
        return f"//evil.example.com{path}", r"host is not allowed"
    if kind == "bad_scheme":
        scheme = draw(st.sampled_from(["http", "javascript", "ftp"]))
        return f"{scheme}://{_ALLOWED_HOST}{path}", r"Invalid nextUrl scheme"
    if kind == "missing_host":
        return f"https:///{path.lstrip('/')}", r"must include a hostname"
    if kind == "custom_port":
        port = draw(st.integers(min_value=1, max_value=65535))
        return f"https://{_ALLOWED_HOST}:{port}{path}", r"must not contain a custom port"
    if kind == "invalid_port":
        suffix = draw(st.sampled_from(["abc", "12x", "9a9"]))
        return f"https://{_ALLOWED_HOST}:{suffix}{path}", r"contains an invalid port"
    if kind == "off_host":
        host = draw(st.sampled_from(["evil.example.com", "localhost", "127.0.0.1"]))
        return f"https://{host}{path}", r"host is not allowed"

    return draw(st.sampled_from(["", " ", "   "])), r"must be a non-empty string"


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

    caplog.set_level("DEBUG", logger="cb_events._parser")
    _parse_json_response(
        payload,
        strict_validation=False,
        context=_parser_context(),
    )

    assert "Received 1 events for user user" in caplog.text


@given(case=_next_url_cases())
@settings(max_examples=50, deadline=None)
def test_validate_next_url_property_cases(case: tuple[object, str | None]) -> None:
    """Property-based coverage for nextUrl validation edge cases."""
    next_url, expected_pattern = case
    context = _parser_context()

    if expected_pattern is None:
        validated = _validate_next_url(next_url, response_text="{}", context=context)
        assert validated is not None

        resolved, parsed = _resolve_absolute_url(str(next_url).strip(), context=context)
        assert validated == resolved
        assert parsed.scheme == "https"
        assert parsed.hostname == _ALLOWED_HOST
        assert parsed.port is None
        assert urlparse(validated).hostname == _ALLOWED_HOST
        return

    with pytest.raises(EventsError, match=expected_pattern):
        _validate_next_url(next_url, response_text="{}", context=context)
