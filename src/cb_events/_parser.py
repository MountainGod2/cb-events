"""Response parsing and nextUrl validation helpers for EventClient."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from http import HTTPStatus
from typing import TYPE_CHECKING, TypeGuard
from urllib.parse import urljoin, urlparse

from pydantic import ValidationError

from ._exceptions import AUTH_ERROR_STATUS_CODES, AuthError, EventsError, build_http_error
from ._models import Event
from ._utils import TRUNCATE_LENGTH, truncate_text

if TYPE_CHECKING:
    import logging
    from collections.abc import Callable, Sequence
    from urllib.parse import ParseResult


_TIMEOUT_STATUS_MESSAGE = "waited too long"


@dataclass(frozen=True)
class ParserContext:
    """Shared context used by response parsing helpers.

    Attributes:
        username: Account username used for diagnostics.
        base_url: Canonical base API URL.
        logger: Logger used for warnings/debug output.
        parsed_base_url: Parsed representation of base_url. Derived
            automatically from base_url; do not pass this explicitly.
    """

    username: str
    base_url: str
    logger: logging.Logger
    parsed_base_url: ParseResult = field(init=False)

    def __post_init__(self) -> None:
        """Derive parsed_base_url from base_url.

        Uses object.__setattr__ because the dataclass is frozen.
        """
        object.__setattr__(self, "parsed_base_url", urlparse(self.base_url))


def _is_json_object(value: object) -> TypeGuard[dict[str, object]]:
    """Return True when value is a JSON object dict."""
    return isinstance(value, dict)


def _is_object_list(value: object) -> TypeGuard[list[object]]:
    """Return True when value is a JSON array list."""
    return isinstance(value, list)


def _parse_json_object(text: str) -> dict[str, object]:
    """Parse text as a JSON object.

    Args:
        text: Raw response body.

    Returns:
        Parsed JSON object.

    Raises:
        EventsError: If JSON is malformed or top-level is not an object.
    """
    try:
        data: object = json.loads(text)  # pyright: ignore[reportAny]
    except json.JSONDecodeError as exc:
        msg = f"Invalid JSON: {exc.msg}."
        raise EventsError(msg, response_text=text) from exc
    if not _is_json_object(data):
        msg = f"Expected JSON object, got {type(data).__name__}."
        raise EventsError(msg, response_text=text)
    return data


def _log_validation_error(
    item: object,
    exc: ValidationError,
    *,
    logger: logging.Logger,
) -> None:
    """Log a warning for an event that failed Pydantic validation."""
    event_id = item.get("id", "<unknown>") if _is_json_object(item) else "<unknown>"
    fields: set[str] = set()
    for detail in exc.errors():
        location = detail.get("loc")
        if not location:
            continue
        fields.add(".".join(str(part) for part in location))
    logger.warning(
        "Skipping invalid event %s (invalid fields: %s)",
        event_id,
        ", ".join(sorted(fields)),
    )


def _parse_event(
    item: object,
    *,
    strict: bool,
    context: ParserContext,
) -> Event | None:
    """Parse one raw event object into an Event model.

    Args:
        item: Raw event payload object.
        strict: Whether validation errors should be raised.
        context: Parsing context.

    Returns:
        Parsed Event, or None in non-strict mode when validation fails.

    Raises:
        ValidationError: If strict is True and validation fails.
    """
    try:
        return Event.model_validate(item)
    except ValidationError as exc:
        if strict:
            raise
        _log_validation_error(item, exc, logger=context.logger)
        return None


def _parse_events(
    raw: Sequence[object],
    *,
    strict: bool,
    context: ParserContext,
) -> list[Event]:
    """Parse raw event dictionaries into Event models.

    Args:
        raw: Raw JSON-compatible event payload items.
        strict: Whether validation errors should be raised.
        context: Parsing context.

    Returns:
        Parsed events.
    """
    return [
        event
        for item in raw
        if (event := _parse_event(item, strict=strict, context=context)) is not None
    ]


def _resolve_absolute_url(
    stripped: str,
    *,
    context: ParserContext,
) -> tuple[str, ParseResult]:
    """Resolve nextUrl to an absolute URL.

    Args:
        stripped: nextUrl value with surrounding whitespace removed.
        context: Parsing context.

    Returns:
        Tuple of (absolute URL, parsed URL object).
    """
    parsed = urlparse(stripped)
    if not parsed.scheme and not parsed.netloc:
        base_origin = (
            f"{context.parsed_base_url.scheme}://{context.parsed_base_url.netloc}"
            if context.parsed_base_url.scheme and context.parsed_base_url.netloc
            else context.base_url
        )
        base_for_join = base_origin if stripped.startswith("/") else context.base_url
        base_for_join = f"{base_for_join.rstrip('/')}/"
        absolute = urljoin(base_for_join, stripped)
        return absolute, urlparse(absolute)
    if not parsed.scheme and (parsed.netloc or stripped.startswith("//")):
        absolute = f"{context.parsed_base_url.scheme}:{stripped}"
        return absolute, urlparse(absolute)
    return stripped, parsed


def _validate_next_url(
    next_url: object,
    *,
    response_text: str,
    context: ParserContext,
) -> str | None:
    """Validate and normalize an API nextUrl value.

    Args:
        next_url: Raw nextUrl value.
        response_text: Original response body for diagnostics.
        context: Parsing context.

    Returns:
        Normalized absolute nextUrl, or None when nextUrl is absent.

    Raises:
        EventsError: If nextUrl is malformed or points to an invalid host/scheme.
    """
    if next_url is None:
        return None

    msg = "Invalid API response: 'nextUrl' must be a non-empty string."
    if not isinstance(next_url, str):
        context.logger.error(
            "Received invalid nextUrl type %s for user %s",
            type(next_url).__name__,
            context.username,
        )
        raise EventsError(msg, response_text=response_text)

    stripped = next_url.strip()
    if not stripped:
        context.logger.error(
            "Received empty nextUrl from API for user %s",
            context.username,
        )
        raise EventsError(msg, response_text=response_text)

    absolute, parsed = _resolve_absolute_url(stripped, context=context)

    scheme = parsed.scheme
    if scheme != "https":
        context.logger.error(
            "Received nextUrl with unsupported scheme %s for user %s",
            scheme or "<missing>",
            context.username,
        )
        msg = "Invalid nextUrl scheme; only https is allowed."
        raise EventsError(msg, response_text=response_text)

    try:
        port = parsed.port
    except ValueError:
        context.logger.warning(
            "Received nextUrl with invalid port for user %s",
            context.username,
        )
        msg = "Invalid API response: 'nextUrl' contains an invalid port."
        raise EventsError(msg, response_text=response_text) from None

    if port is not None:
        context.logger.error(
            "Received nextUrl with custom port %s for user %s",
            port,
            context.username,
        )
        msg = "Invalid API response: 'nextUrl' must not contain a custom port."
        raise EventsError(msg, response_text=response_text)

    hostname = parsed.hostname
    if not hostname:
        context.logger.error(
            "Received nextUrl without hostname for user %s",
            context.username,
        )
        msg = "Invalid API response: 'nextUrl' must include a hostname."
        raise EventsError(msg, response_text=response_text)

    allowed_host = (context.parsed_base_url.hostname or "").lower()
    if hostname.lower() != allowed_host:
        context.logger.error(
            "Received nextUrl host %s which is not allowed for user %s",
            hostname,
            context.username,
        )
        msg = "Invalid API response: 'nextUrl' host is not allowed."
        raise EventsError(msg, response_text=response_text)

    return absolute


def _extract_next_url_from_timeout(
    text: str,
    *,
    context: ParserContext,
    log_next_url: Callable[[str], None],
) -> str | None:
    """Extract nextUrl from timeout-style responses.

    Args:
        text: Raw response body.
        context: Parsing context used for nextUrl validation.
        log_next_url: Callback used to log a masked nextUrl.

    Returns:
        Normalized nextUrl when present on timeout responses; otherwise None.
    """
    try:
        data = _parse_json_object(text)
    except EventsError:
        return None

    status_msg = data.get("status")
    if not (isinstance(status_msg, str) and _TIMEOUT_STATUS_MESSAGE in status_msg.lower()):
        return None

    next_url = data.get("nextUrl")
    if next_url is None:
        return None

    validated = _validate_next_url(
        next_url,
        response_text=text,
        context=context,
    )
    if validated is None:
        return None

    log_next_url(validated)
    return validated


def _parse_json_response(
    text: str,
    *,
    strict_validation: bool,
    context: ParserContext,
) -> tuple[list[Event], str | None]:
    """Parse response JSON into events and nextUrl.

    Args:
        text: Raw response body.
        strict_validation: Whether invalid events should raise validation errors.
        context: Parsing context.

    Returns:
        Tuple of (events, nextUrl).

    Raises:
        EventsError: If payload format is invalid.
    """
    try:
        data = _parse_json_object(text)
    except EventsError as exc:
        if isinstance(exc.__cause__, json.JSONDecodeError):
            snippet = truncate_text(text, limit=TRUNCATE_LENGTH)
            context.logger.exception("Failed to parse JSON: %s", snippet)
        raise

    next_url = _validate_next_url(
        data.get("nextUrl"),
        response_text=text,
        context=context,
    )
    if "events" in data:
        raw_events_obj: object = data["events"]
        if not _is_object_list(raw_events_obj):
            msg = (
                "Invalid API response format: 'events' must be a list. Each item must be an object."
            )
            raise EventsError(msg, response_text=text)
        raw_events_list = raw_events_obj
    else:
        raw_events_list = []

    events = _parse_events(
        raw_events_list,
        strict=strict_validation,
        context=context,
    )

    if events:
        context.logger.debug(
            "Received %d events for user %s",
            len(events),
            context.username,
        )

    return events, next_url


def process_response(
    status: int,
    text: str,
    *,
    context: ParserContext,
    strict_validation: bool,
    log_next_url: Callable[[str], None],
) -> tuple[list[Event], str | None]:
    """Process an HTTP response and return parsed events and nextUrl.

    Args:
        status: HTTP status code.
        text: Raw response body.
        context: Parsing context.
        strict_validation: Whether invalid events should raise validation errors.
        log_next_url: Callback used to log a masked nextUrl.

    Returns:
        Tuple of (events, nextUrl).

    Raises:
        AuthError: If authentication fails.
        HttpStatusError: If response status is non-200 and not a timeout redirect.
    """  # noqa: DOC501, DOC502  # ruff wants the raised function listed, not the propagated error.
    if status in AUTH_ERROR_STATUS_CODES:
        context.logger.warning(
            "Authentication failed for user %s (HTTP %d)",
            context.username,
            status,
        )
        msg = (
            f"Authentication failed for '{context.username}'. "
            "Verify your username and token are correct. "
            "Generate a new token at "
            "https://chaturbate.com/statsapi/authtoken/."
        )
        raise AuthError(msg, status_code=status, response_text=text)

    if status == HTTPStatus.BAD_REQUEST and (
        next_url := _extract_next_url_from_timeout(
            text,
            context=context,
            log_next_url=log_next_url,
        )
    ):
        return [], next_url

    if status != HTTPStatus.OK:
        snippet = truncate_text(text, limit=TRUNCATE_LENGTH)
        context.logger.error(
            "HTTP %d for user %s: %s",
            status,
            context.username,
            snippet,
        )

        msg = f"Request failed: {snippet}"
        raise build_http_error(
            msg,
            status_code=status,
            response_text=text,
        )

    return _parse_json_response(
        text,
        strict_validation=strict_validation,
        context=context,
    )
