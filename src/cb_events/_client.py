"""Async HTTP client for polling the Chaturbate Events API."""

from __future__ import annotations

import asyncio
import json
import logging
from contextlib import suppress
from enum import Enum, auto
from http import HTTPStatus
from typing import TYPE_CHECKING, Final, NoReturn, TypeGuard
from urllib.parse import quote, unquote, urljoin, urlparse

import stamina
from aiohttp import ClientSession, ClientTimeout
from aiohttp.client_exceptions import ClientError
from aiolimiter import AsyncLimiter
from pydantic import ValidationError

from ._compat import override
from ._config import ClientConfig
from ._exceptions import (
    AUTH_ERROR_STATUS_CODES,
    CF_SERVER_ERROR_CODES,
    TRUNCATE_LENGTH,
    AuthError,
    EventsError,
    build_http_error,
    truncate_text,
)
from ._models import Event

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Sequence
    from types import TracebackType
    from urllib.parse import ParseResult

    from ._compat import Self


_logger = logging.getLogger(__name__)
"""Module logger."""

BASE_URL: Final[str] = "https://eventsapi.chaturbate.com/events"
"""Production Events API base URL."""

TESTBED_URL: Final[str] = "https://events.testbed.cb.dev/events"
"""Testbed Events API base URL."""

_DEFAULT_MAX_RATE: Final[int] = 2000
"""Default request budget per limiter window."""

_DEFAULT_TIME_PERIOD: Final[int] = 60
"""Limiter window size in seconds."""

_SESSION_TIMEOUT_BUFFER: Final[int] = 5
"""Extra seconds added to the client timeout."""

_RETRY_STATUS_CODES: Final[frozenset[int]] = frozenset({
    HTTPStatus.INTERNAL_SERVER_ERROR.value,
    HTTPStatus.BAD_GATEWAY.value,
    HTTPStatus.SERVICE_UNAVAILABLE.value,
    HTTPStatus.GATEWAY_TIMEOUT.value,
    HTTPStatus.TOO_MANY_REQUESTS.value,
    *CF_SERVER_ERROR_CODES,
})
"""HTTP status codes retried with exponential backoff."""

_TOKEN_VISIBLE_CHARS: Final[int] = 0
"""Trailing token characters visible in logs (0 means fully masked)."""

_TIMEOUT_STATUS_MESSAGE: Final[str] = "waited too long"
"""Marker text used by timeout responses."""

_CLIENT_CLOSING_MESSAGE: Final[str] = "Client is closing or closed."
"""Error raised when polling while closing or closed."""

_CLIENT_CLOSED_ENTER_MESSAGE: Final[str] = (
    "Client is closed and cannot be reopened. Create a new EventClient instance."
)
"""Error raised when entering a client after close()."""

_POLL_CANCELLED_ON_CLOSE_MESSAGE: Final[str] = "Polling cancelled because client is closing."
"""Error raised when close() cancels an active poll."""

_SUPPORTED_EVENTS_HOSTS: Final[dict[str, str]] = {
    "eventsapi.chaturbate.com": BASE_URL,
    "events.testbed.cb.dev": TESTBED_URL,
}
"""Allowed API hosts mapped to canonical base URLs."""


class _ClientState(Enum):
    """Lifecycle state of an :class:`EventClient` instance."""

    OPEN = auto()
    """Client is active and ready to poll."""

    CLOSING = auto()
    """Client is shutting down; new polls are rejected."""

    CLOSED = auto()
    """Client has been fully closed and cannot be reopened."""


class _RetryableStatusError(Exception):
    """Internal exception used to retry specific HTTP statuses.

    Carries status_code and response_text for later error mapping.
    """

    status_code: int
    response_text: str

    def __init__(self, msg: str, *, status_code: int, response_text: str) -> None:
        """Initialize with message and HTTP metadata.

        Args:
            msg: Human-readable description of the transient failure.
            status_code: HTTP status code returned by the API.
            response_text: Raw response body returned by the API.
        """
        super().__init__(msg)
        self.status_code = status_code
        self.response_text = response_text


def _parse_and_validate_events_url(events_url: str) -> ParseResult:
    """Parse the Events URL and validate top-level URL components.

    Args:
        events_url: Full Events API URL provided by upstream.

    Returns:
        ParsedResult with validated scheme, host, and path shape.

    Raises:
        AuthError: If the URL is malformed or contains invalid components.
    """
    if not events_url or events_url != events_url.strip():
        msg = "Events URL must not be empty or contain leading/trailing whitespace."
        raise AuthError(msg)

    parsed = urlparse(events_url)
    if parsed.scheme != "https":
        msg = "Events URL must use https."
        raise AuthError(msg)

    if parsed.query or parsed.fragment:
        msg = "Events URL must not include query parameters or fragments."
        raise AuthError(msg)

    custom_port_msg = "Events URL must not include a custom port."
    try:
        if parsed.port is not None:
            raise AuthError(custom_port_msg)
    except ValueError as exc:
        raise AuthError(custom_port_msg) from exc

    return parsed


def _resolve_base_url(hostname: str | None) -> str:
    """Resolve canonical base URL from a parsed hostname.

    Args:
        hostname: Hostname extracted from the parsed Events URL.

    Returns:
        Canonical base URL corresponding to the hostname.

    Raises:
        AuthError: If the hostname is not in the list of supported hosts.
    """
    base_url = _SUPPORTED_EVENTS_HOSTS.get((hostname or "").lower())
    if base_url is not None:
        return base_url
    msg = "Events URL host is not supported. Use eventsapi.chaturbate.com or events.testbed.cb.dev."
    raise AuthError(msg)


def _extract_username_token(path: str) -> tuple[str, str]:
    """Extract and URL-decode username/token from an Events path.

    Args:
        path: Path component of the Events URL.

    Returns:
        Tuple of (username, token).

    Raises:
        AuthError: If the path does not match the expected format.
    """
    parts = [part for part in path.split("/") if part]
    if len(parts) != 3 or parts[0] != "events":  # noqa: PLR2004
        msg = "Events URL must match https://<host>/events/<username>/<token>/"
        raise AuthError(msg)
    return unquote(parts[1]), unquote(parts[2])


def _validate_non_empty_stripped(value: str, *, field: str, hint: str) -> None:
    """Raise AuthError if value is empty or has leading/trailing whitespace.

    Args:
        value: The string value to validate.
        field: Name of the field being validated, used in error messages.
        hint: Additional hint to include in the error message.

    Raises:
        AuthError: If the value is empty or contains leading/trailing whitespace.
    """
    if not value or value != value.strip():
        msg = f"{field} must not be empty or contain leading/trailing whitespace. {hint}"
        raise AuthError(msg)


def _parse_events_url(events_url: str) -> tuple[str, str, str]:
    """Parse and validate the Events API URL.

    Args:
        events_url: Full upstream URL containing host, username, and token.

    Returns:
        Tuple of (base_url, username, token).
    """
    parsed = _parse_and_validate_events_url(events_url)
    base_url = _resolve_base_url(parsed.hostname)
    username, token = _extract_username_token(parsed.path)
    _validate_non_empty_stripped(
        username, field="Username", hint="Provide a valid Chaturbate username."
    )
    _validate_non_empty_stripped(
        token,
        field="Token",
        hint="Generate a valid token at https://chaturbate.com/statsapi/authtoken/",
    )
    return base_url, username, token


def _mask_token(token: str, visible: int = _TOKEN_VISIBLE_CHARS) -> str:
    """Mask token for logging.

    Args:
        token: Raw token string to mask.
        visible: Number of trailing characters to leave unmasked.

    Returns:
        Masked token string.
    """
    if visible <= 0 or len(token) <= visible:
        return "*" * len(token)
    return f"{'*' * (len(token) - visible)}{token[-visible:]}"


def _mask_url(url: str, token: str) -> str:
    """Mask token in URL for safe logging.

    Args:
        url: Full URL that may contain the token.
        token: Raw token string to redact from the URL.

    Returns:
        URL string with token masked.
    """
    masked = _mask_token(token)
    return url.replace(token, masked).replace(quote(token, safe=""), masked)


def _is_json_object(value: object) -> TypeGuard[dict[str, object]]:
    """Return True when value is a JSON object dict."""
    return isinstance(value, dict)


def _is_object_list(value: object) -> TypeGuard[list[object]]:
    """Return True when value is a JSON array list."""
    return isinstance(value, list)


def _parse_json_object(text: str) -> dict[str, object]:
    """Parse text as a JSON object.

    Args:
        text: Raw response body expected to contain a JSON object.

    Returns:
        Parsed JSON object.

    Raises:
        EventsError: If JSON is invalid or the top-level value is not an object.
    """
    try:
        data: object = json.loads(text)  # pyright: ignore[reportAny]
    except json.JSONDecodeError as exc:
        msg = f"Invalid JSON: {exc.msg}."
        raise EventsError(msg, response_text=text) from exc
    if not _is_json_object(data):
        msg = f"Expected JSON object, got {type(data).__name__}."
        raise EventsError(
            msg,
            response_text=text,
        )
    return data


def _log_validation_error(
    item: object,
    exc: ValidationError,
) -> None:
    """Log a warning for an event that failed Pydantic validation.

    Args:
        item: Raw object that failed validation.
        exc: The ValidationError raised during parsing.
    """
    event_id = item.get("id", "<unknown>") if _is_json_object(item) else "<unknown>"
    fields: set[str] = set()
    for detail in exc.errors():
        location = detail.get("loc")
        if not location:
            continue
        fields.add(".".join(str(part) for part in location))
    _logger.warning(
        "Skipping invalid event %s (invalid fields: %s)",
        event_id,
        ", ".join(sorted(fields)),
    )


def _parse_events(raw: Sequence[object], *, strict: bool) -> list[Event]:
    """Parse raw event dictionaries into Event models.

    Args:
        raw: Raw JSON-compatible objects returned by the API.
        strict: Whether to raise ValidationError on invalid payloads.

    Returns:
        List of validated Event instances.
    """
    return [event for item in raw if (event := _parse_event(item, strict=strict)) is not None]


def _parse_event(item: object, *, strict: bool) -> Event | None:
    """Parse a single raw event object into an Event model.

    Args:
        item: Raw JSON-compatible object returned by the API.
        strict: Whether to raise ValidationError on invalid payloads.

    Returns:
        Validated Event instance, or None when validation fails in non-strict
        mode.

    Raises:
        ValidationError: If strict is True and validation fails.
    """
    try:
        return Event.model_validate(item)
    except ValidationError as exc:
        if strict:
            raise
        _log_validation_error(item, exc)
        return None


class EventClient:
    """Async long-poll client for Events API streams.

    Handles URL parsing, retries, rate limiting, and nextUrl continuation.
    Use as an async context manager and async iterator.
    """

    def __init__(
        self,
        events_url: str,
        *,
        config: ClientConfig | None = None,
        rate_limiter: AsyncLimiter | None = None,
    ) -> None:
        """Initialize a client from an Events API URL.

        Args:
            events_url: Full Events API URL provided by upstream.
            config: Optional client configuration overrides.
            rate_limiter: Optional shared limiter for multiple clients.
        """
        base_url, username, token = _parse_events_url(events_url)
        self.base_url: str = base_url
        self.username: str = username
        self._token: str = token
        self.config: ClientConfig = config or ClientConfig()
        self.session: ClientSession | None = None
        self._parsed_base_url: ParseResult = urlparse(base_url)
        self._active_poll_task: asyncio.Task[object] | None = None
        self._state: _ClientState = _ClientState.OPEN
        self._next_url: str | None = None
        self._polling_lock: asyncio.Lock = asyncio.Lock()
        self._rate_limiter: AsyncLimiter = rate_limiter or AsyncLimiter(
            max_rate=_DEFAULT_MAX_RATE,
            time_period=_DEFAULT_TIME_PERIOD,
        )

    @override
    def __repr__(self) -> str:
        """Return a representation with a masked token.

        Returns:
            Masked representation revealing only limited token characters.
        """
        return f"EventClient(username='{self.username}', token='{_mask_token(self._token)}')"

    async def __aenter__(self) -> Self:
        """Open the HTTP session on context entry.

        Returns:
            Self: Client instance ready for use.

        Raises:
            EventsError: If the client has already been closed, is already
                open, or if session creation fails.
        """
        creation_error: Exception | None = None
        async with self._polling_lock:
            if self._state in {_ClientState.CLOSED, _ClientState.CLOSING}:
                raise EventsError(_CLIENT_CLOSED_ENTER_MESSAGE)
            if self.session is not None:
                msg = (
                    "Client is already open. Use a new instance or exit the current context first."
                )
                raise EventsError(msg)
            try:
                self.session = ClientSession(
                    timeout=ClientTimeout(total=self.config.timeout + _SESSION_TIMEOUT_BUFFER),
                )
            except (ClientError, OSError, RuntimeError, TimeoutError) as e:
                creation_error = e
            else:
                return self

        # Preserve the prior behavior that a failed entry transitions the client to terminal state.
        if creation_error is not None:  # pyright:ignore[reportUnnecessaryComparison]
            await self.close()
            msg = "Failed to create HTTP session."
            raise EventsError(msg) from creation_error

        return None  # pyright:ignore[reportUnreachable]

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Close resources on context exit.

        Args:
            exc_type: Exception type raised inside the context, if any.
            exc_val: Exception instance raised inside the context, if any.
            exc_tb: Traceback object for the exception, if any.
        """
        await self.close()

    def _build_url(self) -> str:
        """Build the URL for the next poll.

        Note:
            The timeout query parameter is added only to the initial request URL.

        Returns:
            Fully qualified URL for the upcoming API request.
        """
        if self._next_url:
            return self._next_url
        return (
            f"{self.base_url}/{quote(self.username, safe='')}/"
            f"{quote(self._token, safe='')}/?timeout={self.config.timeout}"
        )

    async def _perform_request_attempt(self, url: str) -> tuple[int, str]:
        """Perform one HTTP request attempt.

        Args:
            url: Fully qualified endpoint to request.

        Returns:
            Tuple of (status_code, response_text).

        Raises:
            EventsError: If the client session is unexpectedly unavailable.
            _RetryableStatusError: If the status should trigger a retry.
        """
        if self.session is None:
            msg = "Client session unexpectedly unavailable"
            raise EventsError(msg)

        await self._rate_limiter.acquire()
        async with self.session.get(url, allow_redirects=False) as response:
            status = response.status
            text = await response.text()

        if status in _RETRY_STATUS_CODES:
            msg = f"HTTP {status}"
            raise _RetryableStatusError(msg, status_code=status, response_text=text)

        return status, text

    def _raise_request_failure(
        self,
        *,
        attempts_made: int,
        original_exception: Exception,
    ) -> NoReturn:
        """Raise the final request error after retries.

        Args:
            attempts_made: Number of attempts that were made before failure.
            original_exception: The last exception raised during the request.

        Raises:
            EventsError: With details about the failure, including HTTP metadata
                if available. Raised as a specific subclass (e.g. RateLimitError,
                ServerError) when the final failure was an HTTP status error.
        """  # noqa: DOC501
        _logger.error(
            "Request failed after %d attempts for user %s",
            attempts_made,
            self.username,
            exc_info=original_exception,
        )

        attempt_label = "attempt" if attempts_made == 1 else "attempts"
        msg = f"Failed to fetch events after {attempts_made} {attempt_label}."

        status_code: int | None = None
        response_text: str | None = None
        cause: Exception | None = original_exception

        if isinstance(original_exception, _RetryableStatusError):
            status_code = original_exception.status_code
            response_text = original_exception.response_text
            cause = None

        if status_code is not None:
            raise build_http_error(
                msg,
                status_code=status_code,
                response_text=response_text,
            ) from cause

        raise EventsError(
            msg,
            status_code=status_code,
            response_text=response_text,
        ) from cause

    async def _request(self, url: str) -> tuple[int, str]:
        """Run one request with retry/backoff policy.

        Args:
            url: Fully qualified endpoint to request.

        Returns:
            Tuple of (status_code, response_text).

        Raises:
            EventsError: If the client is not initialized or the request fails.
        """
        if self.session is None:
            msg = "Client not initialized. Use 'async with EventClient(...)' as a context manager."
            raise EventsError(msg)

        attempts_made = 0
        retriable_exc_types = (
            ClientError,
            TimeoutError,
            OSError,
            _RetryableStatusError,
        )

        try:
            async for attempt in stamina.retry_context(
                on=retriable_exc_types,
                attempts=self.config.retry_attempts,
                timeout=None,
                wait_initial=self.config.retry_backoff,
                wait_max=self.config.retry_max_delay,
                wait_exp_base=self.config.retry_factor,
            ):
                attempts_made = attempt.num
                try:
                    with attempt:
                        return await self._perform_request_attempt(url)
                except retriable_exc_types as exc:
                    if attempts_made < self.config.retry_attempts:
                        msg = "Attempt %d/%d failed for user %s: %r. Retrying..."
                        _logger.warning(
                            msg,
                            attempts_made,
                            self.config.retry_attempts,
                            self.username,
                            exc,
                        )
                    raise

        except retriable_exc_types as original_exception:
            self._raise_request_failure(
                attempts_made=attempts_made,
                original_exception=original_exception,
            )

        msg = "Unexpected error in request loop"
        raise EventsError(msg)  # pragma: no cover

    def _process_response(self, status: int, text: str) -> list[Event]:
        """Process an HTTP response and return events.

        Args:
            status: HTTP status code received from the API.
            text: Raw response body.

        Returns:
            List of parsed Event instances.

        Raises:
            AuthError: For HTTP 401/403 responses.
            EventsError: For other non-200 responses, or when a timeout response
                contains an invalid nextUrl.
        """  # noqa: DOC501, DOC502
        if status in AUTH_ERROR_STATUS_CODES:
            _logger.warning(
                "Authentication failed for user %s (HTTP %d)",
                self.username,
                status,
            )
            msg = (
                f"Authentication failed for '{self.username}'. "
                "Verify your username and token are correct. "
                "Generate a new token at "
                "https://chaturbate.com/statsapi/authtoken/."
            )
            raise AuthError(msg, status_code=status, response_text=text)

        if status == HTTPStatus.BAD_REQUEST and (
            next_url := self._extract_next_url_from_timeout(text)
        ):
            self._next_url = next_url
            return []

        if status != HTTPStatus.OK:
            snippet = truncate_text(text, limit=TRUNCATE_LENGTH)
            _logger.error(
                "HTTP %d for user %s: %s",
                status,
                self.username,
                snippet,
            )

            msg = f"Request failed: {snippet}"
            raise build_http_error(
                msg,
                status_code=status,
                response_text=text,
            )

        return self._parse_json_response(text)

    def _resolve_absolute_url(self, stripped: str) -> tuple[str, ParseResult]:
        """Resolve a nextUrl value to an absolute URL.

        Args:
            stripped: Stripped nextUrl string from the API response.

        Returns:
            Tuple of (absolute URL string, parsed ParseResult).
        """
        parsed = urlparse(stripped)
        if not parsed.scheme and not parsed.netloc:
            base_origin = (
                f"{self._parsed_base_url.scheme}://{self._parsed_base_url.netloc}"
                if self._parsed_base_url.scheme and self._parsed_base_url.netloc
                else self.base_url
            )
            base_for_join = base_origin if stripped.startswith("/") else self.base_url
            base_for_join = f"{base_for_join.rstrip('/')}/"
            absolute = urljoin(base_for_join, stripped)
            return absolute, urlparse(absolute)
        if not parsed.scheme and (parsed.netloc or stripped.startswith("//")):
            absolute = f"{self._parsed_base_url.scheme}:{stripped}"
            return absolute, urlparse(absolute)
        return stripped, parsed

    def _require_next_url_str(
        self,
        next_url: object,
        *,
        response_text: str,
    ) -> str:
        """Validate that a nextUrl value is a non-empty string.

        Args:
            next_url: Raw nextUrl value extracted from the API response.
            response_text: Original response body for error diagnostics.

        Returns:
            Stripped nextUrl string.

        Raises:
            EventsError: If next_url is not a string or is empty after stripping.
        """
        msg = "Invalid API response: 'nextUrl' must be a non-empty string."

        if not isinstance(next_url, str):
            _logger.error(
                "Received invalid nextUrl type %s for user %s",
                type(next_url).__name__,
                self.username,
            )
            raise EventsError(msg, response_text=response_text)

        stripped = next_url.strip()
        if not stripped:
            _logger.error(
                "Received empty nextUrl from API for user %s",
                self.username,
            )
            raise EventsError(msg, response_text=response_text)

        return stripped

    def _validate_next_url_scheme(self, parsed: ParseResult, *, response_text: str) -> None:
        """Validate that a parsed nextUrl uses the https scheme.

        Args:
            parsed: Parsed nextUrl components.
            response_text: Original response body for error diagnostics.

        Raises:
            EventsError: If the scheme is not https.
        """
        scheme = parsed.scheme
        if scheme == "https":
            return

        _logger.error(
            "Received nextUrl with unsupported scheme %s for user %s",
            scheme or "<missing>",
            self.username,
        )
        msg = "Invalid nextUrl scheme; only https is allowed."
        raise EventsError(msg, response_text=response_text)

    def _validate_next_url_port(self, parsed: ParseResult, *, response_text: str) -> None:
        """Validate that a parsed nextUrl does not include a custom port.

        Args:
            parsed: Parsed nextUrl components.
            response_text: Original response body for error diagnostics.

        Raises:
            EventsError: If a custom or malformed port is present.
        """
        try:
            port = parsed.port
        except ValueError:
            _logger.warning(
                "Received nextUrl with invalid port for user %s",
                self.username,
            )
            msg = "Invalid API response: 'nextUrl' contains an invalid port."
            raise EventsError(msg, response_text=response_text) from None

        if port is None:
            return

        _logger.error(
            "Received nextUrl with custom port %s for user %s",
            port,
            self.username,
        )
        msg = "Invalid API response: 'nextUrl' must not contain a custom port."
        raise EventsError(msg, response_text=response_text)

    def _validate_next_url_host(self, parsed: ParseResult, *, response_text: str) -> None:
        """Validate that a parsed nextUrl hostname matches the base API host.

        Args:
            parsed: Parsed nextUrl components.
            response_text: Original response body for error diagnostics.

        Raises:
            EventsError: If the hostname is missing or does not match the base API host.
        """
        hostname = parsed.hostname
        if not hostname:
            _logger.error(
                "Received nextUrl without hostname for user %s",
                self.username,
            )
            msg = "Invalid API response: 'nextUrl' must include a hostname."
            raise EventsError(msg, response_text=response_text)

        allowed_host = (self._parsed_base_url.hostname or "").lower()
        if hostname.lower() == allowed_host:
            return

        _logger.error(
            "Received nextUrl host %s which is not allowed for user %s",
            hostname,
            self.username,
        )
        msg = "Invalid API response: 'nextUrl' host is not allowed."
        raise EventsError(msg, response_text=response_text)

    def _validate_next_url(
        self,
        next_url: object,
        *,
        response_text: str,
    ) -> str | None:
        """Validate and normalize a nextUrl value from the API.

        Args:
            next_url: Raw nextUrl value extracted from the API response.
            response_text: Original response body for error diagnostics.

        Returns:
            Sanitized nextUrl string, or None when no follow-up poll is required.

        Raises:
            EventsError: If nextUrl is present but not a non-empty string, has
                an unsupported scheme, contains a custom port, or references a
                hostname other than the base API host.
        """  # noqa: DOC502
        if next_url is None:
            return None

        stripped = self._require_next_url_str(next_url, response_text=response_text)
        absolute, parsed = self._resolve_absolute_url(stripped)

        self._validate_next_url_scheme(parsed, response_text=response_text)
        self._validate_next_url_port(parsed, response_text=response_text)
        self._validate_next_url_host(parsed, response_text=response_text)

        return absolute

    def _extract_next_url_from_timeout(self, text: str) -> str | None:
        """Extract nextUrl from timeout-style responses.

        Args:
            text: Raw response body from the timeout response.

        Returns:
            The extracted nextUrl if found and valid, otherwise None.
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

        validated = self._validate_next_url(next_url, response_text=text)
        if validated is None:
            return None
        _logger.debug(
            "Received nextUrl from timeout response: %s",
            _mask_url(validated, self._token),
        )
        return validated

    def _parse_json_response(self, text: str) -> list[Event]:
        """Parse a JSON response payload and extract events.

        Args:
            text: Raw HTTP response body expected to contain JSON.

        Returns:
            List of parsed Event instances.

        Raises:
            EventsError: If JSON is invalid or response format is wrong.
        """
        try:
            data = _parse_json_object(text)
        except EventsError as exc:
            # Only log the snippet for JSON decode failures; other EventsError
            # subtypes have already captured relevant context at the raise site.
            if isinstance(exc.__cause__, json.JSONDecodeError):
                snippet = truncate_text(text, limit=TRUNCATE_LENGTH)
                _logger.exception("Failed to parse JSON: %s", snippet)
            raise

        # Extract events and nextUrl
        self._next_url = self._validate_next_url(
            data.get("nextUrl"),
            response_text=text,
        )
        if "events" in data:
            raw_events_obj: object = data["events"]
            if not _is_object_list(raw_events_obj):
                msg = (
                    "Invalid API response format: 'events' must be a list. "
                    "Each item must be an object."
                )
                raise EventsError(
                    msg,
                    response_text=text,
                )
            raw_events_list = raw_events_obj
        else:
            raw_events_list = []

        events = _parse_events(
            raw_events_list,
            strict=self.config.strict_validation,
        )

        if events:
            _logger.debug(
                "Received %d events for user %s",
                len(events),
                self.username,
            )

        return events

    async def _poll(self) -> list[Event]:
        """Fetch one batch of events from the API.

        Makes one request and updates _next_url for the next poll.

        Returns:
            List of events received, or an empty list on timeout.

        Raises:
            EventsError: If shutdown has started or if close() cancels this poll.
            asyncio.CancelledError: If the polling task is cancelled externally.

        Note:
            The polling lock is held for the entire duration of the request. This is intentional to
            prevent concurrent polls from racing on _next_url, but means a stalled request will
            block other callers until it finishes or is cancelled.
        """
        if self._state is not _ClientState.OPEN:
            raise EventsError(_CLIENT_CLOSING_MESSAGE)

        current_task = asyncio.current_task()
        if current_task is None:
            msg = "Unable to resolve current asyncio task."
            raise EventsError(msg)

        async with self._polling_lock:
            if self._state is not _ClientState.OPEN:
                raise EventsError(_CLIENT_CLOSING_MESSAGE)

            self._active_poll_task = current_task
            url = self._build_url()
            _logger.debug("Polling %s", _mask_url(url, self._token))

            try:
                status, text = await self._request(url)
                return self._process_response(status, text)
            except asyncio.CancelledError:
                if self._state is _ClientState.CLOSING:  # pyright: ignore[reportUnnecessaryComparison]  # pylint: disable=line-too-long
                    raise EventsError(_POLL_CANCELLED_ON_CLOSE_MESSAGE) from None
                raise
            finally:
                if self._active_poll_task is current_task:
                    self._active_poll_task = None

    async def __aiter__(self) -> AsyncGenerator[Event]:
        """Yield events continuously from the API.

        Runs until cancelled or a terminal error occurs. Transient failures
        are retried according to config.retry_attempts.

        Yields:
            Event instances as they are received from the API.

        Raises:
            AuthError: If authentication fails (e.g. invalid token).
            EventsError: If a non-retryable error occurs or retries are exhausted.

        Poll position is tracked with nextUrl between iterations.
        """  # noqa: DOC502
        while True:
            events = await self._poll()
            for event in events:
                yield event

    async def close(self) -> None:
        """Close the HTTP session and reset poll state.

        Safe to call multiple times. Called automatically by context exit.
        After close(), the instance cannot be reopened.
        """
        if self._state is _ClientState.CLOSED:
            return

        self._state = _ClientState.CLOSING
        try:  # noqa: PLW0717
            # Cancel any in-flight poll task first so lock handoff is fast on shutdown.
            poll_task = self._active_poll_task
            current_task = asyncio.current_task()
            if poll_task is not None and poll_task is not current_task and not poll_task.done():
                _ = poll_task.cancel()
                with suppress(asyncio.CancelledError, EventsError):
                    await poll_task

            # If outside the lock, await session.close() so it is not held on I/O.
            async with self._polling_lock:
                session: ClientSession | None = self.session
                self.session = None
                self._next_url = None
                self._active_poll_task = None
            if session is not None:
                try:
                    # asyncio.shield ensures session.close() runs to completion even
                    # if close() itself is cancelled from an outer task, preventing
                    # the underlying TCP connection from being abandoned mid-teardown.
                    await asyncio.shield(session.close())
                except (ClientError, OSError, RuntimeError) as e:
                    _logger.warning("Error closing session: %s", e, exc_info=True)
        finally:
            self._state = _ClientState.CLOSED
