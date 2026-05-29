"""HTTP client for the Chaturbate Events API.

This module provides the EventClient class for polling events from the
Chaturbate Events API with automatic retries, rate limiting, and credential
handling.
"""

from __future__ import annotations

import asyncio
import json
import logging
from contextlib import suppress
from http import HTTPStatus
from typing import TYPE_CHECKING, Final, NoReturn, TypeGuard
from urllib.parse import quote, unquote, urljoin, urlparse

import stamina
from aiohttp import ClientSession, ClientTimeout
from aiohttp.client_exceptions import ClientError
from aiolimiter import AsyncLimiter
from pydantic import ValidationError
from typing_extensions import Self, override

from .config import ClientConfig
from .exceptions import (
    AUTH_ERROR_STATUS_CODES,
    CF_SERVER_ERROR_CODES,
    TRUNCATE_LENGTH,
    AuthError,
    EventsError,
    build_http_error,
    truncate_text,
)
from .models import Event

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Sequence
    from types import TracebackType
    from urllib.parse import ParseResult

logger = logging.getLogger(__name__)
"""Logger for the cb_events.client module."""

BASE_URL: Final[str] = "https://eventsapi.chaturbate.com/events"
"""Production Events API endpoint base."""

TESTBED_URL: Final[str] = "https://events.testbed.cb.dev/events"
"""Testbed Events API endpoint base."""

DEFAULT_MAX_RATE: Final[int] = 2000
"""Default maximum number of requests per limiter window."""

DEFAULT_TIME_PERIOD: Final[int] = 60
"""Length in seconds of the limiter window used for rate limiting."""

SESSION_TIMEOUT_BUFFER: Final[int] = 5
"""Extra seconds added to aiohttp's client timeout."""

TOKEN_VISIBLE_CHARS: Final[int] = 0
"""Number of trailing token characters to reveal in logs (0 = fully masked)."""

RETRY_STATUS_CODES: Final[frozenset[int]] = frozenset({
    HTTPStatus.INTERNAL_SERVER_ERROR.value,
    HTTPStatus.BAD_GATEWAY.value,
    HTTPStatus.SERVICE_UNAVAILABLE.value,
    HTTPStatus.GATEWAY_TIMEOUT.value,
    HTTPStatus.TOO_MANY_REQUESTS.value,
    *CF_SERVER_ERROR_CODES,
})
"""HTTP status codes that trigger exponential backoff retries."""

TIMEOUT_STATUS_MESSAGE: Final[str] = "waited too long"
"""Status message indicating API polling timeout."""

CLIENT_CLOSING_MESSAGE: Final[str] = "Client is closing or closed."
"""Error message raised when polling is attempted during shutdown."""

CLIENT_CLOSED_ENTER_MESSAGE: Final[str] = (
    "Client is closed and cannot be reopened. Create a new EventClient instance."
)
"""Error message raised when entering a client after it has been closed."""

POLL_CANCELLED_ON_CLOSE_MESSAGE: Final[str] = "Polling cancelled because client is closing."
"""Error message raised when close() cancels an in-flight poll()."""

SUPPORTED_EVENTS_HOSTS: Final[dict[str, str]] = {
    "eventsapi.chaturbate.com": BASE_URL,
    "events.testbed.cb.dev": TESTBED_URL,
}
"""Allowed Events API hosts mapped to canonical base URLs."""


class _RetryableStatusError(Exception):
    """Internal data-carrier exception for retryable HTTP status failures.

    The retry loop retries this type via ``stamina.retry_context(on=...)``.
    It exists to carry ``status_code`` and ``response_text`` so
    ``_raise_request_failure`` can preserve HTTP details in the final error.
    """

    __slots__: tuple[str, ...] = ("response_text", "status_code")
    status_code: int
    response_text: str

    def __init__(self, msg: str, *, status_code: int, response_text: str) -> None:
        """Initialize exception with message and HTTP metadata.

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
        ParsedResult from urlparse with validated scheme, host, and path format.

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
    base_url = SUPPORTED_EVENTS_HOSTS.get((hostname or "").lower())
    if base_url is not None:
        return base_url
    msg = "Events URL host is not supported. Use eventsapi.chaturbate.com or events.testbed.cb.dev."
    raise AuthError(msg)


def _extract_username_token(path: str) -> tuple[str, str]:
    """Extract and URL-decode username/token from an Events path.

    Args:
        path: Path component of the Events URL.

    Returns:
        Tuple of ``(username, token)``.

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
    if value and value == value.strip():
        return
    msg = f"{field} must not be empty or contain leading/trailing whitespace. {hint}"
    raise AuthError(msg)


def _parse_events_url(events_url: str) -> tuple[str, str, str]:
    """Parse and validate the Events API URL.

    Args:
        events_url: Full upstream URL containing host, username, and token.

    Returns:
        Tuple of ``(base_url, username, token)``.
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


def _mask_token(token: str, visible: int = TOKEN_VISIBLE_CHARS) -> str:
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
    """Return True when value is a JSON object represented as a dict.

    Args:
        value: Value to validate.

    Returns:
        True when value is a JSON object represented as ``dict[str, object]``.
    """
    return isinstance(value, dict)


def _is_object_list(value: object) -> TypeGuard[list[object]]:
    """Return True when value is a JSON array represented as a Python list.

    Args:
        value: Value to validate.

    Returns:
        True when value is a list of JSON-compatible Python objects.
    """
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
    logger.warning(
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
    """Async client for polling the Chaturbate Events API.

    Streams events with automatic retries, rate limiting, and credential
    handling. Use as an async context manager and async iterator.

    This client implements long-polling with stateful URL tracking, where the
    API returns a nextUrl to continue from the last position.

    Attributes:
        username: Chaturbate username parsed from the Events URL.
        token: API token parsed from the Events URL.
        config: Client configuration instance.
        base_url: API endpoint base URL.
        session: Active HTTP session (None until context entry).

    Example:
        Basic polling loop::

            try:
                async with EventClient("https://...") as client:
                    async for event in client:
                        print(f"Received {event.type}: {event.id}")
            except AuthError:
                print("Invalid credentials")
            except EventsError as e:
                print(f"Stream failed: {e}")

        Shared rate limiting across multiple clients::

            from aiolimiter import AsyncLimiter

            limiter = AsyncLimiter(max_rate=2000, time_period=60)
            async with (
                EventClient(
                    "https://eventsapi.chaturbate.com/events/user1/token1/",
                    rate_limiter=limiter,
                ) as c1,
                EventClient(
                    "https://eventsapi.chaturbate.com/events/user2/token2/",
                    rate_limiter=limiter,
                ) as c2,
            ):
                # Both clients share the same rate limit pool
                pass

    Note:
        Not thread-safe. Must be used as an async context manager.
    """

    __slots__: tuple[str, ...] = (
        "_active_poll_task",
        "_base_hostname",
        "_base_origin",
        "_base_scheme",
        "_closed_event",
        "_closing_event",
        "_next_url",
        "_polling_lock",
        "_rate_limiter",
        "base_url",
        "config",
        "session",
        "token",
        "username",
    )

    def __init__(
        self,
        events_url: str,
        *,
        config: ClientConfig | None = None,
        rate_limiter: AsyncLimiter | None = None,
    ) -> None:
        """Initialize event client with credentials and configuration.

        Args:
            events_url: Full Events API URL provided by upstream, for
                example ``https://eventsapi.chaturbate.com/events/<username>/<token>/``.
            config: Optional client configuration overrides.
            rate_limiter: Optional shared rate limiter to coordinate calls
                across multiple clients.
        """
        self.base_url, self.username, self.token = _parse_events_url(events_url)
        self.config: ClientConfig = config or ClientConfig()
        parsed_base = urlparse(self.base_url)
        self._base_scheme: str = parsed_base.scheme
        if parsed_base.scheme and parsed_base.netloc:
            self._base_origin: str = f"{parsed_base.scheme}://{parsed_base.netloc}"
        else:
            self._base_origin = self.base_url
        self._base_hostname: str | None = parsed_base.hostname
        self.session: ClientSession | None = None
        self._active_poll_task: asyncio.Task[object] | None = None
        self._closing_event: asyncio.Event = asyncio.Event()
        self._closed_event: asyncio.Event = asyncio.Event()
        self._next_url: str | None = None
        self._polling_lock: asyncio.Lock = asyncio.Lock()
        self._rate_limiter: AsyncLimiter = rate_limiter or AsyncLimiter(
            max_rate=DEFAULT_MAX_RATE,
            time_period=DEFAULT_TIME_PERIOD,
        )

    @override
    def __repr__(self) -> str:
        """Return string representation with masked token.

        Returns:
            Masked representation revealing only limited token characters.
        """
        return f"EventClient(username='{self.username}', token='{_mask_token(self.token)}')"

    async def __aenter__(self) -> Self:
        """Initialize HTTP session on context entry.

        Returns:
            Self: Client instance ready for use.

        Raises:
            EventsError: If session creation fails.
        """
        if self._closed_event.is_set():
            raise EventsError(CLIENT_CLOSED_ENTER_MESSAGE)
        if self.session is not None:
            msg = "Client is already open. Use a new instance or exit the current context first."
            raise EventsError(msg)
        try:
            self.session = ClientSession(
                timeout=ClientTimeout(total=self.config.timeout + SESSION_TIMEOUT_BUFFER),
            )
        except (ClientError, OSError, RuntimeError, TimeoutError) as e:
            await self.close()
            msg = "Failed to create HTTP session."
            raise EventsError(msg) from e
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Clean up session on context exit.

        Args:
            exc_type: Exception type raised inside the context, if any.
            exc_val: Exception instance raised inside the context, if any.
            exc_tb: Traceback object for the exception, if any.
        """
        await self.close()

    def _build_url(self) -> str:
        """Build URL for next poll request.

        Returns:
            Fully qualified URL for the upcoming API request.

        Note:
            Timeout is only set as a query parameter on the initial URL; subsequent URLs from the
            API use the nextUrl and are expected to already include any necessary parameters.
        """
        if self._next_url:
            return self._next_url
        return (
            f"{self.base_url}/{quote(self.username, safe='')}/"
            f"{quote(self.token, safe='')}/?timeout={self.config.timeout}"
        )

    async def _perform_request_attempt(self, url: str) -> tuple[int, str]:
        """Perform one HTTP attempt and surface retryable status failures.

        Args:
            url: Fully qualified endpoint to request.

        Returns:
            Tuple of (status_code, response_text).

        Raises:
            EventsError: If the client session is unexpectedly unavailable.
            _RetryableStatusError: If the response status should trigger a retry.
        """
        if self.session is None:
            msg = "Client session unexpectedly unavailable"
            raise EventsError(msg)

        await self._rate_limiter.acquire()
        async with self.session.get(url, allow_redirects=False) as response:
            status = response.status
            text = await response.text()

        if status in RETRY_STATUS_CODES:
            msg = f"HTTP {status}"
            raise _RetryableStatusError(msg, status_code=status, response_text=text)

        return status, text

    def _raise_request_failure(
        self,
        *,
        attempts_made: int,
        original_exception: Exception,
    ) -> NoReturn:
        """Raise request failure with contextual details.

        Args:
            attempts_made: Number of attempts that were made before failure.
            original_exception: The last exception raised during the request.

        Raises:
            EventsError: With details about the failure, including HTTP metadata
                if available.
        """  # noqa: DOC501
        logger.error(
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
        """Make HTTP request with retries.

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
                        logger.warning(
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
        """Process HTTP response and extract events.

        Args:
            status: HTTP status code received from the API.
            text: Raw response body.

        Returns:
            List of parsed Event instances.

        Raises:
            AuthError: For HTTP 401/403 responses.
            EventsError: For other non-200 responses or invalid nextUrl in timeout responses.
        """  # noqa: DOC501, DOC502
        if status in AUTH_ERROR_STATUS_CODES:
            logger.warning(
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
            logger.error(
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
        """Resolve a potentially-relative nextUrl to an absolute URL.

        Args:
            stripped: Stripped nextUrl string from the API response.

        Returns:
            Tuple of (absolute URL string, parsed ParseResult).
        """
        parsed = urlparse(stripped)
        if not parsed.scheme and not parsed.netloc:
            if stripped.startswith("/"):
                base_for_join = f"{self._base_origin.rstrip('/')}/"
            else:
                base_for_join = f"{self.base_url.rstrip('/')}/"
            absolute = urljoin(base_for_join, stripped)
            return absolute, urlparse(absolute)
        if not parsed.scheme and (parsed.netloc or stripped.startswith("//")):
            scheme = self._base_scheme
            absolute = f"{scheme}:{stripped}"
            return absolute, urlparse(absolute)
        return stripped, parsed

    @staticmethod
    def _reject_next_url(
        log_msg: str,
        *args: object,
        username: str,
        exc_msg: str,
        response_text: str,
    ) -> NoReturn:
        """Log nextUrl validation error and raise a standardized EventsError.

        Args:
            log_msg: Log message format string with placeholders for args.
            *args: Arguments to format into the log message.
            username: Username to include explicitly in log output.
            exc_msg: Error message for the raised EventsError.
            response_text: Original response body for error diagnostics.

        Raises:
            EventsError: Always raised with the provided exc_msg and response_text.
        """
        logger.error(log_msg, *args, username)
        raise EventsError(exc_msg, response_text=response_text)

    def _validate_next_url(
        self,
        next_url: object,
        *,
        response_text: str,
    ) -> str | None:
        """Validate the nextUrl value from API responses.

        Args:
            next_url: Raw nextUrl value extracted from the API response.
            response_text: Original response body for error diagnostics.

        Returns:
            Sanitized nextUrl string or None when no follow-up poll is
            required. Relative URLs are resolved against the current base API
            endpoint.

        Raises:
            EventsError: If nextUrl is present but not a non-empty string, has
            an unsupported scheme, or references a hostname other than the
            base API host.
        """  # noqa: DOC502 # Static analysis may not recognize raised EventsError
        if next_url is None:
            return None

        invalid_next_url_msg = "Invalid API response: 'nextUrl' must be a non-empty string."

        if not isinstance(next_url, str):
            self._reject_next_url(
                "Received invalid nextUrl type %s for user %s",
                type(next_url).__name__,
                username=self.username,
                exc_msg=invalid_next_url_msg,
                response_text=response_text,
            )

        stripped = next_url.strip()
        if not stripped:
            self._reject_next_url(
                "Received empty nextUrl from API for user %s",
                username=self.username,
                exc_msg=invalid_next_url_msg,
                response_text=response_text,
            )

        absolute, parsed = self._resolve_absolute_url(stripped)

        scheme = parsed.scheme
        if scheme != "https":
            self._reject_next_url(
                "Received nextUrl with unsupported scheme %s for user %s",
                scheme or "<missing>",
                username=self.username,
                exc_msg="Invalid nextUrl scheme; only https is allowed.",
                response_text=response_text,
            )

        hostname = parsed.hostname
        allowed_host = self._base_hostname
        if not hostname:
            self._reject_next_url(
                "Received nextUrl without hostname for user %s",
                username=self.username,
                exc_msg="Invalid nextUrl host.",
                response_text=response_text,
            )

        if hostname.lower() != allowed_host:
            self._reject_next_url(
                "Received nextUrl host %s which is not allowed for user %s",
                hostname,
                username=self.username,
                exc_msg="Invalid nextUrl host.",
                response_text=response_text,
            )

        return absolute

    def _extract_next_url_from_timeout(self, text: str) -> str | None:
        """Try to extract nextUrl from timeout responses.

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
        if not (isinstance(status_msg, str) and TIMEOUT_STATUS_MESSAGE in status_msg.lower()):
            return None

        next_url = data.get("nextUrl")
        if next_url is None:
            return None

        validated = self._validate_next_url(next_url, response_text=text)
        if validated is None:
            return None
        logger.debug(
            "Received nextUrl from timeout response: %s",
            _mask_url(validated, self.token),
        )
        return validated

    def _parse_json_response(self, text: str) -> list[Event]:
        """Parse JSON response and extract events.

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
            if isinstance(exc.__cause__, json.JSONDecodeError):
                snippet = truncate_text(text, limit=TRUNCATE_LENGTH)
                logger.exception("Failed to parse JSON: %s", snippet)
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
            logger.debug(
                "Received %d events for user %s",
                len(events),
                self.username,
            )

        return events

    async def poll(self) -> list[Event]:
        """Poll the API for new events.

        Makes a single request to the Events API and returns any available
        events. Updates _next_url from each response for subsequent polls.

        Returns:
            List of events received, or an empty list on timeout.

        Raises:
            EventsError: If shutdown has started or if close() cancels this poll.
            asyncio.CancelledError: If the polling task is cancelled externally.

        Note:
            Holds ``_polling_lock`` for the full request so ``_next_url`` progression remains
            serialized and ``session`` is not detached mid-poll. ``close`` may cancel an active
            poll task, then waits for lock handoff to complete state reset.
        """
        if self._closing_event.is_set() or self._closed_event.is_set():
            raise EventsError(CLIENT_CLOSING_MESSAGE)

        current_task = asyncio.current_task()
        if current_task is None:
            msg = "Unable to resolve current asyncio task."
            raise EventsError(msg)

        async with self._polling_lock:
            if self._closing_event.is_set() or self._closed_event.is_set():
                raise EventsError(CLIENT_CLOSING_MESSAGE)

            self._active_poll_task = current_task
            url = self._build_url()
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("Polling %s", _mask_url(url, self.token))

            try:
                status, text = await self._request(url)
                return self._process_response(status, text)
            except asyncio.CancelledError:
                if self._closing_event.is_set():
                    raise EventsError(POLL_CANCELLED_ON_CLOSE_MESSAGE) from None
                raise
            finally:
                if self._active_poll_task is current_task:
                    self._active_poll_task = None

    async def __aiter__(self) -> AsyncGenerator[Event]:
        """Generate events continuously from the API.

        Runs indefinitely until cancelled or a terminal error occurs. Transient
        failures (network errors, 5xx responses) are retried automatically per
        ``config.retry_attempts`` before surfacing.

        Yields:
            Event instances as they are received from the API.

        Raises:
            AuthError: If authentication fails (e.g. invalid token).
            EventsError: If a non-retryable error occurs or retries are exhausted.

        Note:
            The loop is naturally throttled: the server holds each long-poll connection open for
            ``config.timeout`` seconds before responding. Empty results are therefore infrequent
            under normal conditions. If the server begins returning empty responses immediately
            (e.g. during an outage), the rate limiter provides a backstop.
        """  # noqa: DOC502 # Static analysis may not recognize raised AuthError and EventsError
        while True:
            events = await self.poll()
            for event in events:
                yield event

    async def close(self) -> None:
        """Close the HTTP session and reset internal state.

        Releases network resources and clears the stored nextUrl. Safe to
        call multiple times. Called automatically when exiting the async
        context manager.

        Note:
            Close marks the client as terminal state. Re-entry is not supported;
            create a new client instance after close().
        """
        if self._closed_event.is_set():
            return

        self._closing_event.set()

        # Cancel any in-flight poll task first so lock handoff is fast on shutdown.
        poll_task = self._active_poll_task
        current_task = asyncio.current_task()
        if poll_task is not None and poll_task is not current_task and not poll_task.done():
            poll_task.cancel()
            with suppress(asyncio.CancelledError, EventsError):
                await poll_task

        # Two-phase close:
        # - Under lock: detach session and reset poll state.
        # - Outside lock: await session.close() so lock is not held on I/O.
        async with self._polling_lock:
            session: ClientSession | None = self.session
            self.session = None
            self._next_url = None
            self._active_poll_task = None
        if session is not None:
            try:
                await asyncio.shield(session.close())
            except (ClientError, OSError, RuntimeError) as e:
                logger.warning("Error closing session: %s", e, exc_info=True)

        self._closed_event.set()
