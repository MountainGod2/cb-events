"""HTTP client for the Chaturbate Events API.

This module provides the EventClient class for polling events from the
Chaturbate Events API with automatic retries, rate limiting, and credential
handling.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Mapping
from http import HTTPStatus
from typing import TYPE_CHECKING, Final, NoReturn, cast
from urllib.parse import quote, urljoin, urlparse

import stamina
from aiohttp import ClientSession, ClientTimeout
from aiohttp.client_exceptions import ClientError
from aiolimiter import AsyncLimiter
from pydantic import ValidationError
from typing_extensions import Self, override

from .config import ClientConfig
from .exceptions import (
    _TRUNCATE_LENGTH,  # pyright: ignore[reportPrivateUsage]
    AUTH_ERROR_STATUS_CODES,
    AuthError,
    EventsError,
    build_http_error,
)
from .models import Event

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, AsyncIterator, Sequence
    from types import TracebackType

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

CF_ORIGIN_DOWN: Final[int] = 521
"""Cloudflare status code indicating the origin server is down."""

CF_CONNECTION_TIMEOUT: Final[int] = 522
"""Cloudflare status code indicating a connection timeout to the origin."""

CF_ORIGIN_UNREACHABLE: Final[int] = 523
"""Cloudflare status code indicating the origin is unreachable."""

CF_TIMEOUT_OCCURRED: Final[int] = 524
"""Cloudflare status code indicating a timeout occurred."""

RETRY_STATUS_CODES: Final[frozenset[int]] = frozenset({
    HTTPStatus.INTERNAL_SERVER_ERROR.value,
    HTTPStatus.BAD_GATEWAY.value,
    HTTPStatus.SERVICE_UNAVAILABLE.value,
    HTTPStatus.GATEWAY_TIMEOUT.value,
    HTTPStatus.TOO_MANY_REQUESTS.value,
    CF_ORIGIN_DOWN,  # Cloudflare: origin down
    CF_CONNECTION_TIMEOUT,  # Cloudflare: connection timeout
    CF_ORIGIN_UNREACHABLE,  # Cloudflare: origin unreachable
    CF_TIMEOUT_OCCURRED,  # Cloudflare: timeout occurred
})
"""HTTP status codes that trigger exponential backoff retries."""

TIMEOUT_STATUS_MESSAGE: Final[str] = "waited too long"
"""Status message indicating API polling timeout."""

logger = logging.getLogger(__name__)
"""Logger for the cb_events.client module."""


class _TransientError(Exception):
    """Internal exception for triggering retries on bad status codes."""

    __slots__: tuple[str, ...] = ("response_text", "status_code")
    status_code: int
    response_text: str

    def __init__(
        self, msg: str, *, status_code: int, response_text: str
    ) -> None:
        """Initialize exception with message and HTTP metadata.

        Args:
            msg: Human-readable description of the transient failure.
            status_code: HTTP status code returned by the API.
            response_text: Raw response body returned by the API.
        """
        super().__init__(msg)
        self.status_code = status_code
        self.response_text = response_text


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


def _response_snippet(text: str, *, limit: int = _TRUNCATE_LENGTH) -> str:
    """Truncate response text for safe logging.

    Args:
        text: Raw response body to truncate.
        limit: Maximum number of characters to retain.

    Returns:
        Text truncated to ``limit`` characters with ellipsis if needed.
    """
    if len(text) <= limit:
        return text
    return f"{text[:limit]}..."


def _normalize_host_entry(candidate: str | None) -> str | None:
    """Normalise a host candidate to a lowercase hostname string.

    Args:
        candidate: URL, bare hostname, or None.

    Returns:
        Lowercase hostname string, or None if nothing usable can be extracted.
    """
    if candidate is None:
        return None
    host_text = candidate.strip()
    if not host_text:
        return None

    parsed = urlparse(host_text)
    if parsed.hostname:
        return parsed.hostname.lower()

    trimmed = host_text.split("/", 1)[0]
    trimmed = trimmed.split("@", 1)[-1]
    trimmed = trimmed.split(":", 1)[0]
    trimmed = trimmed.strip()
    return trimmed.lower() or None


def _build_allowed_hosts(
    base_url: str, extra_hosts: tuple[str, ...] | None
) -> set[str]:
    """Build the set of permitted hostnames for nextUrl redirection.

    Args:
        base_url: The client's base API endpoint URL.
        extra_hosts: Additional hosts to allow, as configured by the caller.

    Returns:
        Set of lowercase hostnames that are allowed in nextUrl responses.
    """
    hosts: set[str] = set()
    if host := _normalize_host_entry(base_url):
        hosts.add(host)
    if extra_hosts:
        for entry in extra_hosts:
            if host := _normalize_host_entry(entry):
                hosts.add(host)
    return hosts


def _log_validation_error(
    item: object,
    exc: ValidationError,
) -> None:
    """Log a warning for an event that failed Pydantic validation.

    Args:
        item: Raw object that failed validation.
        exc: The ValidationError raised during parsing.
    """
    event_id = (
        cast("Mapping[str, object]", item).get("id", "<unknown>")
        if isinstance(item, Mapping)
        else "<unknown>"
    )
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
    return [
        event
        for item in raw
        if (event := _parse_event(item, strict=strict)) is not None
    ]


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
        username: Chaturbate username for the event feed.
        token: API token for authentication.
        config: Client configuration instance.
        base_url: API endpoint base URL.
        session: Active HTTP session (None until context entry).

    Example:
        Basic polling loop::

            async with EventClient("username", "token") as client:
                async for event in client:
                    print(f"Received {event.type}: {event.id}")

        Shared rate limiting across multiple clients::

            from aiolimiter import AsyncLimiter

            limiter = AsyncLimiter(max_rate=2000, time_period=60)
            async with (
                EventClient("user1", "token1", rate_limiter=limiter) as c1,
                EventClient("user2", "token2", rate_limiter=limiter) as c2,
            ):
                # Both clients share the same rate limit pool
                pass

    Note:
        Not thread-safe. Must be used as an async context manager.
    """

    __slots__: tuple[str, ...] = (
        "_allowed_next_hosts",
        "_base_origin",
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
        username: str,
        token: str,
        *,
        config: ClientConfig | None = None,
        rate_limiter: AsyncLimiter | None = None,
    ) -> None:
        """Initialize event client with credentials and configuration.

        Args:
            username: Chaturbate username associated with the event feed.
            token: API token generated for the username.
            config: Optional client configuration overrides.
            rate_limiter: Optional shared rate limiter to coordinate calls
                across multiple clients.

        Raises:
            AuthError: If username or token is empty or contains whitespace.
        """
        if not username or username != username.strip():
            msg = (
                "Username must not be empty or contain leading/trailing "
                "whitespace. Provide a valid Chaturbate username."
            )
            raise AuthError(msg)
        if not token or token != token.strip():
            msg = (
                "Token must not be empty or contain leading/trailing "
                "whitespace. Generate a valid token at "
                "https://chaturbate.com/statsapi/authtoken/"
            )
            raise AuthError(msg)

        self.username: str = username
        self.token: str = token
        self.config: ClientConfig = config or ClientConfig()
        self.base_url: str = (
            TESTBED_URL if self.config.use_testbed else BASE_URL
        )
        parsed_base = urlparse(self.base_url)
        if parsed_base.scheme and parsed_base.netloc:
            self._base_origin: str = (
                f"{parsed_base.scheme}://{parsed_base.netloc}"
            )
        else:
            self._base_origin = self.base_url
        self.session: ClientSession | None = None
        self._next_url: str | None = None

        self._allowed_next_hosts: set[str] = _build_allowed_hosts(
            self.base_url,
            self.config.next_url_allowed_hosts,
        )
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
        return (
            f"EventClient(username='{self.username}', "
            f"token='{_mask_token(self.token)}')"
        )

    async def __aenter__(self) -> Self:
        """Initialize HTTP session on context entry.

        Returns:
            Self: Client instance ready for use.

        Raises:
            EventsError: If session creation fails.
        """
        try:
            if self.session is None:
                self.session = ClientSession(
                    timeout=ClientTimeout(
                        total=self.config.timeout + SESSION_TIMEOUT_BUFFER
                    ),
                )
        except (ClientError, OSError, TimeoutError) as e:
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
        """
        if self._next_url:
            return self._next_url
        return (
            f"{self.base_url}/{quote(self.username, safe='')}/"
            f"{quote(self.token, safe='')}/?timeout={self.config.timeout}"
        )

    def _next_sleep_for_attempt(self, attempt_num: int) -> float:
        """Compute capped exponential backoff delay for the given attempt.

        Args:
            attempt_num: 1-based attempt number for which to compute the delay.

        Returns:
            Delay in seconds before the next retry.
        """
        sleep_seconds = self.config.retry_backoff * (
            self.config.retry_factor ** (attempt_num - 1)
        )
        return min(sleep_seconds, self.config.retry_max_delay)

    async def _perform_request_attempt(self, url: str) -> tuple[int, str]:
        """Perform one HTTP attempt and surface retryable status failures.

        Args:
            url: Fully qualified endpoint to request.

        Returns:
            Tuple of (status_code, response_text).

        Raises:
            EventsError: If the client session is unexpectedly unavailable.
            _TransientError: If the response status should trigger a retry.
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
            raise _TransientError(msg, status_code=status, response_text=text)

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

        # Unwrap _TransientError if that was the cause to avoid noise.
        cause = (
            None
            if isinstance(original_exception, _TransientError)
            else original_exception
        )

        status_code: int | None = getattr(
            original_exception, "status_code", None
        )
        response_text: str | None = getattr(
            original_exception, "response_text", None
        )

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
            msg = (
                "Client not initialized. Use 'async with EventClient(...)'"
                " as a context manager."
            )
            raise EventsError(msg)

        attempts_made = 0
        last_delay: float = 0.0
        retriable_exc_types = (
            ClientError,
            TimeoutError,
            OSError,
            _TransientError,
        )

        def _should_retry(exc: Exception) -> bool | float:
            nonlocal last_delay
            if not isinstance(exc, retriable_exc_types):
                return False
            last_delay = self._next_sleep_for_attempt(attempts_made)
            return last_delay

        try:
            async for attempt in stamina.retry_context(
                on=_should_retry,
                attempts=self.config.retry_attempts,
            ):
                attempts_made = attempt.num
                try:
                    with attempt:
                        return await self._perform_request_attempt(url)
                except retriable_exc_types as exc:
                    if attempts_made < self.config.retry_attempts:
                        msg = (
                            "Attempt %d/%d failed for user %s: %r. "
                            "Retrying in %.2fs..."
                        )
                        logger.warning(
                            msg,
                            attempts_made,
                            self.config.retry_attempts,
                            self.username,
                            exc,
                            last_delay,
                        )
                    raise

        except retriable_exc_types as original_exception:
            self._raise_request_failure(
                attempts_made=attempts_made,
                original_exception=original_exception,
            )

        msg = "Unexpected error in request loop"
        raise EventsError(msg)

    def _process_response(self, status: int, text: str) -> list[Event]:
        """Process HTTP response and extract events.

        Args:
            status: HTTP status code received from the API.
            text: Raw response body.

        Returns:
            List of parsed Event instances.

        Raises:
            AuthError: For HTTP 401/403 responses.
            EventsError: For other non-200 responses or when response format is
                invalid. Includes HTTP metadata when available.
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
            snippet = _response_snippet(text)
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
            an unsupported scheme, or references a hostname not permitted by
            ClientConfig.next_url_allowed_hosts (the base API host is always
            permitted).
        """
        if next_url is None:
            return None

        invalid_next_url_msg = (
            "Invalid API response: 'nextUrl' must be a non-empty string."
        )

        if not isinstance(next_url, str):
            logger.error(
                "Received invalid nextUrl type %s for user %s",
                type(next_url).__name__,
                self.username,
            )
            raise EventsError(invalid_next_url_msg, response_text=response_text)

        stripped = next_url.strip()
        if not stripped:
            logger.error(
                "Received empty nextUrl from API for user %s",
                self.username,
            )
            raise EventsError(invalid_next_url_msg, response_text=response_text)

        absolute = stripped
        parsed = urlparse(stripped)
        if not parsed.scheme and not parsed.netloc:
            if stripped.startswith("/"):
                base_for_join = f"{self._base_origin.rstrip('/')}/"
            else:
                base_for_join = f"{self.base_url.rstrip('/')}/"
            absolute = urljoin(base_for_join, stripped)
            parsed = urlparse(absolute)

        scheme = parsed.scheme
        if scheme not in {"http", "https"}:
            logger.error(
                "Received nextUrl with unsupported scheme %s for user %s",
                scheme or "<missing>",
                self.username,
            )
            msg = "Invalid nextUrl scheme; only http/https are allowed."
            raise EventsError(msg, response_text=response_text)

        hostname = parsed.hostname
        if not hostname:
            logger.error(
                "Received nextUrl without hostname for user %s",
                self.username,
            )
            msg = (
                "Invalid nextUrl host. Allow via "
                "ClientConfig.next_url_allowed_hosts."
            )
            raise EventsError(msg, response_text=response_text)

        if hostname.lower() not in self._allowed_next_hosts:
            logger.error(
                "Received nextUrl host %s which is not allowed for user %s",
                hostname,
                self.username,
            )
            msg = (
                "Invalid nextUrl host. Allow via "
                "ClientConfig.next_url_allowed_hosts."
            )
            raise EventsError(msg, response_text=response_text)

        return absolute

    def _extract_next_url_from_timeout(self, text: str) -> str | None:
        """Try to extract nextUrl from timeout responses.

        Args:
            text: Raw response body from the timeout response.

        Returns:
            The extracted nextUrl if found and valid, otherwise None.
        """
        try:
            data_obj: object = json.loads(text)  # pyright: ignore[reportAny]
        except json.JSONDecodeError:
            return None

        if not isinstance(data_obj, dict):
            return None

        data = cast("dict[str, object]", data_obj)
        status_msg = data.get("status")
        if not (
            isinstance(status_msg, str)
            and TIMEOUT_STATUS_MESSAGE in status_msg.lower()
        ):
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
            data_obj: object = json.loads(text)  # pyright: ignore[reportAny]
        except json.JSONDecodeError as exc:
            snippet = _response_snippet(text)
            logger.exception("Failed to parse JSON: %s", snippet)
            msg = f"Invalid JSON response from API: {exc.msg}."
            raise EventsError(
                msg,
                response_text=text,
            ) from exc

        if not isinstance(data_obj, dict):
            msg = (
                "Invalid API response format: expected JSON object, "
                f"got {type(data_obj).__name__}."
            )
            raise EventsError(
                msg,
                response_text=text,
            )

        data = cast("dict[str, object]", data_obj)
        # Extract events and nextUrl
        self._next_url = self._validate_next_url(
            data.get("nextUrl"),
            response_text=text,
        )
        if "events" in data:
            raw_events_obj: object = data["events"]
            if not isinstance(raw_events_obj, list):
                msg = (
                    "Invalid API response format: 'events' must be a list. "
                    "Each item must be an object."
                )
                raise EventsError(
                    msg,
                    response_text=text,
                )
            raw_events_list: list[object] = cast("list[object]", raw_events_obj)
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
            EventsError: If the client is not initialized or the request fails.
            AuthError: If authentication fails (HTTP 401/403).
        """  # noqa: DOC502
        async with self._polling_lock:
            url = self._build_url()
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("Polling %s", _mask_url(url, self.token))

            status, text = await self._request(url)
            return self._process_response(status, text)

    def __aiter__(self) -> AsyncIterator[Event]:
        """Implement async iteration over events.

        Returns:
            Async iterator that yields Event instances indefinitely.
        """
        return self._stream()

    async def _stream(self) -> AsyncGenerator[Event]:
        """Generate events continuously from the API.

        Yields:
            Event instances as they are received from the API.
        """
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
            After calling close(), the client must be re-entered via
            async with before making further requests.
        """
        session: ClientSession | None = self.session
        self.session = None
        self._next_url = None
        if session is not None:
            try:
                await session.close()
            except (ClientError, OSError, RuntimeError) as e:
                logger.warning("Error closing session: %s", e, exc_info=True)
