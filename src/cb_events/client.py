"""HTTP client for the Chaturbate Events API.

This module provides the EventClient class for polling events from the
Chaturbate Events API with automatic retries, rate limiting, and credential
handling.

Module Attributes:
    BASE_URL: Production Events API endpoint.
    TESTBED_URL: Testbed Events API endpoint for development.
    DEFAULT_MAX_RATE: Default requests per rate limiter window.
    DEFAULT_TIME_PERIOD: Default rate limiter window in seconds.
    RETRY_STATUS_CODES: HTTP status codes that trigger retry logic.
    AUTH_ERRORS: HTTP status codes indicating authentication failure.
"""

import asyncio
import json
import logging
import random
from collections.abc import AsyncGenerator, AsyncIterator, Mapping, Sequence
from http import HTTPStatus
from types import TracebackType
from typing import Final, Self, cast, override
from urllib.parse import ParseResult, quote, urljoin, urlparse

from aiohttp import ClientSession, ClientTimeout
from aiohttp.client_exceptions import ClientError
from aiolimiter import AsyncLimiter
from pydantic import ValidationError

from .config import ClientConfig
from .exceptions import AuthError, EventsError
from .models import Event

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

TOKEN_VISIBLE_CHARS: Final[int] = 4
"""Number of trailing token characters to reveal in logs."""

TRUNCATE_LENGTH: Final[int] = 200
"""Maximum number of characters of response text shown in logs."""

AUTH_ERRORS: set[HTTPStatus] = {HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN}
"""HTTP status codes treated as authentication failures."""

CF_ORIGIN_DOWN: Final[int] = 521
CF_CONNECTION_TIMEOUT: Final[int] = 522
CF_ORIGIN_UNREACHABLE: Final[int] = 523
CF_TIMEOUT_OCCURRED: Final[int] = 524

RETRY_STATUS_CODES: set[int] = {
    HTTPStatus.INTERNAL_SERVER_ERROR.value,
    HTTPStatus.BAD_GATEWAY.value,
    HTTPStatus.SERVICE_UNAVAILABLE.value,
    HTTPStatus.GATEWAY_TIMEOUT.value,
    HTTPStatus.TOO_MANY_REQUESTS.value,
    CF_ORIGIN_DOWN,  # Cloudflare: origin down
    CF_CONNECTION_TIMEOUT,  # Cloudflare: connection timeout
    CF_ORIGIN_UNREACHABLE,  # Cloudflare: origin unreachable
    CF_TIMEOUT_OCCURRED,  # Cloudflare: timeout occurred
}
"""HTTP status codes that trigger exponential backoff retries."""

TIMEOUT_STATUS_MESSAGE: Final[str] = "waited too long"
"""Status message indicating API polling timeout."""

logger: logging.Logger = logging.getLogger(__name__)
"""Logger for the cb_events.client module."""


def _compose_message(*parts: str) -> str:
    """Join message components with single spaces.

    Args:
        parts: Message fragments to join in order.

    Returns:
        Concatenated message containing the provided parts.
    """
    return " ".join(part.strip() for part in parts if part)


def _mask_token(token: str, visible: int = TOKEN_VISIBLE_CHARS) -> str:
    """Mask token for logging.

    Args:
        token: Sensitive token string to sanitize.
        visible: Number of trailing characters to keep unobscured.

    Returns:
        Masked token with only the configured number of trailing characters
        visible.
    """
    if visible <= 0 or len(token) <= visible:
        return "*" * len(token)
    return f"{'*' * (len(token) - visible)}{token[-visible:]}"


def _mask_url(url: str, token: str) -> str:
    """Mask token in URL for safe logging.

    Args:
        url: URL string that may contain the sensitive token.
        token: Token substring to redact within the URL.

    Returns:
        URL with masked token occurrences replaced by the sanitized version.
    """
    masked: str = _mask_token(token)
    return url.replace(token, masked).replace(quote(token, safe=""), masked)


def _response_snippet(text: str, *, limit: int = TRUNCATE_LENGTH) -> str:
    """Return a truncated response preview for logging."""
    if len(text) <= limit:
        return text
    return f"{text[:limit]}..."


def _normalize_host_entry(candidate: object) -> str | None:
    """Best-effort sanitize of host entries for allow lists.

    Returns:
        Sanitized hostname in lowercase, or None if invalid.
    """
    if candidate is None:
        return None
    host_text: str = str(candidate).strip()
    if not host_text:
        return None

    parsed: ParseResult = urlparse(host_text)
    if parsed.hostname:
        return parsed.hostname.lower()

    trimmed: str = host_text.split("/", 1)[0]
    trimmed = trimmed.split("@", 1)[-1]
    trimmed = trimmed.split(":", 1)[0]
    trimmed = trimmed.strip()
    return trimmed.lower() or None


def _build_allowed_hosts(
    base_url: str, extra_hosts: Sequence[str] | None
) -> set[str]:
    """Compile list of permitted nextUrl hostnames.

    Returns:
        Set of normalized hostnames allowed for nextUrl values.
    """
    hosts: set[str] = set()
    parsed_base: ParseResult = urlparse(base_url)
    if parsed_base.hostname:
        hosts.add(parsed_base.hostname.lower())
    else:
        normalized_base: str | None = _normalize_host_entry(base_url)
        if normalized_base:
            hosts.add(normalized_base)

    if extra_hosts:
        for host in extra_hosts:
            normalized: str | None = _normalize_host_entry(host)
            if normalized:
                hosts.add(normalized)

    return hosts


def _log_validation_error(
    item: object,
    exc: ValidationError,
) -> None:
    """Log validation error details for an invalid event.

    Args:
        item: Raw event data that failed validation.
        exc: Validation error containing field-level details.
    """
    mapping_item: Mapping[str, object] | None = None
    if isinstance(item, Mapping):
        mapping_item = cast("Mapping[str, object]", item)

    event_id: object = (
        mapping_item.get("id", "<unknown>")
        if mapping_item is not None
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

    Raises:
        ValidationError: If strict is True and validation fails.
    """
    events: list[Event] = []
    for item in raw:
        try:
            events.append(Event.model_validate(item))
        except ValidationError as exc:
            if strict:
                raise
            _log_validation_error(item, exc)
    return events


class _BackoffSchedule:
    """Track exponential backoff without compounding jitter."""

    __slots__: tuple[str, ...] = (
        "_current",
        "_factor",
        "_first_call",
        "_max_delay",
    )

    def __init__(
        self, initial: float, *, factor: float, max_delay: float
    ) -> None:
        self._current: float = max(0.0, initial)
        self._factor: float = factor
        self._max_delay: float = max_delay
        self._first_call: bool = True

    def next_delay(self) -> float:
        """Return the next sleep duration applying jitter and clamping."""
        base_delay: float = min(self._current, self._max_delay)
        if self._first_call:
            sleep_for: float = base_delay
            self._first_call = False
        else:
            jitter_factor: float = random.uniform(0.8, 1.2)  # noqa: S311  # nosec
            sleep_for = base_delay * jitter_factor

        next_base: float = min(base_delay * self._factor, self._max_delay)
        self._current = next_base
        return min(sleep_for, self._max_delay)


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
        timeout: Request timeout in seconds.
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
        Always use as an async context manager to ensure proper session
        cleanup. The client is not thread-safe.
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
        "timeout",
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
        self.timeout: int = self.config.timeout
        self.base_url: str = (
            TESTBED_URL if self.config.use_testbed else BASE_URL
        )
        parsed_base: ParseResult = urlparse(self.base_url)
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
                        total=self.timeout + SESSION_TIMEOUT_BUFFER
                    ),
                )
        except (ClientError, OSError, TimeoutError) as e:
            await self.close()
            msg = (
                "Failed to create HTTP session. Check system resources, "
                "network configuration, and ensure aiohttp is properly "
                "installed."
            )
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
            f"{quote(self.token, safe='')}/?timeout={self.timeout}"
        )

    async def _request(self, url: str) -> tuple[int, str]:
        """Make HTTP request with retries.

        Args:
            url: Fully qualified endpoint to request.

        Returns:
            Tuple of (status_code, response_text).

        Raises:
            EventsError: If the request fails after the configured retries.
        """
        if self.session is None:
            init_msg = (
                "Client not initialized - use 'async with EventClient(...)' "
                "context manager to properly initialize the session"
            )
            raise EventsError(init_msg)

        max_attempts: int = self.config.retry_attempts
        retry_schedule = _BackoffSchedule(
            self.config.retry_backoff,
            factor=self.config.retry_factor,
            max_delay=self.config.retry_max_delay,
        )

        for attempt in range(1, max_attempts + 1):
            try:
                await self._rate_limiter.acquire()
                async with self.session.get(
                    url,
                    allow_redirects=False,
                ) as response:
                    status: int = response.status
                    text: str = await response.text()
            except (ClientError, TimeoutError, OSError) as exc:
                if attempt == max_attempts:
                    logger.exception(
                        "Request failed after %d attempts for user %s",
                        attempt,
                        self.username,
                    )
                    attempt_label: str = (
                        "attempt" if attempt == 1 else "attempts"
                    )
                    failure_msg: str = (
                        "Failed to fetch events after "
                        f"{attempt} {attempt_label}."
                    )
                    msg: str = _compose_message(
                        failure_msg,
                        "Check network connectivity and firewall settings.",
                        "Review API status at https://status.chaturbate.com.",
                    )
                    raise EventsError(msg) from exc

                logger.warning(
                    "Attempt %d/%d failed for user %s: %r",
                    attempt,
                    max_attempts,
                    self.username,
                    exc,
                )
                await self._sleep_with_backoff(
                    retry_schedule,
                    attempt=attempt,
                    max_attempts=max_attempts,
                    reason="transient error",
                )
                continue

            if status in RETRY_STATUS_CODES and attempt < max_attempts:
                await self._sleep_with_backoff(
                    retry_schedule,
                    attempt=attempt,
                    max_attempts=max_attempts,
                    reason=f"HTTP {status}",
                )
                continue

            return status, text

        # Should be unreachable
        msg = "Unexpected error in request loop"
        raise EventsError(msg)

    async def _sleep_with_backoff(
        self,
        backoff: _BackoffSchedule,
        *,
        attempt: int,
        max_attempts: int,
        reason: str,
    ) -> None:
        """Sleep according to the retry schedule and log the delay used."""
        delay: float = backoff.next_delay()
        logger.debug(
            "Retrying %s for %s (attempt %d/%d, delay %.1fs)",
            reason,
            self.username,
            attempt,
            max_attempts,
            delay,
        )
        await asyncio.sleep(delay)

    def _process_response(self, status: int, text: str) -> list[Event]:
        """Process HTTP response and extract events.

        Args:
            status: HTTP status code received from the API.
            text: Raw response body.

        Returns:
            List of parsed Event instances.

        Raises:
            AuthError: For HTTP 401/403 responses.
            EventsError: For other non-success responses.
        """
        if status in AUTH_ERRORS:
            logger.warning(
                "Authentication failed for user %s (HTTP %d)",
                self.username,
                status,
            )
            msg: str = _compose_message(
                f"Authentication failed for '{self.username}'.",
                "Verify your username and token are correct.",
                (
                    "Generate a new token at "
                    "https://chaturbate.com/statsapi/authtoken/."
                ),
            )
            raise AuthError(msg, status_code=status, response_text=text)

        if status == HTTPStatus.BAD_REQUEST and (
            next_url := self._extract_next_url_from_timeout(text)
        ):
            self._next_url = next_url
            return []

        if status != HTTPStatus.OK:
            snippet: str = _response_snippet(text)
            logger.error(
                "HTTP %d for user %s: %s",
                status,
                self.username,
                snippet,
            )

            if status == HTTPStatus.TOO_MANY_REQUESTS:
                guidance: str = " " + _compose_message(
                    "Rate limit exceeded.",
                    "Reduce request rate.",
                    "Share a limiter across clients.",
                )
            elif status >= HTTPStatus.INTERNAL_SERVER_ERROR:
                guidance = " " + _compose_message(
                    "Server error.",
                    "Check https://status.chaturbate.com for API status.",
                    "Retry later.",
                )
            else:
                guidance = ""

            msg = f"HTTP {status}: {snippet}{guidance}"
            raise EventsError(
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

        if not isinstance(next_url, str):
            logger.error(
                "Received invalid nextUrl type %s for user %s",
                type(next_url).__name__,
                self.username,
            )
            msg: str = _compose_message(
                "Invalid API response: 'nextUrl' must be a non-empty string.",
                "Check https://status.chaturbate.com for service status.",
            )
            raise EventsError(msg, response_text=response_text)

        stripped: str = next_url.strip()
        if not stripped:
            logger.error(
                "Received empty nextUrl from API for user %s",
                self.username,
            )
            msg = _compose_message(
                "Invalid API response: 'nextUrl' must be a non-empty string.",
                "Check https://status.chaturbate.com for service status.",
            )
            raise EventsError(msg, response_text=response_text)

        absolute: str = stripped
        parsed: ParseResult = urlparse(stripped)
        if not parsed.scheme and not parsed.netloc:
            if stripped.startswith("/"):
                base_for_join: str = f"{self._base_origin.rstrip('/')}/"
            else:
                base_for_join = f"{self.base_url.rstrip('/')}/"
            absolute = urljoin(base_for_join, stripped)
            parsed = urlparse(absolute)

        scheme: str | None = parsed.scheme
        if scheme not in {"http", "https"}:
            logger.error(
                "Received nextUrl with unsupported scheme %s for user %s",
                scheme or "<missing>",
                self.username,
            )
            msg_scheme: str = _compose_message(
                "Invalid nextUrl scheme; only http/https are allowed.",
                "Check https://status.chaturbate.com for service status.",
            )
            raise EventsError(msg_scheme, response_text=response_text)

        hostname: str | None = parsed.hostname
        if not hostname:
            logger.error(
                "Received nextUrl without hostname for user %s",
                self.username,
            )
            msg_host: str = _compose_message(
                "Invalid nextUrl host.",
                "Allow via ClientConfig.next_url_allowed_hosts.",
            )
            raise EventsError(msg_host, response_text=response_text)

        if hostname.lower() not in self._allowed_next_hosts:
            logger.error(
                "Received nextUrl host %s which is not allowed for user %s",
                hostname,
                self.username,
            )
            host_msg: str = _compose_message(
                "Invalid nextUrl host.",
                "Allow via ClientConfig.next_url_allowed_hosts.",
            )
            raise EventsError(host_msg, response_text=response_text)

        return absolute

    def _extract_next_url_from_timeout(self, text: str) -> str | None:
        """Try to extract nextUrl from timeout responses.

        Args:
            text: Raw response body from the timeout response.

        Returns:
            The extracted nextUrl if found and valid, otherwise None.
        """
        try:
            data_obj: object = json.loads(text)
        except (json.JSONDecodeError, KeyError):
            return None

        if not isinstance(data_obj, dict):
            return None

        status_msg: object | None = data_obj.get("status")
        is_timeout: bool = (
            isinstance(status_msg, str)
            and TIMEOUT_STATUS_MESSAGE in status_msg.lower()
        )
        if is_timeout:
            next_url: object | None = data_obj.get("nextUrl")
            if next_url is None:
                return None

            validated: str | None = self._validate_next_url(
                next_url,
                response_text=text,
            )
            if validated is None:
                return None

            logger.debug(
                "Received nextUrl from timeout response: %s",
                _mask_url(validated, self.token),
            )
            return validated
        return None

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
            data_obj: object = json.loads(text)
        except json.JSONDecodeError as exc:
            snippet: str = _response_snippet(text)
            logger.exception("Failed to parse JSON: %s", snippet)
            msg: str = _compose_message(
                f"Invalid JSON response from API: {exc.msg}.",
                "The response may indicate an API outage or unexpected format.",
                "Check https://status.chaturbate.com for service status.",
            )
            raise EventsError(
                msg,
                response_text=text,
            ) from exc

        if not isinstance(data_obj, dict):
            msg = _compose_message(
                "Invalid API response format: expected JSON object.",
                f"Got {type(data_obj).__name__} instead.",
                "Check https://status.chaturbate.com for service status.",
            )
            raise EventsError(
                msg,
                response_text=text,
            )

        # Extract events and nextUrl
        self._next_url = self._validate_next_url(
            data_obj.get("nextUrl"),
            response_text=text,
        )
        if "events" in data_obj:
            raw_events_obj: object = data_obj["events"]
            if not isinstance(raw_events_obj, list):
                msg = _compose_message(
                    "Invalid API response format: 'events' must be a list.",
                    "Each item must be an object.",
                )
                raise EventsError(
                    msg,
                    response_text=text,
                )
            raw_events_list = raw_events_obj
        else:
            raw_events_list = []

        events: list[Event] = _parse_events(
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
        events. The client automatically tracks the nextUrl for subsequent
        calls to maintain position in the event stream.

        Returns:
            List of events received. Returns an empty list if no events are
            available or the request timed out.

        Note:
            May raise EventsError if the client is not initialized or
            the request fails, or AuthError if authentication fails.
        """
        async with self._polling_lock:
            url: str = self._build_url()
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("Polling %s", _mask_url(url, self.token))

            status, text = await self._request(url)
            return self._process_response(status, text)

    def __aiter__(self) -> AsyncIterator[Event]:
        """Return an async iterator for continuous event streaming.

        Enables use in async for loops for continuous polling.

        Returns:
            Async iterator that yields Event instances indefinitely.

        Example:
            Continuous event streaming::

                async with EventClient("user", "token") as client:
                    async for event in client:
                        print(f"Event: {event.type}")
        """
        return self._stream()

    async def _stream(self) -> AsyncGenerator[Event]:
        """Generate events continuously from the API.

        Internal generator that polls indefinitely and yields events as they
        arrive. Used by __aiter__() to implement async iteration.

        Yields:
            Event instances as they are received from the API.
        """
        while True:
            events: list[Event] = await self.poll()
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
        if session is not None:
            try:
                await session.close()
            except (ClientError, OSError, RuntimeError) as e:
                logger.warning("Error closing session: %s", e, exc_info=True)
