"""Async HTTP client for polling the Chaturbate Events API."""

from __future__ import annotations

import asyncio
import logging
from contextlib import suppress
from enum import Enum, auto
from http import HTTPStatus
from typing import TYPE_CHECKING, Final
from urllib.parse import quote, unquote, urlparse

from aiohttp import ClientSession, ClientTimeout
from aiohttp.client_exceptions import ClientError
from aiolimiter import AsyncLimiter

from ._compat import override
from ._config import ClientConfig
from ._exceptions import CF_SERVER_ERROR_CODES, AuthError, EventsError
from ._parser import (
    ParserContext,
    process_response,
)
from ._request import perform_request_attempt, request_with_retry

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator
    from types import TracebackType
    from urllib.parse import ParseResult

    from ._compat import Self
    from ._models import Event


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
        self._parser_context: ParserContext = ParserContext(
            username=self.username,
            base_url=self.base_url,
            parsed_base_url=self._parsed_base_url,
            logger=_logger,
        )
        self._active_poll_tasks: set[asyncio.Task[object]] = set()
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
        async with self._polling_lock:
            if self._state in {_ClientState.CLOSED, _ClientState.CLOSING}:
                raise EventsError(_CLIENT_CLOSED_ENTER_MESSAGE)
            if self.session is not None:
                msg = "Client is already open. ..."
                raise EventsError(msg)
            try:
                self.session = ClientSession(
                    timeout=ClientTimeout(total=self.config.timeout + _SESSION_TIMEOUT_BUFFER),
                )
            except (ClientError, OSError, RuntimeError, TimeoutError) as exc:
                # Fall through to close() and re-raise outside the lock.
                creation_exc: Exception = exc
            else:
                return self

        await self.close()
        msg = "Failed to create HTTP session."
        raise EventsError(msg) from creation_exc

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

    def _build_url(
        self,
        next_url: str | None = None,
    ) -> str:
        """Build the URL for the next poll.

        Args:
            next_url: Optional nextUrl snapshot to use for this request.

        Note:
            The timeout query parameter is added only to the initial request URL.

        Returns:
            Fully qualified URL for the upcoming API request.
        """
        if next_url:
            return next_url
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
        """
        # Session may be set to None by close() between retry attempts.
        if self.session is None:
            msg = "Client session unexpectedly unavailable"
            raise EventsError(msg)

        return await perform_request_attempt(
            session=self.session,
            rate_limiter=self._rate_limiter,
            url=url,
            retry_status_codes=_RETRY_STATUS_CODES,
        )

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

        return await request_with_retry(
            url=url,
            config=self.config,
            username=self.username,
            perform_attempt=self._perform_request_attempt,
            logger=_logger,
        )

    async def _poll(self) -> list[Event]:
        """Fetch one batch of events from the API.

        Makes one request and updates _next_url for the next poll.

        Returns:
            List of events received, or an empty list on timeout.

        Raises:
            EventsError: If shutdown has started or if close() cancels this poll.
            asyncio.CancelledError: If the polling task is cancelled externally.

        Note:
            The polling lock is held only while reading or writing _next_url and
            tracking active poll tasks. HTTP I/O runs outside the lock.
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
            self._active_poll_tasks.add(current_task)
            request_next_url = self._next_url

        url = self._build_url(next_url=request_next_url)
        _logger.debug("Polling %s", _mask_url(url, self._token))

        try:
            status, text = await self._request(url)

            events, next_url = process_response(
                status=status,
                text=text,
                context=self._parser_context,
                strict_validation=self.config.strict_validation,
                log_next_url=lambda next_url: _logger.debug(
                    "Received nextUrl from timeout response: %s",
                    _mask_url(next_url, self._token),
                ),
            )

            async with self._polling_lock:
                if self._state is _ClientState.OPEN:
                    if self._next_url == request_next_url:
                        self._next_url = next_url
                    else:
                        _logger.debug(
                            "Skipping stale nextUrl update for user %s",
                            self.username,
                        )
        except asyncio.CancelledError:
            if self._state is not _ClientState.OPEN:
                raise EventsError(_POLL_CANCELLED_ON_CLOSE_MESSAGE) from None
            raise
        else:
            return events
        finally:
            async with self._polling_lock:
                self._active_poll_tasks.discard(current_task)

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
        """  # noqa: DOC502  # Called functions raise AuthError/EventsError on failure.
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
        try:
            current_task = asyncio.current_task()
            # Cancel in-flight poll tasks first so shutdown does not wait on long I/O.
            async with self._polling_lock:
                poll_tasks = [
                    task
                    for task in self._active_poll_tasks
                    if task is not current_task and not task.done()
                ]

            for poll_task in poll_tasks:
                _ = poll_task.cancel()

            for poll_task in poll_tasks:
                with suppress(asyncio.CancelledError, EventsError):
                    await poll_task

            # If outside the lock, await session.close() so it is not held on I/O.
            async with self._polling_lock:
                session: ClientSession | None = self.session
                self.session = None
                self._next_url = None
                self._active_poll_tasks.clear()
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
