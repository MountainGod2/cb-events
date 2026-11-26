"""Async HTTP client for polling the Chaturbate Events API."""

from __future__ import annotations

import asyncio
import logging
from enum import Enum, auto
from typing import TYPE_CHECKING, Final
from urllib.parse import quote, unquote

from aiohttp import ClientSession, ClientTimeout
from aiohttp.client_exceptions import ClientError
from aiolimiter import AsyncLimiter
from typing_extensions import override
from yarl import URL

from ._config import ClientConfig
from ._exceptions import EventsError, EventsUrlError
from ._parser import (
    ParserContext,
    process_response,
)
from ._request import perform_request_attempt, request_with_retry

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from types import TracebackType
    from typing import Self

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

_CONNECT_TIMEOUT: Final[int] = 10
"""Connection timeout in seconds."""

_SESSION_TIMEOUT_BUFFER: Final[int] = 5
"""Extra seconds added to the client timeout."""

_CLIENT_CLOSING_MESSAGE: Final[str] = "Client is closing or closed."
"""Error raised when polling while closing or closed."""

_CLIENT_NOT_INITIALIZED_MESSAGE: Final[str] = (
    "Client not initialized. Use 'async with EventClient(...)' as a context manager."
)
"""Error raised when polling before context entry."""

_CLIENT_CLOSED_ENTER_MESSAGE: Final[str] = (
    "Client is closed and cannot be reopened. Create a new EventClient instance."
)
"""Error raised when entering a client after close()."""

_CLIENT_ALREADY_OPEN_MESSAGE: Final[str] = (
    "EventClient is already open. Enter the 'async with' block only once per instance."
)
"""Error raised when entering an already-open client."""

_CLIENT_SESSION_CLOSED_MESSAGE: Final[str] = "Injected client session is already closed."
"""Error raised when entering with a caller-owned session that cannot be reused."""

_POLL_STOPPED_ON_CLOSE_MESSAGE: Final[str] = "Polling stopped because client is closing."
"""Error raised when close() interrupts an active poll."""

_SUPPORTED_EVENTS_HOSTS: Final[dict[str, str]] = {
    "eventsapi.chaturbate.com": BASE_URL,
    "events.testbed.cb.dev": TESTBED_URL,
}
"""Allowed API hosts mapped to canonical base URLs."""


class _ClientState(Enum):
    """Lifecycle state of an :class:`EventClient` instance."""

    NEW = auto()
    """Client has not entered its context manager."""

    OPEN = auto()
    """Client is active and ready to poll."""

    CLOSING = auto()
    """Client is shutting down; new polls are rejected."""

    CLOSED = auto()
    """Client has been fully closed and cannot be reopened."""


def _validate_non_empty_stripped(value: str, *, field: str, hint: str) -> None:
    """Raise EventsUrlError for empty or padded URL components."""
    if not value or value != value.strip():
        msg = f"{field} must not be empty or contain leading/trailing whitespace. {hint}"
        raise EventsUrlError(msg)


def _quote_segment(value: str) -> str:
    """Percent-encode a single opaque path segment."""
    return quote(value, safe="")


def _parse_events_url(events_url: str) -> tuple[str, str, str]:
    """Parse and validate the Events API URL."""
    if not events_url or events_url != events_url.strip():
        msg = "Events URL must not be empty or contain leading/trailing whitespace."
        raise EventsUrlError(msg)

    try:
        parsed = URL(events_url)
    except ValueError as exc:
        msg = "Events URL must match https://<host>/events/<username>/<token>/"
        raise EventsUrlError(msg) from exc

    if parsed.query_string or parsed.fragment:
        msg = "Events URL must not include query parameters or fragments."
        raise EventsUrlError(msg)

    if parsed.user is not None or parsed.password is not None:
        msg = "Events URL must not include user information."
        raise EventsUrlError(msg)
    if parsed.scheme != "https":
        msg = "Events URL must use https."
        raise EventsUrlError(msg)
    if parsed.explicit_port is not None:
        msg = "Events URL must not include a custom port."
        raise EventsUrlError(msg)
    if not parsed.host:
        msg = (
            "Events URL host is not supported. "
            "Use eventsapi.chaturbate.com or events.testbed.cb.dev."
        )
        raise EventsUrlError(msg)
    normalized_host = parsed.host.lower()
    if normalized_host not in _SUPPORTED_EVENTS_HOSTS:
        msg = (
            "Events URL host is not supported. "
            "Use eventsapi.chaturbate.com or events.testbed.cb.dev."
        )
        raise EventsUrlError(msg)

    base_url = _SUPPORTED_EVENTS_HOSTS[normalized_host]

    parts = [part for part in parsed.raw_parts if part not in {"", "/"}]
    if len(parts) != 3 or parts[0] != "events":  # ruff: ignore[magic-value-comparison]
        msg = "Events URL must match https://<host>/events/<username>/<token>/"
        raise EventsUrlError(msg)

    username, token = unquote(parts[1]), unquote(parts[2])
    _validate_non_empty_stripped(
        username, field="Username", hint="Provide a valid Chaturbate username."
    )
    _validate_non_empty_stripped(
        token,
        field="Token",
        hint="Generate a valid token at https://chaturbate.com/statsapi/authtoken/",
    )
    return base_url, username, token


def _mask_url(url: str, token: str) -> str:
    """Mask token-shaped path/query components.

    The API carries credentials as a complete path segment, so substrings inside
    unrelated component values are deliberately left unchanged.

    Returns:
        URL with exact token components replaced by a fixed marker.
    """
    masked = "***"
    parsed = URL(url)
    masked_path_parts = [
        masked if unquote(part) == token else part for part in parsed.raw_path.split("/")
    ]
    masked_path = "/".join(masked_path_parts)
    masked_query_items = [
        (key, masked if value == token else value) for key, value in parsed.query.items()
    ]
    return str(parsed.with_path(masked_path, encoded=True).with_query(masked_query_items))


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
        session: ClientSession | None = None,
    ) -> None:
        """Initialize a client from an Events API URL.

        Args:
            events_url: Full Events API URL provided by upstream.
            config: Optional client configuration overrides.
            rate_limiter: Optional shared limiter for multiple clients.
            session: Optional caller-owned aiohttp session. Caller-owned
                sessions are not closed by EventClient.
        """
        base_url, username, token = _parse_events_url(events_url)
        self._base_url: str = base_url
        self._username: str = username
        self._token: str = token
        self._config: ClientConfig = config or ClientConfig()
        self._session: ClientSession | None = session
        self._owns_session: bool = session is None
        self._parser_context: ParserContext = ParserContext(
            username=self.username,
            base_url=self.base_url,
            parsed_base_url=URL(self.base_url),
        )
        self._state: _ClientState = _ClientState.NEW
        self._closing = asyncio.Event()
        self._next_url: str | None = None
        self._polling_semaphore: asyncio.Semaphore = asyncio.Semaphore(1)
        self._rate_limiter: AsyncLimiter = rate_limiter or AsyncLimiter(
            max_rate=_DEFAULT_MAX_RATE,
            time_period=_DEFAULT_TIME_PERIOD,
        )

    @property
    def base_url(self) -> str:
        """Canonical Events API base URL."""
        return self._base_url

    @property
    def username(self) -> str:
        """Account username parsed from the Events API URL."""
        return self._username

    @property
    def config(self) -> ClientConfig:
        """Immutable client configuration."""
        return self._config

    @property
    def session(self) -> ClientSession | None:
        """Active HTTP session, or None before entry and after close."""
        return self._session

    @override
    def __repr__(self) -> str:
        """Return a representation with a masked token.

        Returns:
            Masked representation revealing only limited token characters.
        """
        return f"EventClient(username='{self.username}', token='***')"

    async def __aenter__(self) -> Self:
        """Open the HTTP session on context entry.

        Returns:
            Self: Client instance ready for use.

        Raises:
            EventsError: If the client has already been closed, is already
                open, or if the injected session is already closed.

        Note:
            Session construction errors such as ``OSError`` propagate unchanged.
        """
        if self._state in {_ClientState.CLOSED, _ClientState.CLOSING}:
            raise EventsError(_CLIENT_CLOSED_ENTER_MESSAGE)
        if self._state is not _ClientState.NEW:
            raise EventsError(_CLIENT_ALREADY_OPEN_MESSAGE)
        if self._session is not None and self._session.closed:
            raise EventsError(_CLIENT_SESSION_CLOSED_MESSAGE)

        if self._session is None:
            self._session = ClientSession(
                timeout=ClientTimeout(
                    total=self._config.timeout + _SESSION_TIMEOUT_BUFFER,
                    connect=_CONNECT_TIMEOUT,
                ),
            )
        self._state = _ClientState.OPEN

        return self

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
        """Build the URL for the next poll."""
        if next_url:
            return next_url
        poll_url = URL(
            f"{self._base_url.removesuffix('/')}/{_quote_segment(self._username)}/{_quote_segment(self._token)}/"
        )
        return str(poll_url.with_query(timeout=self._config.timeout))

    async def _send_request(self, url: str) -> tuple[int, str]:
        """Perform one HTTP request attempt."""
        # Session may be set to None by close() between retry attempts.
        if self._session is None:
            msg = "Client session unexpectedly unavailable"
            raise EventsError(msg)

        return await perform_request_attempt(
            session=self._session,
            rate_limiter=self._rate_limiter,
            url=url,
            retry_auth_status_codes=self._config.auth_retry_status_codes,
        )

    async def _request(self, url: str) -> tuple[int, str]:
        """Run one request with retry/backoff policy."""
        if self._session is None:
            raise EventsError(_CLIENT_NOT_INITIALIZED_MESSAGE)

        return await request_with_retry(
            url=url,
            config=self._config,
            perform_attempt=self._send_request,
            username=self._username,
        )

    async def poll(self) -> list[Event]:
        """Fetch one batch of events from the API.

        Makes one request and updates _next_url for the next poll.

        Returns:
            List of events received, or an empty list on timeout.

        Raises:
            EventsError: If shutdown has started.
        """
        if self._state is _ClientState.NEW:
            raise EventsError(_CLIENT_NOT_INITIALIZED_MESSAGE)
        if self._state is not _ClientState.OPEN:
            raise EventsError(_CLIENT_CLOSING_MESSAGE)

        async with self._polling_semaphore:
            if self._state is not _ClientState.OPEN:
                raise EventsError(_CLIENT_CLOSING_MESSAGE)
            request_next_url = self._next_url

            url = self._build_url(next_url=request_next_url)
            if _logger.isEnabledFor(logging.DEBUG):
                _logger.debug("Polling %s", _mask_url(url, self._token))
            request_task = asyncio.create_task(self._request(url))
            closing_task = asyncio.create_task(self._closing.wait())
            try:
                done, _ = await asyncio.wait(
                    (request_task, closing_task),
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if closing_task in done:
                    raise EventsError(_POLL_STOPPED_ON_CLOSE_MESSAGE)
                status, text = await request_task
            finally:
                for task in (request_task, closing_task):
                    if not task.done():
                        task.cancel()  # pyright: ignore[reportUnusedCallResult]
                await asyncio.gather(
                    request_task,
                    closing_task,
                    return_exceptions=True,
                )

            events, next_url = process_response(
                status=status,
                text=text,
                context=self._parser_context,
                strict_validation=self._config.strict_validation,
                log_next_url=lambda next_url: (
                    _logger.debug(
                        "Received nextUrl from timeout response: %s",
                        _mask_url(next_url, self._token),
                    )
                    if _logger.isEnabledFor(logging.DEBUG)
                    else None
                ),
            )

            if self._state is _ClientState.OPEN:
                self._next_url = next_url
            return events

    async def __aiter__(self) -> AsyncIterator[Event]:
        """Yield events continuously from the API.

        Runs until cancelled or a terminal error occurs. Transient failures
        are retried according to config.retry_attempts.

        Yields:
            Event instances as they are received from the API.

        Raises:
            AuthError: If authentication fails (e.g. invalid token).
            EventsError: If a non-retryable error occurs or retries are exhausted.

        Note:
            Poll position is tracked with nextUrl between iterations.
        """  # ruff: ignore[docstring-extraneous-exception]  # Called functions raise AuthError/EventsError on failure.
        while True:
            events = await self.poll()
            for event in events:
                yield event

    async def close(self) -> None:
        """Close the HTTP session and reset poll state.

        Safe to call multiple times. Called automatically by context exit.
        Internally created sessions are closed; caller-owned injected sessions
        remain open. After close(), the instance cannot be reopened.

        """
        if self._state is _ClientState.CLOSED:
            return

        self._state = _ClientState.CLOSING
        self._closing.set()
        session = self._session
        self._session = None
        self._next_url = None
        try:
            if session is not None and self._owns_session:
                close_task = asyncio.create_task(session.close())
                try:
                    await asyncio.shield(close_task)
                except asyncio.CancelledError:
                    _logger.warning(
                        "Session close for user %s was cancelled; waiting for shutdown to finish.",
                        self.username,
                    )
                    try:
                        await asyncio.shield(close_task)
                    except (ClientError, OSError, RuntimeError) as exc:
                        _logger.warning("Error closing session (%s).", type(exc).__name__)
                    raise
                except (ClientError, OSError, RuntimeError) as exc:
                    _logger.warning("Error closing session (%s).", type(exc).__name__)
        finally:
            self._state = _ClientState.CLOSED
