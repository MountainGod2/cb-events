"""Async HTTP client for polling the Chaturbate Events API."""

from __future__ import annotations

import asyncio
import logging
from enum import Enum, auto
from http import HTTPStatus
from typing import TYPE_CHECKING, Final
from urllib.parse import quote, unquote

from aiohttp import ClientSession, ClientTimeout
from aiohttp.client_exceptions import ClientError
from aiolimiter import AsyncLimiter
from typing_extensions import override
from yarl import URL

from ._config import ClientConfig
from ._exceptions import CF_SERVER_ERROR_CODES, EventsError, EventsUrlError
from ._parser import (
    ParserContext,
    process_response,
)
from ._request import AuthRetryOptions, perform_request_attempt, request_with_retry
from ._utils import UrlValidationError, UrlValidationReason, validate_https_host_no_port

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

_RETRY_STATUS_CODES: Final[frozenset[int]] = frozenset({
    HTTPStatus.INTERNAL_SERVER_ERROR.value,
    HTTPStatus.BAD_GATEWAY.value,
    HTTPStatus.SERVICE_UNAVAILABLE.value,
    HTTPStatus.GATEWAY_TIMEOUT.value,
    HTTPStatus.TOO_MANY_REQUESTS.value,
    *CF_SERVER_ERROR_CODES,
})
"""HTTP status codes retried with exponential backoff."""

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

_POLL_CANCELLED_ON_CLOSE_MESSAGE: Final[str] = "Polling cancelled because client is closing."
"""Error raised when close() cancels an active poll."""

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

    try:
        normalized_host = validate_https_host_no_port(
            parsed,
            _SUPPORTED_EVENTS_HOSTS,
        )
    except UrlValidationError as exc:
        reason = exc.reason
        if reason == UrlValidationReason.USER_INFO:
            msg = "Events URL must not include user information."
            raise EventsUrlError(msg) from None
        if reason == UrlValidationReason.SCHEME:
            msg = "Events URL must use https."
            raise EventsUrlError(msg) from None
        if reason == UrlValidationReason.CUSTOM_PORT:
            msg = "Events URL must not include a custom port."
            raise EventsUrlError(msg) from None
        msg = (
            "Events URL host is not supported. "
            "Use eventsapi.chaturbate.com or events.testbed.cb.dev."
        )
        raise EventsUrlError(msg) from None

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


def _mask_token(token: str) -> str:
    """Mask token for logging."""
    return "*" * len(token)


def _mask_url(url: str, token: str) -> str:  # ruff: ignore[complex-structure]
    """Mask only the token value in a URL while preserving host/path/key names."""
    masked = _mask_token(token)
    encoded_token = _quote_segment(token)
    parsed = URL(url)

    def _mask_value(value: str) -> str:
        if value in {token, encoded_token}:
            return masked
        masked_value = value
        if token:
            masked_value = masked_value.replace(token, masked)
        if encoded_token:
            masked_value = masked_value.replace(encoded_token, masked)
        return masked_value

    def _mask_path_value(value: str) -> str:
        if not value:
            return value
        decoded_value = unquote(value)
        if token not in decoded_value:
            return value
        masked_decoded = decoded_value.replace(token, masked)
        masked_value = _quote_segment(masked_decoded).replace("%2A", "*")
        masked_value = masked_value.replace("%3A", ":").replace("%40", "@")
        if (
            len(token) == 1
            and len(masked_value) > 1
            and not any(separator in masked_value for separator in ("-", "_", ".", "~"))
        ):
            return value
        return masked_value

    def _mask_query_value(value: str) -> str:
        if value in {token, encoded_token}:
            return masked
        if len(token) == 1 and not any(separator in value for separator in ("-", "_", ".", "~")):
            return value
        return _mask_value(value)

    masked_path_parts: list[str] = [_mask_path_value(part) for part in parsed.raw_path.split("/")]
    masked_path = "/".join(masked_path_parts)

    masked_query_items: list[tuple[str, str]] = []
    for key, query_value in parsed.query.items():
        masked_query_value = _mask_query_value(query_value)
        masked_query_items.append((key, masked_query_value))

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
        self._active_poll_tasks: set[asyncio.Task[list[Event]]] = set()
        self._state: _ClientState = _ClientState.NEW
        self._next_url: str | None = None
        self._polling_semaphore: asyncio.Semaphore = asyncio.Semaphore(1)
        self._rate_limiter: AsyncLimiter = rate_limiter or AsyncLimiter(
            max_rate=_DEFAULT_MAX_RATE,
            time_period=_DEFAULT_TIME_PERIOD,
        )
        self._auth_retry_options: AuthRetryOptions = AuthRetryOptions(
            status_codes=self._config.auth_retry_status_codes,
            attempts=self._config.auth_retry_attempts,
            delay=self._config.auth_retry_delay,
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
        return f"EventClient(username='{self.username}', token='{_mask_token(self._token)}')"

    async def __aenter__(self) -> Self:
        """Open the HTTP session on context entry.

        Returns:
            Self: Client instance ready for use.

        Raises:
            EventsError: If the client has already been closed, is already
                open, or if session creation fails.
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

    async def _perform_request_attempt(self, url: str) -> tuple[int, str]:
        """Perform one HTTP request attempt."""
        # Session may be set to None by close() between retry attempts.
        if self._session is None:
            msg = "Client session unexpectedly unavailable"
            raise EventsError(msg)

        return await perform_request_attempt(
            session=self._session,
            rate_limiter=self._rate_limiter,
            url=url,
            retry_status_codes=_RETRY_STATUS_CODES,
            auth_retry=self._auth_retry_options,
            username=self._username,
        )

    async def _request(self, url: str) -> tuple[int, str]:
        """Run one request with retry/backoff policy."""
        if self._session is None:
            raise EventsError(_CLIENT_NOT_INITIALIZED_MESSAGE)

        return await request_with_retry(
            url=url,
            config=self._config,
            perform_attempt=self._perform_request_attempt,
            username=self._username,
        )

    async def poll(self) -> list[Event]:
        """Fetch one batch of events from the API.

        Makes one request and updates _next_url for the next poll.

        Returns:
            List of events received, or an empty list on timeout.

        Raises:
            EventsError: If shutdown has started.
            asyncio.CancelledError: If close() cancels this poll.
        """  # ruff: ignore[docstring-extraneous-exception]  # Called function may raise asyncio.CancelledError
        if self._state is _ClientState.NEW:
            raise EventsError(_CLIENT_NOT_INITIALIZED_MESSAGE)
        if self._state is not _ClientState.OPEN:
            raise EventsError(_CLIENT_CLOSING_MESSAGE)

        current_task = asyncio.current_task()
        if current_task is None:  # pragma: no cover
            # asyncio guarantees a current task exists inside a running coroutine.
            msg = "Unable to resolve current asyncio task."
            raise EventsError(msg)

        async with self._polling_semaphore:
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
                    strict_validation=self._config.strict_validation,
                    log_next_url=lambda next_url: _logger.debug(
                        "Received nextUrl from timeout response: %s",
                        _mask_url(next_url, self._token),
                    ),
                )

                if self._state is _ClientState.OPEN:
                    self._next_url = next_url
                return events
            finally:
                self._active_poll_tasks.discard(current_task)

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

        Raises:
            asyncio.CancelledError: If the caller of close() is cancelled while
                waiting for in-flight polls to finish shutting down.
        """
        if self._state is _ClientState.CLOSED:
            return

        self._state = _ClientState.CLOSING
        session = self._session
        self._session = None
        self._next_url = None
        try:
            current_task = asyncio.current_task()
            poll_tasks = [
                task
                for task in self._active_poll_tasks
                if task is not current_task and not task.done()
            ]

            for poll_task in poll_tasks:
                poll_task.cancel()  # pyright: ignore[reportUnusedCallResult]

            for poll_task in poll_tasks:
                try:
                    await poll_task
                except asyncio.CancelledError:
                    current_task = asyncio.current_task()
                    if current_task is not None and current_task.cancelling():
                        raise
        finally:
            self._active_poll_tasks.clear()

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
            self._state = _ClientState.CLOSED
