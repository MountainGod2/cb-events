"""HTTP client for the Chaturbate Events API."""

import asyncio
import json
import logging
from collections.abc import AsyncGenerator, AsyncIterator
from http import HTTPStatus
from logging import Logger
from types import TracebackType
from typing import Any, LiteralString, Self
from urllib.parse import quote

from aiohttp import ClientSession, ClientTimeout
from aiohttp.client_exceptions import ClientError
from aiolimiter import AsyncLimiter
from pydantic import BaseModel, Field, ValidationError
from pydantic.config import ConfigDict

from .config import EventClientConfig
from .exceptions import AuthError, EventsError
from .models import Event

# API endpoints
BASE_URL = "https://eventsapi.chaturbate.com/events"
TESTBED_URL = "https://events.testbed.cb.dev/events"
URL_TEMPLATE = "{base_url}/{username}/{token}/?timeout={timeout}"

# Rate limiting
RATE_LIMIT_MAX_RATE = 2000
RATE_LIMIT_TIME_PERIOD = 60

# HTTP handling
SESSION_TIMEOUT_BUFFER = 5
TOKEN_MASK_VISIBLE = 4
RESPONSE_TRUNCATE_LENGTH = 200
AUTH_ERROR_STATUSES: set[HTTPStatus] = {
    HTTPStatus.UNAUTHORIZED,
    HTTPStatus.FORBIDDEN,
}
RETRY_STATUS_CODES: set[int] = {
    HTTPStatus.INTERNAL_SERVER_ERROR.value,
    HTTPStatus.BAD_GATEWAY.value,
    HTTPStatus.SERVICE_UNAVAILABLE.value,
    HTTPStatus.GATEWAY_TIMEOUT.value,
    HTTPStatus.TOO_MANY_REQUESTS.value,
    521,  # Cloudflare: origin down
    522,  # Cloudflare: connection timeout
    523,  # Cloudflare: origin unreachable
    524,  # Cloudflare: timeout occurred
}

logger: Logger = logging.getLogger(__name__)


def _format_validation_errors(error: ValidationError) -> str:
    """Format validation error locations as comma-separated string.

    Args:
        error: Validation error from Pydantic.

    Returns:
        Comma-separated field paths.
    """
    locations: set[str] = {
        ".".join(str(part) for part in err.get("loc", ())) or "<root>"
        for err in error.errors()
    }
    return ", ".join(sorted(locations))


def _mask_token(token: str) -> str:
    """Mask a token keeping only the last few characters visible.

    Args:
        token: Token to mask.

    Returns:
        Masked token.
    """
    if TOKEN_MASK_VISIBLE <= 0 or len(token) <= TOKEN_MASK_VISIBLE:
        return "*" * len(token)
    masked: LiteralString = "*" * (len(token) - TOKEN_MASK_VISIBLE)
    return f"{masked}{token[-TOKEN_MASK_VISIBLE:]}"


def _mask_url(url: str, token: str) -> str:
    """Mask token in URL for safe logging.

    Args:
        url: URL containing the token.
        token: Token to mask.

    Returns:
        URL with masked token.
    """
    masked: str = _mask_token(token)
    return url.replace(token, masked).replace(quote(token, safe=""), masked)


class _ResponseBatch(BaseModel):
    """API response wrapper."""

    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    next_url: str | None = Field(alias="nextUrl")
    events: list[dict[str, Any]] = Field(default_factory=list)


def _parse_events(raw: list[dict[str, Any]], *, strict: bool) -> list[Event]:
    """Convert raw event dicts to Event models.

    Args:
        raw: Raw event payloads from API.
        strict: Whether to raise on validation failures.

    Returns:
        Validated Event instances.

    Raises:
        ValidationError: If strict=True and a payload is invalid.
    """
    events: list[Event] = []
    for item in raw:
        try:
            events.append(Event.model_validate(item))
        except ValidationError as exc:
            if strict:
                raise
            event_id = str(item.get("id", "<unknown>"))
            logger.warning(
                "Skipping invalid event %s: %s",
                event_id,
                _format_validation_errors(exc),
            )
    return events


class EventClient:
    """Async client for polling the Chaturbate Events API.

    Streams events with automatic retries, rate limiting, and credential
    handling. Use as an async context manager or iterator.

    Share rate limiters across clients to pool request limits:
        >>> limiter = AsyncLimiter(max_rate=2000, time_period=60)
        >>> async with (
        ...     EventClient("user1", "token1", rate_limiter=limiter) as c1,
        ...     EventClient("user2", "token2", rate_limiter=limiter) as c2,
        ... ):
        ...     pass
    """

    def __init__(
        self,
        username: str,
        token: str,
        *,
        config: EventClientConfig | None = None,
        rate_limiter: AsyncLimiter | None = None,
    ) -> None:
        """Initialize the client.

        Args:
            username: Chaturbate username.
            token: Events API token.
            config: Client settings (uses defaults if not provided).
            rate_limiter: Rate limiter shared across clients
                (defaults to 2000 req/60s per instance).

        Raises:
            AuthError: If username or token is empty or has whitespace.
        """
        if not username or username != username.strip():
            msg = "Username must not be empty or contain whitespace"
            raise AuthError(msg)
        if not token or token != token.strip():
            msg = "Token must not be empty or contain whitespace"
            raise AuthError(msg)

        self.username = username
        self.token = token

        self.config = config or EventClientConfig()
        self.timeout = self.config.timeout
        self.base_url = TESTBED_URL if self.config.use_testbed else BASE_URL
        self.session: ClientSession | None = None
        self._next_url: str | None = None
        self._polling_lock = asyncio.Lock()
        self._rate_limiter = rate_limiter or AsyncLimiter(
            max_rate=RATE_LIMIT_MAX_RATE,
            time_period=RATE_LIMIT_TIME_PERIOD,
        )

    def __repr__(self) -> str:
        """Return string representation with masked token."""
        return (
            f"EventClient(username='{self.username}', "
            f"token='{_mask_token(self.token)}')"
        )

    async def __aenter__(self) -> Self:
        """Initialize HTTP session.

        Returns:
            Client instance with active session.

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
            msg = "Failed to create HTTP session"
            raise EventsError(msg) from e
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Clean up session and resources."""
        await self.close()

    def _build_url(self) -> str:
        """Build URL for next poll request.

        Returns:
            URL for next poll.
        """
        return self._next_url or URL_TEMPLATE.format(
            base_url=self.base_url,
            username=quote(self.username, safe=""),
            token=quote(self.token, safe=""),
            timeout=self.timeout,
        )

    def _extract_next_url(self, text: str) -> str | None:
        """Extract nextUrl from timeout error response.

        Args:
            text: Response text.

        Returns:
            Extracted nextUrl or None.
        """
        try:
            data: Any = json.loads(text)
        except json.JSONDecodeError:
            return None

        status: str = data.get("status", "")
        if isinstance(status, str) and "waited too long" in status.lower():
            next_url: str | None = data.get("nextUrl")
            if next_url:
                logger.debug("Received nextUrl from timeout response")
                self._next_url = next_url
                return str(next_url)
        return None

    async def _make_request(self, url: str) -> tuple[int, str]:
        """Fetch response from the Events API.

        Args:
            url: Request URL.

        Returns:
            Tuple of (status_code, response_text).

        Raises:
            EventsError: If request fails after retries.
        """
        if self.session is None:
            msg = "Client not initialized - use async context manager"
            raise EventsError(msg)

        max_attempts: int = max(1, self.config.retry_attempts)
        delay = self.config.retry_backoff
        attempt = 0

        while True:
            attempt += 1
            try:
                async with (
                    self._rate_limiter,
                    self.session.get(url) as response,
                ):
                    text: str = await response.text()
                    status: int = response.status
            except (ClientError, TimeoutError, OSError) as exc:
                if attempt >= max_attempts:
                    logger.exception(
                        "Request failed after %d attempts: %s",
                        attempt,
                        _mask_url(url, self.token),
                    )
                    msg = "Failed to fetch events from API"
                    raise EventsError(msg) from exc

                logger.warning(
                    "Attempt %d/%d failed: %s", attempt, max_attempts, exc
                )
                await asyncio.sleep(delay)
                delay = min(
                    delay * self.config.retry_factor,
                    self.config.retry_max_delay,
                )
                continue

            if status in RETRY_STATUS_CODES and attempt < max_attempts:
                logger.debug(
                    "Retrying due to status %s (attempt %d/%d)",
                    status,
                    attempt,
                    max_attempts,
                )
                await asyncio.sleep(delay)
                delay = min(
                    delay * self.config.retry_factor,
                    self.config.retry_max_delay,
                )
                continue

            return status, text

    def _handle_response_status(self, status: int, text: str) -> bool:
        """Process HTTP response status codes.

        Args:
            status: HTTP status code.
            text: Response body.

        Returns:
            True if timeout response was handled (skip parsing).

        Raises:
            AuthError: For 401/403 responses.
            EventsError: For other non-200 responses.
        """
        if status in AUTH_ERROR_STATUSES:
            logger.warning("Auth failed for user %s", self.username)
            msg = f"Authentication failed for {self.username}"
            raise AuthError(msg)

        if status == HTTPStatus.BAD_REQUEST and self._extract_next_url(text):
            return True

        if status != HTTPStatus.OK:
            snippet: str = text[:RESPONSE_TRUNCATE_LENGTH]
            if len(text) > RESPONSE_TRUNCATE_LENGTH:
                snippet += "..."
            logger.error("HTTP %d: %s", status, snippet)
            msg = f"HTTP {status}: {snippet}"
            raise EventsError(msg, status_code=status, response_text=text)

        return False

    @staticmethod
    def _decode_json(text: str) -> dict[str, Any]:
        """Parse response as JSON.

        Args:
            text: HTTP response body.

        Returns:
            Parsed JSON dictionary.

        Raises:
            EventsError: If JSON is invalid.
        """
        try:
            data: Any = json.loads(text)
        except json.JSONDecodeError as exc:
            snippet: str = text[:RESPONSE_TRUNCATE_LENGTH]
            if len(text) > RESPONSE_TRUNCATE_LENGTH:
                snippet += "..."
            logger.exception("Failed to parse JSON: %s", snippet)
            msg: str = f"Invalid JSON response: {exc.msg}"
            raise EventsError(msg, response_text=text) from exc
        if not isinstance(data, dict):
            msg = "Invalid JSON response: expected object"
            raise EventsError(msg, response_text=text)
        return data

    def _parse_batch(
        self, payload: dict[str, Any], *, raw_text: str
    ) -> tuple[str | None, list[Event]]:
        """Validate API payload and extract events.

        Args:
            payload: Parsed JSON response.
            raw_text: Original response for error messages.

        Returns:
            Tuple of (next_url, events).

        Raises:
            EventsError: If payload validation fails.
        """
        try:
            batch: _ResponseBatch = _ResponseBatch.model_validate(payload)
        except ValidationError as exc:
            msg = "Invalid API response"
            raise EventsError(msg, response_text=raw_text) from exc

        events: list[Event] = _parse_events(
            batch.events,
            strict=self.config.strict_validation,
        )
        self._next_url = batch.next_url

        if events:
            logger.debug("Received %d events", len(events))

        return batch.next_url, events

    async def poll(self) -> list[Event]:
        """Poll the API for new events.

        Safe for concurrent calls (uses internal lock).

        Returns:
            Events received (empty list if timeout or no events).
        """
        async with self._polling_lock:
            url: str = self._build_url()
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("Polling %s", _mask_url(url, self.token))

            status, text = await self._make_request(url)

            if self._handle_response_status(status, text):
                return []

            payload: dict[str, Any] = self._decode_json(text)
            _, events = self._parse_batch(payload, raw_text=text)
            return events

    def __aiter__(self) -> AsyncIterator[Event]:
        """Stream events continuously as an async iterator.

        Yields events as they arrive from the API. Safe to iterate
        multiple times (each iteration polls independently).

        Returns:
            Async iterator yielding Event objects.
        """
        return self._stream()

    async def _stream(self) -> AsyncGenerator[Event]:
        """Internal generator for continuous event streaming.

        Yields:
            Event objects from the API.
        """
        while True:
            events: list[Event] = await self.poll()
            for event in events:
                yield event

    async def close(self) -> None:
        """Close session and reset state (idempotent)."""
        try:
            if self.session:
                await self.session.close()
                self.session = None
        except (ClientError, OSError, RuntimeError) as e:
            logger.warning("Error closing session: %s", e, exc_info=True)

        self._next_url = None
