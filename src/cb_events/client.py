"""HTTP client for the Chaturbate Events API."""

import asyncio
import json
import logging
from collections.abc import AsyncGenerator, AsyncIterator
from http import HTTPStatus
from types import TracebackType
from typing import Any, Self
from urllib.parse import quote

from aiohttp import ClientSession, ClientTimeout
from aiohttp.client_exceptions import ClientError
from aiolimiter import AsyncLimiter
from pydantic import BaseModel, Field, ValidationError
from pydantic.config import ConfigDict

from .config import EventClientConfig
from .constants import (
    AUTH_ERROR_STATUSES,
    BASE_URL,
    RATE_LIMIT_MAX_RATE,
    RATE_LIMIT_TIME_PERIOD,
    RETRY_STATUS_CODES,
    SESSION_TIMEOUT_BUFFER,
    TESTBED_URL,
    URL_TEMPLATE,
)
from .exceptions import AuthError, EventsError
from .models import Event, _format_validation_errors

logger = logging.getLogger(__name__)


def _mask_token(token: str, visible: int = 4) -> str:
    """Mask a token while keeping the last few characters visible.

    Args:
        token: Token to mask.
        visible: Number of trailing characters to show.

    Returns:
        Masked token.
    """
    if visible <= 0 or len(token) <= visible:
        return "*" * len(token)
    return f"{'*' * (len(token) - visible)}{token[-visible:]}"


def _mask_url(url: str, token: str) -> str:
    """Mask token in URL for safe logging.

    Args:
        url: URL that may contain the token.
        token: Token to mask.

    Returns:
        URL with token masked.
    """
    masked = _mask_token(token)
    return url.replace(token, masked).replace(quote(token, safe=""), masked)


class _EventBatch(BaseModel):
    """API response payload."""

    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    next_url: str | None = Field(alias="nextUrl")
    events: list[dict[str, Any]] = Field(default_factory=list)


def _validate_events(
    raw_events: list[dict[str, Any]],
    *,
    strict: bool,
) -> list[Event]:
    """Convert raw event dicts to Event models.

    Args:
        raw_events: Raw event payloads.
        strict: Whether to raise on validation failures.

    Returns:
        List of validated Event instances.

    Raises:
        ValidationError: If strict=True and a payload is invalid.
    """
    events: list[Event] = []
    for item in raw_events:
        try:
            events.append(Event.model_validate(item))
        except ValidationError as exc:
            if strict:
                raise
            event_id = str(item.get("id", "<unknown>"))
            logger.warning(
                "event_id=%s locations=%s",
                event_id,
                _format_validation_errors(exc),
            )
    return events


class EventClient:
    """HTTP client for polling the Chaturbate Events API.

    Streams events with automatic retries, rate limiting, and credential
    handling.

    Share a rate limiter across clients to pool rate limits:
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
            config: Client settings (defaults to EventClientConfig()).
            rate_limiter: Rate limiter to share across clients
                (defaults to 2000 req/60s).

        Raises:
            AuthError: If username or token is empty or has whitespace.
        """
        if not username or username != username.strip():
            msg = (
                "Username cannot be empty or contain "
                "leading/trailing whitespace"
            )
            raise AuthError(msg)
        if not token or token != token.strip():
            msg = "Token cannot be empty or contain leading/trailing whitespace"
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
            EventsError: If session initialization fails.
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
            msg = "Failed to initialize HTTP session"
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
            data = json.loads(text)
        except json.JSONDecodeError:
            return None

        status = data.get("status", "")
        if isinstance(status, str) and "waited too long" in status.lower():
            next_url = data.get("nextUrl")
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

        max_attempts = max(1, self.config.retry_attempts)
        delay = self.config.retry_backoff
        attempt = 0

        while True:
            attempt += 1
            try:
                async with (
                    self._rate_limiter,
                    self.session.get(url) as response,
                ):
                    text = await response.text()
                    status = response.status
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
        """Handle response status codes.

        Args:
            status: HTTP status code.
            text: Response text.

        Returns:
            True if timeout was handled and parsing should be skipped.

        Raises:
            AuthError: For auth failures.
            EventsError: For other HTTP errors.
        """
        if status in AUTH_ERROR_STATUSES:
            logger.warning("Authentication failed for user %s", self.username)
            msg = f"Authentication failed for {self.username}"
            raise AuthError(msg)

        if status == HTTPStatus.BAD_REQUEST and self._extract_next_url(text):
            return True

        if status != HTTPStatus.OK:
            trimmed = text[:200] if len(text) > HTTPStatus.OK else text
            logger.error("HTTP error %d: %s", status, trimmed)
            msg = f"HTTP {status}: {trimmed}"
            raise EventsError(msg, status_code=status, response_text=text)

        return False

    @staticmethod
    def _decode_json(text: str) -> dict[str, Any]:
        """Parse response text as JSON.

        Args:
            text: HTTP response body.

        Returns:
            Parsed JSON dictionary.

        Raises:
            EventsError: If JSON is invalid.
        """
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            logger.exception(
                "Failed to parse JSON: %s",
                text[:200] if len(text) > HTTPStatus.OK else text,
            )
            msg = f"Invalid JSON response: {exc.msg}"
            raise EventsError(msg, response_text=text) from exc
        if not isinstance(data, dict):
            msg = "Invalid JSON response: expected an object"
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
            batch = _EventBatch.model_validate(payload)
        except ValidationError as exc:
            msg = "Invalid API response"
            raise EventsError(msg, response_text=raw_text) from exc

        events = _validate_events(
            batch.events, strict=self.config.strict_validation
        )
        self._next_url = batch.next_url

        if events:
            logger.debug("Received %d events", len(events))

        return batch.next_url, events

    async def poll(self) -> list[Event]:
        """Poll for events from the API.

        Thread-safe for concurrent calls.

        Returns:
            List of Event objects (empty if no events or timeout).
        """
        async with self._polling_lock:
            url = self._build_url()
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("Polling: %s", _mask_url(url, self.token))

            status, text = await self._make_request(url)

            if self._handle_response_status(status, text):
                return []

            payload = self._decode_json(text)
            _, events = self._parse_batch(payload, raw_text=text)
            return events

    async def _poll_continuously(self) -> AsyncGenerator[Event]:
        """Continuously poll and yield events.

        Yields:
            Event objects as received.
        """
        while True:
            events = await self.poll()
            for event in events:
                yield event

    def stream(self) -> AsyncGenerator[Event]:
        """Return async iterator that streams events.

        Returns:
            Async generator yielding events.
        """
        return self._poll_continuously()

    def __aiter__(self) -> AsyncIterator[Event]:
        """Enable async iteration for continuous streaming.

        Returns:
            Async iterator yielding events.
        """
        return self.stream()

    async def close(self) -> None:
        """Close session and reset state (idempotent)."""
        try:
            if self.session:
                await self.session.close()
                self.session = None
        except (ClientError, OSError, RuntimeError) as e:
            logger.warning("Error closing session: %s", e, exc_info=True)

        self._next_url = None
