"""HTTP client for the Chaturbate Events API."""

import asyncio
import json
import logging
from collections.abc import AsyncGenerator, AsyncIterator
from dataclasses import dataclass
from http import HTTPStatus
from types import TracebackType
from typing import Any, Self
from urllib.parse import quote

from aiohttp import ClientSession, ClientTimeout
from aiohttp.client_exceptions import ClientError
from aiolimiter import AsyncLimiter
from pydantic import BaseModel, Field, ValidationError
from pydantic.config import ConfigDict

from ._utils import format_validation_error_locations, mask_secret, mask_secret_in_url, trim_for_log
from .config import EventClientConfig
from .constants import (
    AUTH_ERROR_STATUSES,
    BASE_URL,
    FIELD_NEXT_URL,
    FIELD_STATUS,
    RATE_LIMIT_MAX_RATE,
    RATE_LIMIT_TIME_PERIOD,
    RETRY_STATUS_CODES,
    SESSION_TIMEOUT_BUFFER,
    TESTBED_URL,
    TIMEOUT_ERROR_INDICATOR,
    URL_TEMPLATE,
)
from .exceptions import AuthError, EventsError
from .models import Event

logger = logging.getLogger(__name__)


class _RawEventBatch(BaseModel):
    """Raw payload structure from the Events API."""

    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    next_url: str | None = Field(alias="nextUrl")
    events: list[dict[str, Any]] = Field(default_factory=list)


@dataclass(slots=True)
class _EventBatch:
    """Validated events with the next polling URL."""

    next_url: str | None
    events: list[Event]


def _validate_events(
    raw_events: list[dict[str, Any]],
    *,
    strict_validation: bool,
) -> list[Event]:
    """Convert raw event dictionaries into ``Event`` models.

    Args:
        raw_events: Raw event payloads from the API response.
        strict_validation: Whether to bubble up validation failures.

    Returns:
        A list of validated ``Event`` instances.

    Raises:
        ValidationError: If ``strict_validation`` is ``True`` and a payload is invalid.
    """
    events: list[Event] = []
    for item in raw_events:
        try:
            events.append(Event.model_validate(item))
        except ValidationError as exc:
            if strict_validation:
                raise
            event_id = str(item.get("id", "<unknown>"))
            locations = format_validation_error_locations(exc)
            logger.warning("event_id=%s locations=%s", event_id, locations)
    return events


def _build_event_batch(
    payload: dict[str, Any],
    *,
    strict_validation: bool,
    raw_text: str | None,
) -> _EventBatch:
    """Validate and normalise the API payload into typed models.

    Args:
        payload: Parsed JSON response from the API.
        strict_validation: Whether to raise on invalid events.
        raw_text: Original response body for error reporting.

    Returns:
        An ``_EventBatch`` with the next URL and validated events.

    Raises:
        EventsError: If the payload structure cannot be validated.
    """
    try:
        raw_batch = _RawEventBatch.model_validate(payload)
    except ValidationError as exc:
        msg = "Invalid API response"
        raise EventsError(msg, response_text=raw_text or str(payload)) from exc

    events = _validate_events(raw_batch.events, strict_validation=strict_validation)
    return _EventBatch(next_url=raw_batch.next_url, events=events)


class EventClient:
    r"""HTTP client for polling the Chaturbate Events API.

    Streams events with automatic retries, rate limiting, and credential handling.
    Use as an async context manager or iterate for continuous streaming.

    Share a rate limiter across clients to pool rate limits:
        >>> limiter = AsyncLimiter(max_rate=2000, time_period=60)
        >>> async with EventClient("user1", "token1", rate_limiter=limiter) as c1, \
        ...            EventClient("user2", "token2", rate_limiter=limiter) as c2:
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
            rate_limiter: Rate limiter to share across clients (defaults to 2000 req/60s).

        Raises:
            AuthError: If username or token is empty or has whitespace.
        """
        if not username or username != username.strip():
            msg = "Username cannot be empty or contain leading/trailing whitespace"
            raise AuthError(msg)
        if not token or token != token.strip():
            msg = "Token cannot be empty or contain leading/trailing whitespace"
            raise AuthError(msg)

        self.username = username
        self.token = token

        self.config = config if config is not None else EventClientConfig()
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
        masked_token = mask_secret(self.token)
        return f"EventClient(username='{self.username}', token='{masked_token}')"

    def _mask_url(self, url: str) -> str:
        """Mask token in URL for logging.

        Returns:
            URL with masked token.
        """
        return mask_secret_in_url(url, self.token)

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
                    timeout=ClientTimeout(total=self.timeout + SESSION_TIMEOUT_BUFFER),
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

    def _build_poll_url(self) -> str:
        """Build URL for next poll request.

        Returns:
            URL for next poll request.
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
            text: Response text with potential nextUrl.

        Returns:
            Extracted nextUrl or None if not found.
        """
        try:
            error_data = json.loads(text)
        except json.JSONDecodeError:
            return None

        status_msg = error_data.get(FIELD_STATUS, "")
        if not isinstance(status_msg, str):
            return None

        if TIMEOUT_ERROR_INDICATOR in status_msg.lower():
            next_url = error_data.get(FIELD_NEXT_URL)
            if next_url:
                logger.debug("Received nextUrl from timeout response")
                self._next_url = next_url
                return str(next_url)
        return None

    async def _make_request(self, url: str) -> tuple[int, str]:
        """Fetch the raw response body from the Events API.

        Args:
            url: Request URL.

        Returns:
            Tuple of (status_code, response_text).

        Raises:
            EventsError: If the client is not initialized or the request ultimately fails.
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
                async with self._rate_limiter, self.session.get(url) as response:
                    text = await response.text()
                    status = response.status
            except (ClientError, TimeoutError, OSError) as exc:
                if attempt >= max_attempts:
                    logger.exception(
                        "Request to %s failed after %d attempt(s)",
                        self._mask_url(url),
                        attempt,
                    )
                    msg = "Failed to fetch events from API"
                    raise EventsError(msg) from exc

                logger.warning(
                    "Attempt %d/%d failed for %s: %s",
                    attempt,
                    max_attempts,
                    self._mask_url(url),
                    exc,
                )
                await asyncio.sleep(delay)
                delay = min(delay * self.config.retry_factor, self.config.retry_max_delay)
                continue

            if status in RETRY_STATUS_CODES and attempt < max_attempts:
                logger.debug(
                    "Retrying %s due to status %s (attempt %d/%d)",
                    self._mask_url(url),
                    status,
                    attempt,
                    max_attempts,
                )
                await asyncio.sleep(delay)
                delay = min(delay * self.config.retry_factor, self.config.retry_max_delay)
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
            trimmed = trim_for_log(text)
            logger.error("HTTP error %d: %s", status, trimmed)
            msg = f"HTTP {status}: {trimmed}"
            raise EventsError(msg, status_code=status, response_text=text)

        return False

    @staticmethod
    def _decode_payload(text: str) -> dict[str, Any]:
        """Parse raw response text into a dictionary.

        Args:
            text: HTTP response body.

        Returns:
            Dictionary representation of JSON payload.

        Raises:
            EventsError: If payload cannot be decoded as JSON.
        """
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            msg = f"Invalid JSON response: {exc.msg}"
            logger.exception("Failed to parse JSON response: %s", trim_for_log(text))
            raise EventsError(msg, response_text=text) from exc
        if not isinstance(data, dict):
            msg = "Invalid JSON response: expected an object"
            raise EventsError(msg, response_text=text)
        return data

    def _parse_event_batch(self, payload: dict[str, Any], *, raw_text: str) -> _EventBatch:
        """Validate the JSON payload and capture the next polling URL.

        Args:
            payload: Parsed JSON payload.
            raw_text: Original response body for error messages.

        Returns:
            An ``_EventBatch`` containing validated events and the next URL.
        """
        batch = _build_event_batch(
            payload,
            strict_validation=self.config.strict_validation,
            raw_text=raw_text,
        )

        self._next_url = batch.next_url

        if batch.events:
            logger.debug(
                "Received %d events",
                len(batch.events),
                extra={"event_types": [event.type.value for event in batch.events[:3]]},
            )

        return batch

    async def poll(self) -> list[Event]:
        """Poll for events from the API.

        Thread-safe for concurrent calls from multiple tasks.

        Returns:
            List of Event objects (empty if no events or timeout).
        """
        async with self._polling_lock:
            url = self._build_poll_url()
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("Polling events from %s", self._mask_url(url))

            status, text = await self._make_request(url)

            timeout_handled = self._handle_response_status(status, text)
            if timeout_handled:
                return []

            payload = self._decode_payload(text)
            batch = self._parse_event_batch(payload, raw_text=text)
            return batch.events

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
        """Return an async iterator that streams events until cancellation."""
        return self._poll_continuously()

    def __aiter__(self) -> AsyncIterator[Event]:
        """Enable async iteration for continuous streaming.

        Returns:
            Async iterator yielding Event objects.
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
