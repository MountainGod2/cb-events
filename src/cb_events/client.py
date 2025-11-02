"""HTTP client for the Chaturbate Events API.

Connects to the Events API to stream real-time events with automatic retries,
rate limiting, and secure credential handling.
"""

import asyncio
import json
import logging
from collections.abc import AsyncIterator
from http import HTTPStatus
from types import TracebackType
from typing import Any, Self
from urllib.parse import quote

from aiohttp import ClientSession, ClientTimeout
from aiohttp.client_exceptions import ClientError
from aiohttp_retry import ExponentialRetry, RetryClient
from aiolimiter import AsyncLimiter

from ._parsing import EventBatch, build_event_batch
from ._utils import mask_secret, mask_secret_in_url, trim_for_log
from .config import EventClientConfig
from .constants import (
    AUTH_ERROR_STATUSES,
    BASE_URL,
    CLOUDFLARE_ERROR_CODES,
    FIELD_NEXT_URL,
    FIELD_STATUS,
    RATE_LIMIT_MAX_RATE,
    RATE_LIMIT_TIME_PERIOD,
    SESSION_TIMEOUT_BUFFER,
    TESTBED_URL,
    TIMEOUT_ERROR_INDICATOR,
    URL_TEMPLATE,
)
from .exceptions import AuthError, EventsError
from .models import Event

logger = logging.getLogger(__name__)
"""Logger for client module."""


class EventClient:
    """HTTP client for polling the Chaturbate Events API.

    Streams events with automatic retries, rate limiting, and credential handling.
    Use as an async context manager or iterate for continuous streaming.

    Thread safety:
        Poll state is protected by a lock, so poll() can be called from multiple
        tasks. Best practice is one polling task per client.

    Rate limiting:
        Each client has its own rate limiter (2000 req/60s). Share a rate limiter
        across clients by passing the same AsyncLimiter instance:

        .. code-block:: python

            from aiolimiter import AsyncLimiter
            from cb_events import EventClient

            shared_limiter = AsyncLimiter(max_rate=2000, time_period=60)

            async with EventClient(
                "user1", "token1", config=config, rate_limiter=shared_limiter
            ) as client1, EventClient(
                "user2", "token2", config=config, rate_limiter=shared_limiter
            ) as client2:
                events1 = await client1.poll()
                events2 = await client2.poll()

    Attributes:
        username: Chaturbate username for authentication.
        token: Authentication token with Events API scope.
        config: Client configuration settings.
        timeout: Request timeout in seconds.
        base_url: API base URL (production or testbed).
        session: HTTP session for requests.
        retry_client: Retry-enabled HTTP client.
    """

    def __init__(
        self,
        username: str,
        token: str,
        *,
        config: EventClientConfig | None = None,
        rate_limiter: AsyncLimiter | None = None,
    ) -> None:
        """Initialize the client with credentials and settings.

        Args:
            username: Chaturbate username.
            token: Events API authentication token.
            config: Client settings. Defaults to EventClientConfig().
            rate_limiter: Rate limiter instance. Defaults to 2000 req/60s.
                Share across clients to pool rate limits.

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
        self.retry_client: RetryClient | None = None
        self._next_url: str | None = None
        self._polling_lock = asyncio.Lock()
        self._rate_limiter = rate_limiter or AsyncLimiter(
            max_rate=RATE_LIMIT_MAX_RATE,
            time_period=RATE_LIMIT_TIME_PERIOD,
        )

        self._retry_options = ExponentialRetry(
            attempts=self.config.retry_attempts,
            start_timeout=self.config.retry_backoff,
            max_timeout=self.config.retry_max_delay,
            factor=self.config.retry_factor,
            statuses={
                HTTPStatus.INTERNAL_SERVER_ERROR,
                HTTPStatus.BAD_GATEWAY,
                HTTPStatus.SERVICE_UNAVAILABLE,
                HTTPStatus.GATEWAY_TIMEOUT,
                HTTPStatus.TOO_MANY_REQUESTS,
                *CLOUDFLARE_ERROR_CODES,
            },
        )

    def __repr__(self) -> str:
        """Return string representation with masked token.

        Returns:
            String showing username and masked token.
        """
        masked_token = mask_secret(self.token)
        return f"EventClient(username='{self.username}', token='{masked_token}')"

    def _mask_url(self, url: str) -> str:
        """Mask token in URL for logging.

        Args:
            url: URL containing the token.

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
                self.retry_client = RetryClient(
                    client_session=self.session, retry_options=self._retry_options
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
        """Clean up session and resources.

        Args:
            exc_type: Exception type if raised.
            exc_val: Exception value if raised.
            exc_tb: Exception traceback if raised.
        """
        await self.close()

    def _build_poll_url(self) -> str:
        """Build polling URL for next request.

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
            text: Response text with potential nextUrl.

        Returns:
            Extracted nextUrl or None if not found or parsing fails.
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
        """Make HTTP request to the API.

        Args:
            url: Request URL.

        Returns:
            Tuple of (status_code, response_text).

        Raises:
            EventsError: If session is not initialized.
        """
        if self.session is None or self.retry_client is None:
            msg = "Client not initialized - use async context manager"
            raise EventsError(msg)

        try:
            async with self._rate_limiter, self.retry_client.get(url) as resp:
                text = await resp.text()
                return resp.status, text
        except (ClientError, TimeoutError, OSError) as exc:
            logger.exception("Request to %s failed", self._mask_url(url))
            msg = "Failed to fetch events from API"
            raise EventsError(msg) from exc

    def _handle_response_status(self, status: int, text: str) -> bool:
        """Handle response status codes.

        Args:
            status: HTTP status code.
            text: Response text.

        Returns:
            True if timeout was handled and parsing should be skipped, False otherwise.

        Raises:
            AuthError: For auth failures.
            EventsError: For other HTTP errors.
        """
        if status in AUTH_ERROR_STATUSES:
            logger.warning(
                "Authentication failed for user %s",
                self.username,
                extra={"status_code": status},
            )
            msg = f"Authentication failed for {self.username}"
            raise AuthError(msg)

        if status == HTTPStatus.BAD_REQUEST and self._extract_next_url(text):
            return True

        if status != HTTPStatus.OK:
            trimmed = trim_for_log(text)
            logger.error("HTTP error %d: %s", status, trimmed)
            msg = f"HTTP {status}: {trimmed}"
            raise EventsError(
                msg,
                status_code=status,
                response_text=text,
            )

        return False

    @staticmethod
    def _decode_payload(text: str) -> dict[str, Any]:
        """Parse raw response text into a dictionary.

        Args:
            text: HTTP response body received from the Events API.

        Returns:
            Dictionary representation of the JSON payload.

        Raises:
            EventsError: If the payload cannot be decoded as JSON.
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

    def _build_event_batch(self, payload: dict[str, Any], *, raw_text: str) -> EventBatch:
        """Validate the API payload and log diagnostics for event batches.

        Args:
            payload: Parsed JSON payload from the Events API.
            raw_text: Original response body, used when surfacing validation errors.

        Returns:
            EventBatch containing the next polling URL and validated events.
        """
        batch = build_event_batch(
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

        Makes a request and parses the response into Event objects. Handles auth
        errors, timeouts, and maintains nextUrl for subsequent requests.

        Thread-safe for concurrent calls from multiple tasks.

        Returns:
            List of Event objects. Empty if no events or timeout.
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
            batch = self._build_event_batch(payload, raw_text=text)
            return batch.events

    async def _poll_continuously(self) -> AsyncIterator[Event]:
        """Continuously poll and yield events.

        Infinite loop that polls and yields individual events.

        Yields:
            Event objects as received.
        """
        while True:
            events = await self.poll()
            for event in events:
                yield event

    def __aiter__(self) -> AsyncIterator[Event]:
        """Enable async iteration for continuous streaming.

        Returns:
            Async iterator yielding Event objects.
        """
        return self._poll_continuously()

    async def close(self) -> None:
        """Close session and reset state.

        Idempotent - safe to call multiple times.
        """
        try:
            if self.retry_client:
                await self.retry_client.close()
                self.retry_client = None
        except (ClientError, OSError, RuntimeError) as e:
            logger.warning("Error closing retry client: %s", e, exc_info=True)

        try:
            if self.session:
                await self.session.close()
                self.session = None
        except (ClientError, OSError, RuntimeError) as e:
            logger.warning("Error closing session: %s", e, exc_info=True)

        self._next_url = None
