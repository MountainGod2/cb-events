"""Asynchronous client for the Chaturbate Events API."""

import json
import logging
from collections.abc import AsyncIterator
from http import HTTPStatus
from types import TracebackType
from typing import Any, Self

from aiohttp import ClientError, ClientSession, ClientTimeout
from aiohttp_retry import ExponentialRetry, RetryClient
from aiolimiter import AsyncLimiter

from .constants import (
    AUTH_ERROR_STATUSES,
    BASE_URL,
    DEFAULT_RETRY_ATTEMPTS,
    DEFAULT_RETRY_BACKOFF,
    DEFAULT_RETRY_EXPONENTIAL_BASE,
    DEFAULT_RETRY_MAX_DELAY,
    DEFAULT_TIMEOUT,
    RATE_LIMIT_MAX_RATE,
    RATE_LIMIT_TIME_PERIOD,
    TESTBED_URL,
    TIMEOUT_ERROR_INDICATOR,
    TOKEN_MASK_LENGTH,
)
from .exceptions import AuthError, EventsError
from .models import Event

logger = logging.getLogger(__name__)
"""Module-level logger for the EventClient."""


class EventClient:
    """HTTP client for polling Chaturbate Events API."""

    # pylint: disable=too-many-arguments
    def __init__(
        self,
        username: str,
        token: str,
        *,
        timeout: int = DEFAULT_TIMEOUT,
        use_testbed: bool = False,
        retry_attempts: int = DEFAULT_RETRY_ATTEMPTS,
        retry_backoff: float = DEFAULT_RETRY_BACKOFF,
        retry_exponential_base: float = DEFAULT_RETRY_EXPONENTIAL_BASE,
        retry_max_delay: float = DEFAULT_RETRY_MAX_DELAY,
    ) -> None:
        """Initialize the EventClient with credentials and connection settings.

        Args:
            username: Chaturbate username for authentication.
            token: Authentication token with Events API scope.
            timeout: Request timeout in seconds. Defaults to 10.
            use_testbed: Whether to use the testbed API endpoint. Defaults to False.
            retry_attempts: Maximum number of retry attempts. Defaults to 8.
            retry_backoff: Initial retry backoff in seconds. Defaults to 1.0.
            retry_exponential_base: Base for exponential backoff. Defaults to 2.0.
            retry_max_delay: Maximum delay between retries in seconds. Defaults to 30.0.

        Raises:
            ValueError: If username or token is empty or contains only whitespace.
        """
        if not username.strip():
            msg = "Username cannot be empty"
            raise ValueError(msg)
        if not token.strip():
            msg = "Token cannot be empty"
            raise ValueError(msg)

        self.username = username.strip()
        self.token = token.strip()
        self.timeout = timeout
        self.base_url = TESTBED_URL if use_testbed else BASE_URL
        self.session: ClientSession | None = None
        self.retry_client: RetryClient | None = None
        self._next_url: str | None = None
        self._rate_limiter = AsyncLimiter(
            max_rate=RATE_LIMIT_MAX_RATE, time_period=RATE_LIMIT_TIME_PERIOD
        )

        self._retry_options = ExponentialRetry(
            attempts=retry_attempts,
            start_timeout=retry_backoff,
            max_timeout=retry_max_delay,
            factor=retry_exponential_base,
            statuses={
                HTTPStatus.INTERNAL_SERVER_ERROR,
                HTTPStatus.BAD_GATEWAY,
                HTTPStatus.SERVICE_UNAVAILABLE,
                HTTPStatus.GATEWAY_TIMEOUT,
                HTTPStatus.TOO_MANY_REQUESTS,
            },
        )

    def __repr__(self) -> str:
        """Return string representation with masked authentication token.

        Returns:
            A string representation showing username and masked token for security.
        """
        masked_token = self._mask_token(self.token)
        return f"EventClient(username='{self.username}', token='{masked_token}')"

    @staticmethod
    def _mask_token(token: str) -> str:
        """Mask authentication token showing only the last 4 characters.

        Args:
            token: The authentication token to mask.

        Returns:
            The masked token string with asterisks replacing all but the last
            4 characters.
        """
        if len(token) <= TOKEN_MASK_LENGTH:
            return "*" * len(token)
        return "*" * (len(token) - TOKEN_MASK_LENGTH) + token[-TOKEN_MASK_LENGTH:]

    def _mask_url(self, url: str) -> str:
        """Mask authentication token in URL for secure logging.

        Args:
            url: The URL containing the authentication token.

        Returns:
            The URL with the authentication token masked for safe logging.
        """
        return url.replace(self.token, self._mask_token(self.token))

    async def __aenter__(self) -> Self:
        """Initialize HTTP session for async context manager.

        Returns:
            The EventClient instance with an active HTTP session.
        """
        if self.session is None or self.session.closed:
            self.session = ClientSession(
                timeout=ClientTimeout(total=self.timeout + 5),
            )
            self.retry_client = RetryClient(
                client_session=self.session, retry_options=self._retry_options
            )
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Clean up HTTP session and resources on context manager exit."""
        await self.close()

    def _build_poll_url(self) -> str:
        """Build the polling URL for the next request.

        Returns:
            The URL to use for the next polling request.
        """
        if self._next_url:
            return self._next_url
        return f"{self.base_url}/{self.username}/{self.token}/?timeout={self.timeout}"

    def _handle_auth_error(self, status_code: int) -> None:
        """Handle authentication errors from API responses.

        Args:
            status_code: The HTTP status code from the response.

        Raises:
            AuthError: If the status code indicates an authentication failure.
        """
        logger.warning(
            "Authentication failed for user %s",
            self.username,
            extra={"status_code": status_code},
        )
        msg = f"Authentication failed for {self.username}"
        raise AuthError(msg)

    def _handle_timeout_response(self, text: str) -> bool:
        """Handle timeout responses and extract nextUrl.

        Args:
            text: The response text to check for timeout indicators.

        Returns:
            True if this was a timeout response that was handled, False otherwise.
        """
        if next_url := self._extract_next_url(text):
            logger.debug("Received nextUrl from timeout response")
            self._next_url = next_url
            return True
        return False

    def _parse_response_data(self, resp_data: dict[str, Any]) -> list[Event]:
        """Parse API response data into Event objects.

        Args:
            resp_data: The parsed JSON response data.

        Returns:
            List of Event objects from the response.
        """
        self._next_url = resp_data["nextUrl"]
        events = [Event.model_validate(item) for item in resp_data.get("events", [])]
        logger.debug(
            "Received %d events",
            len(events),
            extra={"event_types": [event.type.value for event in events[:3]]} if events else {},
        )
        return events

    async def poll(self) -> list[Event]:
        """Execute a single poll request and return parsed events.

        Makes an HTTP request to the Events API and parses the response into
        Event objects. Handles authentication errors, timeouts, and maintains
        the polling state with nextUrl for subsequent requests.

        Returns:
            A list of Event objects parsed from the API response. May be empty
            if no events are available or on timeout.

        Raises:
            EventsError: For network errors, timeouts, or invalid JSON responses.
        """
        if self.session is None or self.retry_client is None:
            msg = "Session not initialized - use async context manager"
            raise EventsError(msg)

        url = self._build_poll_url()
        logger.debug("Polling events from %s", self._mask_url(url))

        try:
            async with self._rate_limiter, self.retry_client.get(url) as resp:
                text = await resp.text()

                if resp.status in AUTH_ERROR_STATUSES:
                    self._handle_auth_error(resp.status)

                if resp.status == HTTPStatus.BAD_REQUEST and self._handle_timeout_response(text):
                    return []

                if resp.status != HTTPStatus.OK:
                    logger.error("HTTP error %d: %s", resp.status, text[:200])
                    msg = f"HTTP {resp.status}: {text[:200]}"
                    raise EventsError(
                        msg,
                        status_code=resp.status,
                        response_text=text,
                    )

                try:
                    data = await resp.json()
                except json.JSONDecodeError as json_err:
                    logger.exception(
                        "Invalid JSON response received",
                        extra={
                            "status_code": resp.status,
                            "response_preview": text[:100],
                        },
                    )
                    msg = f"Invalid JSON response: {json_err}"
                    raise EventsError(
                        msg,
                        status_code=resp.status,
                        response_text=text,
                    ) from json_err

                return self._parse_response_data(data)

        except TimeoutError as err:
            logger.warning("Request timeout after %ds", self.timeout)
            msg = f"Request timeout after {self.timeout}s"
            raise EventsError(msg) from err
        except ClientError as err:
            logger.exception(
                "Network error occurred",
                extra={"error_type": type(err).__name__},
            )
            msg = f"Network error: {err}"
            raise EventsError(msg) from err

    @staticmethod
    def _extract_next_url(text: str) -> str | None:
        """Extract nextUrl from timeout error response.

        Args:
            text: The response text containing potential error data with nextUrl.

        Returns:
            The extracted nextUrl string if present in a timeout error response,
            otherwise None.
        """
        error_data = json.loads(text)
        if TIMEOUT_ERROR_INDICATOR in error_data.get("status", "").lower():
            next_url = error_data.get("nextUrl")
            return str(next_url) if next_url else None
        return None

    async def poll_continuously(self) -> AsyncIterator[Event]:
        """Continuously poll the API and yield events as they arrive.

        Creates an infinite loop that polls the Events API and yields individual
        events. This method maintains the polling state and handles the nextUrl
        mechanism automatically.

        Yields:
            Event objects as they are received from the API.
        """
        while True:
            events = await self.poll()
            for event in events:
                yield event

    def __aiter__(self) -> AsyncIterator[Event]:
        """Enable async iteration over the client for continuous event streaming.

        Returns:
            An async iterator that yields Event objects continuously from the API.
        """
        return self.poll_continuously()

    async def close(self) -> None:
        """Close the HTTP session and reset polling state.

        Closes the aiohttp ClientSession and resets the nextUrl state.
        Safe to call multiple times.
        """
        if self.retry_client:
            await self.retry_client.close()
            self.retry_client = None
        if self.session:
            await self.session.close()
            self.session = None
        self._next_url = None
