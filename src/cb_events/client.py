"""HTTP client for the Chaturbate Events API."""

import asyncio
import json
import logging
from collections.abc import AsyncGenerator, AsyncIterator, Mapping
from http import HTTPStatus
from types import TracebackType
from typing import Any, Self
from urllib.parse import quote

from aiohttp import ClientSession, ClientTimeout
from aiohttp.client_exceptions import ClientError
from aiolimiter import AsyncLimiter
from pydantic import ValidationError

from .config import ClientConfig
from .exceptions import AuthError, EventsError
from .models import Event

# API endpoints
BASE_URL = "https://eventsapi.chaturbate.com/events"
TESTBED_URL = "https://events.testbed.cb.dev/events"

# Default rate limiting (per client instance)
DEFAULT_MAX_RATE = 2000
DEFAULT_TIME_PERIOD = 60

# HTTP configuration
SESSION_TIMEOUT_BUFFER = 5
TOKEN_VISIBLE_CHARS = 4
TRUNCATE_LENGTH = 200
AUTH_ERRORS: set[HTTPStatus] = {HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN}
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

logger: logging.Logger = logging.getLogger(__name__)


def _mask_token(token: str, visible: int = TOKEN_VISIBLE_CHARS) -> str:
    """Mask token for logging.

    Returns:
        Masked token with only last few characters visible.
    """
    if visible <= 0 or len(token) <= visible:
        return "*" * len(token)
    return f"{'*' * (len(token) - visible)}{token[-visible:]}"


def _mask_url(url: str, token: str) -> str:
    """Mask token in URL for safe logging.

    Returns:
        URL with masked token.
    """
    masked: str = _mask_token(token)
    return url.replace(token, masked).replace(quote(token, safe=""), masked)


def _parse_events(raw: list[dict[str, Any]], *, strict: bool) -> list[Event]:
    """Parse raw event dictionaries into Event models.

    Returns:
        List of validated Event instances.

    Raises:
        ValidationError: If strict=True and validation fails.
    """
    events: list[Event] = []
    for item in raw:
        try:
            events.append(Event.model_validate(item))
        except ValidationError as exc:
            if strict:
                raise
            event_id: Any = (
                item.get("id", "<unknown>")
                if isinstance(item, Mapping)
                else "<unknown>"
            )
            fields: set[str] = {
                ".".join(str(p) for p in e.get("loc", ())) for e in exc.errors()
            }
            logger.warning(
                "Skipping invalid event %s: %s",
                event_id,
                ", ".join(sorted(fields)),
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
        config: ClientConfig | None = None,
        rate_limiter: AsyncLimiter | None = None,
    ) -> None:
        """Initialize event client with credentials and configuration.

        Raises:
            AuthError: If username or token is invalid.
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

        self.username = username
        self.token = token
        self.config = config or ClientConfig()
        self.timeout = self.config.timeout
        self.base_url = TESTBED_URL if self.config.use_testbed else BASE_URL
        self.session: ClientSession | None = None
        self._next_url: str | None = None
        self._polling_lock = asyncio.Lock()
        self._rate_limiter = rate_limiter or AsyncLimiter(
            max_rate=DEFAULT_MAX_RATE,
            time_period=DEFAULT_TIME_PERIOD,
        )

    def __repr__(self) -> str:
        """Return string representation with masked token."""
        return (
            f"EventClient(username='{self.username}', "
            f"token='{_mask_token(self.token)}')"
        )

    async def __aenter__(self) -> Self:
        """Initialize HTTP session on context entry.

        Returns:
            The client instance.

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
        """Clean up session on context exit."""
        await self.close()

    def _build_url(self) -> str:
        """Build URL for next poll request.

        Returns:
            URL for the next API request.
        """
        if self._next_url:
            return self._next_url
        return (
            f"{self.base_url}/{quote(self.username, safe='')}/"
            f"{quote(self.token, safe='')}/?timeout={self.timeout}"
        )

    async def _request(self, url: str) -> tuple[int, str]:
        """Make HTTP request with retries.

        Returns:
            Tuple of (status_code, response_text).

        Raises:
            EventsError: If request fails after all retries.
        """
        if self.session is None:
            msg = (
                "Client not initialized - use 'async with EventClient(...)' "
                "context manager to properly initialize the session"
            )
            raise EventsError(msg)

        max_attempts: int = max(1, self.config.retry_attempts)
        delay: float = self.config.retry_backoff
        attempt = 0

        while True:
            attempt += 1
            try:
                async with (
                    self._rate_limiter,
                    self.session.get(url) as response,
                ):
                    status: int = response.status
                    text: str = await response.text()
            except (ClientError, TimeoutError, OSError) as exc:
                if attempt >= max_attempts:
                    logger.exception(
                        "Request failed after %d attempts: %s",
                        attempt,
                        _mask_url(url, self.token),
                    )
                    msg = (
                        f"Failed to fetch events after {max_attempts} "
                        "attempts. Check network connectivity, firewall "
                        "settings, and Chaturbate API status at "
                        "https://status.chaturbate.com"
                    )
                    raise EventsError(msg) from exc

                logger.warning(
                    "Attempt %d/%d failed: %s",
                    attempt,
                    max_attempts,
                    exc,
                )
                await asyncio.sleep(delay)
                delay = min(
                    delay * self.config.retry_factor,
                    self.config.retry_max_delay,
                )
                continue

            if status in RETRY_STATUS_CODES and attempt < max_attempts:
                logger.debug(
                    "Retrying due to status %d (attempt %d/%d)",
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

    def _process_response(self, status: int, text: str) -> list[Event]:
        """Process HTTP response and extract events.

        Returns:
            List of parsed Event instances.

        Raises:
            AuthError: For 401/403 responses.
            EventsError: For other non-OK responses.
        """
        # Handle authentication errors
        if status in AUTH_ERRORS:
            logger.warning("Auth failed for user %s", self.username)
            msg: str = (
                f"Authentication failed for '{self.username}'. "
                "Verify your username and token are correct. "
                "Generate a new token at "
                "https://chaturbate.com/statsapi/authtoken/"
            )
            raise AuthError(msg, status_code=status, response_text=text)

        # Check for timeout response with nextUrl
        if status == HTTPStatus.BAD_REQUEST and self._try_extract_next_url(
            text
        ):
            return []

        # Handle non-OK responses
        if status != HTTPStatus.OK:
            snippet: str = text[:TRUNCATE_LENGTH]
            if len(text) > TRUNCATE_LENGTH:
                snippet += "..."
            logger.error("HTTP %d: %s", status, snippet)

            # Provide status-specific guidance
            if status == HTTPStatus.TOO_MANY_REQUESTS:
                guidance = (
                    " Rate limit exceeded. Reduce request frequency or "
                    "share a rate limiter across multiple clients."
                )
            elif status >= HTTPStatus.INTERNAL_SERVER_ERROR:
                guidance = (
                    " Server error. Check https://status.chaturbate.com "
                    "for API status or retry later."
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

    def _try_extract_next_url(self, text: str) -> bool:
        """Try to extract nextUrl from timeout response.

        Returns:
            True if nextUrl was found and extracted.
        """
        try:
            data: Any = json.loads(text)
            status_msg = data.get("status", "")
            is_timeout: bool = (
                isinstance(status_msg, str)
                and "waited too long" in status_msg.lower()
            )
            if is_timeout:
                next_url = data.get("nextUrl")
                if next_url:
                    logger.debug("Received nextUrl from timeout response")
                    self._next_url = next_url
                    return True
        except (json.JSONDecodeError, KeyError):
            pass
        return False

    def _parse_json_response(self, text: str) -> list[Event]:
        """Parse JSON response and extract events.

        Returns:
            List of parsed Event instances.

        Raises:
            EventsError: If JSON is invalid or response format is wrong.
        """
        try:
            data: Any = json.loads(text)
        except json.JSONDecodeError as exc:
            snippet: str = text[:TRUNCATE_LENGTH]
            if len(text) > TRUNCATE_LENGTH:
                snippet += "..."
            logger.exception("Failed to parse JSON: %s", snippet)
            msg: str = (
                f"Invalid JSON response from API: {exc.msg}. "
                "This may indicate an API outage or unexpected response "
                "format. Check https://status.chaturbate.com for service "
                "status."
            )
            raise EventsError(
                msg,
                response_text=text,
            ) from exc

        if not isinstance(data, dict):
            msg = (
                "Invalid API response format: expected JSON object, got "
                f"{type(data).__name__}. The API may be returning an "
                "unexpected response. Check https://status.chaturbate.com "
                "for service status."
            )
            raise EventsError(
                msg,
                response_text=text,
            )

        # Extract events and nextUrl
        self._next_url = data.get("nextUrl")
        raw_events = data.get("events", [])
        events: list[Event] = _parse_events(
            raw_events, strict=self.config.strict_validation
        )

        if events:
            logger.debug("Received %d events", len(events))

        return events

    async def poll(self) -> list[Event]:
        """Poll the API for new events.

        Safe for concurrent calls (uses internal lock).

        Returns:
            List of events received (empty if timeout or no events).
        """
        async with self._polling_lock:
            url: str = self._build_url()
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("Polling %s", _mask_url(url, self.token))

            status, text = await self._request(url)
            return self._process_response(status, text)

    def __aiter__(self) -> AsyncIterator[Event]:
        """Stream events continuously as an async iterator.

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
