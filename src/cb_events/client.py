"""HTTP client for the Chaturbate Events API."""

import asyncio
import json
import logging
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
"""HTTP status codes that trigger exponential backoff retries."""

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
        strict: Whether to raise ``ValidationError`` on invalid payloads.

    Returns:
        List of validated :class:`Event` instances.

    Raises:
        ValidationError: If ``strict`` is ``True`` and validation fails.
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

        base_hostname: str = urlparse(self.base_url).hostname or ""
        raw_allowed: list[str] | None = self.config.next_url_allowed_hosts
        allowed_hosts: set[str] = set()
        if raw_allowed:
            for host in raw_allowed:
                host_str: str = str(host).strip()
                if not host_str:
                    continue
                parsed: ParseResult = urlparse(host_str)
                if parsed.hostname:
                    allowed_hosts.add(parsed.hostname.lower())
                else:
                    allowed_hosts.add(host_str.split(":", 1)[0].lower())

        if base_hostname:
            allowed_hosts.add(base_hostname.lower())

        self._allowed_next_hosts: set[str] = allowed_hosts
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
            Tuple of ``(status_code, response_text)``.

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
        delay: float = self.config.retry_backoff
        attempt = 0

        while True:
            attempt += 1
            try:
                async with (
                    self._rate_limiter,
                    self.session.get(url, allow_redirects=False) as response,
                ):
                    status: int = response.status
                    text: str = await response.text()
            except (ClientError, TimeoutError, OSError) as exc:
                if attempt >= max_attempts:
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
                await asyncio.sleep(delay)
                delay = min(
                    delay * self.config.retry_factor,
                    self.config.retry_max_delay,
                )
                continue

            if status in RETRY_STATUS_CODES and attempt < max_attempts:
                retry_msg = (
                    "Retrying HTTP %d for %s (attempt %d/%d, delay %.1fs)"
                )
                logger.debug(
                    retry_msg,
                    status,
                    self.username,
                    attempt,
                    max_attempts,
                    delay,
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

        Args:
            status: HTTP status code received from the API.
            text: Raw response body.

        Returns:
            List of parsed :class:`Event` instances.

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

        if status == HTTPStatus.BAD_REQUEST and self._try_extract_next_url(
            text
        ):
            return []

        if status != HTTPStatus.OK:
            snippet: str = text[:TRUNCATE_LENGTH]
            if len(text) > TRUNCATE_LENGTH:
                snippet += "..."
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
        """Validate the ``nextUrl`` value from API responses.

        Args:
            next_url: Raw ``nextUrl`` value extracted from the API response.
            response_text: Original response body for error diagnostics.

        Returns:
            Sanitized ``nextUrl`` string or ``None`` when no follow-up poll is
            required. Relative URLs are resolved against the current base API
            endpoint.

        Raises:
            EventsError: If ``nextUrl`` is present but not a non-empty string
            or if the URL references a hostname not permitted by
            ``ClientConfig.next_url_allowed_hosts`` (the base API host is
            always permitted).
        """
        if next_url is None:
            return None

        if isinstance(next_url, str):
            stripped: str = next_url.strip()
            if stripped:
                absolute: str = stripped
                parsed: ParseResult = urlparse(stripped)
                if not parsed.scheme and not parsed.netloc:
                    if stripped.startswith("/"):
                        base_for_join: str = f"{self._base_origin.rstrip('/')}/"
                    else:
                        base_for_join = f"{self.base_url.rstrip('/')}/"
                    absolute = urljoin(base_for_join, stripped)
                    parsed = urlparse(absolute)

                hostname: str | None = parsed.hostname or (
                    parsed.netloc or None
                )
                if hostname is None:
                    return absolute

                if hostname.lower() not in self._allowed_next_hosts:
                    logger.error(
                        "Received nextUrl host %s which is not allowed "
                        "for user %s",
                        hostname,
                        self.username,
                    )
                    host_msg: str = _compose_message(
                        "Invalid nextUrl host.",
                        "Allow via ClientConfig.next_url_allowed_hosts.",
                    )
                    raise EventsError(host_msg, response_text=response_text)
                return absolute
            logger.error(
                "Received empty nextUrl from API for user %s",
                self.username,
            )
        else:
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

    def _try_extract_next_url(self, text: str) -> bool:
        """Try to extract ``nextUrl`` from timeout responses.

        Args:
            text: Raw response body from the timeout response.

        Returns:
            ``True`` if ``nextUrl`` was extracted and stored; otherwise
            ``False``.
        """
        try:
            data_obj: object = json.loads(text)
        except (json.JSONDecodeError, KeyError):
            return False

        if not isinstance(data_obj, dict):
            return False

        data_dict = data_obj
        status_msg: object | None = data_dict.get("status")
        is_timeout: bool = (
            isinstance(status_msg, str)
            and "waited too long" in status_msg.lower()
        )
        if is_timeout:
            next_url: object | None = data_dict.get("nextUrl")
            if next_url is None:
                return False

            validated: str | None = self._validate_next_url(
                next_url,
                response_text=text,
            )
            if validated is None:
                return False
            self._next_url = validated
            logger.debug(
                "Received nextUrl from timeout response: %s",
                _mask_url(validated, self.token),
            )
            return True
        return False

    def _parse_json_response(self, text: str) -> list[Event]:
        """Parse JSON response and extract events.

        Args:
            text: Raw HTTP response body expected to contain JSON.

        Returns:
            List of parsed :class:`Event` instances.

        Raises:
            EventsError: If JSON is invalid or response format is wrong.
        """
        try:
            data_obj: object = json.loads(text)
        except json.JSONDecodeError as exc:
            snippet: str = text[:TRUNCATE_LENGTH]
            if len(text) > TRUNCATE_LENGTH:
                snippet += "..."
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
        data_dict = data_obj
        self._next_url = self._validate_next_url(
            data_dict.get("nextUrl"),
            response_text=text,
        )
        if "events" in data_dict:
            raw_events_obj: object = data_dict["events"]
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
            Async iterator yielding :class:`Event` objects.
        """
        return self._stream()

    async def _stream(self) -> AsyncGenerator[Event]:
        """Internal generator for continuous event streaming.

        Yields:
            Event: Objects emitted by the Events API.
        """
        while True:
            events: list[Event] = await self.poll()
            for event in events:
                yield event

    async def close(self) -> None:
        """Close session and reset internal state.

        Safe to call multiple times.
        """
        session: ClientSession | None = self.session
        self.session = None
        if session is not None:
            try:
                await session.close()
            except (ClientError, OSError, RuntimeError) as e:
                logger.warning("Error closing session: %s", e, exc_info=True)

        self._next_url = None
