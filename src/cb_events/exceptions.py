"""Exceptions for the Chaturbate Events client.

This module defines the exception hierarchy for API errors:

    EventsError: Base exception for all API failures.
    AuthError: Authentication failures (HTTP 401/403).
    HttpStatusError: Generic HTTP status failures.
    ClientRequestError: HTTP 4xx failures (except auth/rate limit).
    RateLimitError: HTTP 429 failures.
    ServerError: HTTP 5xx and Cloudflare 52x failures.

Example:
    Handling API errors::

        from cb_events import EventClient, AuthError, EventsError

        try:
            async with EventClient("user", "token") as client:
                async for event in client:
                    pass
        except AuthError as e:
            print(f"Authentication failed: {e}")
        except EventsError as e:
            print(f"API error (HTTP {e.status_code}): {e}")
"""

from __future__ import annotations

from typing import Final

from typing_extensions import override

AUTH_ERROR_STATUS_CODES: Final[frozenset[int]] = frozenset({401, 403})
"""HTTP status codes indicating authentication failures."""

TRUNCATE_LENGTH: Final[int] = 200
"""Maximum characters stored in response_text to limit PII exposure in logs."""

_RATE_LIMIT_STATUS_CODE: Final[int] = 429
"""HTTP status code indicating rate-limiting failures."""


def truncate_text(text: str, *, limit: int = TRUNCATE_LENGTH) -> str:
    """Truncate text with ellipsis if it exceeds the limit.

    Args:
        text: Text to truncate.
        limit: Maximum number of characters to retain.

    Returns:
        Text truncated to ``limit`` characters with ellipsis if needed.
    """
    if len(text) <= limit:
        return text
    return f"{text[:limit]}..."


class EventsError(Exception):
    """Base exception for API failures with optional HTTP metadata.

    Raised for network errors, invalid responses, rate limiting, and other
    non-authentication failures. Includes HTTP status code and response body
    when available.

    Example:
        Inspecting error details::

            try:
                events = await client.poll()
            except EventsError as e:
                if e.status_code == 429:
                    print("Rate limited, backing off...")
                print(f"Response: {e.response_text}")
    """

    __slots__: tuple[str, ...] = ("response_text", "status_code")

    status_code: int | None
    """HTTP status code if available."""

    response_text: str | None
    """Raw response body, truncated to 200 characters to limit PII in logs."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        response_text: str | None = None,
    ) -> None:
        """Initialize error with message and optional HTTP details.

        Args:
            message: Human-readable description of the failure.
            status_code: Optional HTTP status code returned by the API.
            response_text: Optional raw response body. Truncated to
                200 characters to reduce PII exposure in structured
                exception loggers and error-reporting tools.
        """
        super().__init__(message)
        self.status_code = status_code
        self.response_text = (
            truncate_text(response_text)
            if response_text is not None
            else response_text
        )

    @override
    def __str__(self) -> str:
        """Return error message with HTTP status if available.

        Returns:
            Message string with optional HTTP status suffix.
        """
        if self.status_code is not None:
            return f"{super().__str__()} (HTTP {self.status_code})"
        return super().__str__()


class AuthError(EventsError):
    """Authentication failure from the Events API.

    Raised when the API returns HTTP 401 (Unauthorized) or 403 (Forbidden),
    typically indicating invalid credentials or an expired token.

    Also raised during client initialization if username or token is empty
    or contains invalid whitespace.

    Example:
        Handling authentication errors::

            try:
                async with EventClient("user", "invalid_token") as client:
                    await client.poll()
            except AuthError:
                print("Invalid credentials - regenerate token")
    """

    __slots__: tuple[str, ...] = ()


class HttpStatusError(EventsError):
    """Base error for non-authentication HTTP status code failures."""

    __slots__: tuple[str, ...] = ()


class ClientRequestError(HttpStatusError):
    """HTTP 4xx request failure (excluding auth and rate limiting)."""

    __slots__: tuple[str, ...] = ()


class RateLimitError(HttpStatusError):
    """HTTP 429 rate-limiting failure."""

    __slots__: tuple[str, ...] = ()


class ServerError(HttpStatusError):
    """HTTP 5xx server-side failure."""

    __slots__: tuple[str, ...] = ()


def build_http_error(
    message: str,
    *,
    status_code: int,
    response_text: str | None = None,
) -> EventsError:
    """Build the most specific HTTP status error for a status code.

    Args:
        message: Human-readable failure message.
        status_code: HTTP status code returned by the API.
        response_text: Optional response body.

    Returns:
        An instance of the most specific EventsError subclass matching the
        status code, with message and HTTP details included.
    """
    if status_code in AUTH_ERROR_STATUS_CODES:
        return AuthError(
            message,
            status_code=status_code,
            response_text=response_text,
        )
    if status_code == _RATE_LIMIT_STATUS_CODE:
        return RateLimitError(
            message,
            status_code=status_code,
            response_text=response_text,
        )
    if 400 <= status_code < 500:  # noqa: PLR2004
        return ClientRequestError(
            message,
            status_code=status_code,
            response_text=response_text,
        )
    if 500 <= status_code < 600:  # noqa: PLR2004
        return ServerError(
            message,
            status_code=status_code,
            response_text=response_text,
        )
    return HttpStatusError(
        message,
        status_code=status_code,
        response_text=response_text,
    )
