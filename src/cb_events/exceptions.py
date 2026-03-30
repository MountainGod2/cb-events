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

from typing import Final

_RESPONSE_TEXT_LIMIT: Final[int] = 200
"""Maximum characters stored in response_text to limit PII exposure in logs."""

RATE_LIMIT_STATUS_CODE: Final[int] = 429
"""HTTP status code for rate limiting."""

CLIENT_ERROR_MIN_STATUS_CODE: Final[int] = 400
"""Lower bound for HTTP client error status codes."""

CLIENT_ERROR_MAX_STATUS_CODE: Final[int] = 499
"""Upper bound for HTTP client error status codes."""

SERVER_ERROR_MIN_STATUS_CODE: Final[int] = 500
"""Lower bound for HTTP server error status codes."""

SERVER_ERROR_MAX_STATUS_CODE: Final[int] = 599
"""Upper bound for HTTP server error status codes."""

_CLOUDFLARE_SERVER_ERRORS: Final[frozenset[int]] = frozenset({
    521,
    522,
    523,
    524,
})
"""Cloudflare-origin status codes treated as upstream server errors."""


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
            f"{response_text[:_RESPONSE_TEXT_LIMIT]}..."
            if response_text is not None
            and len(response_text) > _RESPONSE_TEXT_LIMIT
            else response_text
        )

    def __str__(self) -> str:
        """Return error message with HTTP status if available.

        Returns:
            Message string with optional HTTP status suffix.
        """
        if self.status_code:
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
    """HTTP 5xx or Cloudflare 52x server-side failure."""

    __slots__: tuple[str, ...] = ()


def build_http_error(
    message: str,
    *,
    status_code: int,
    response_text: str | None = None,
) -> HttpStatusError:
    """Build the most specific HTTP status error for a status code.

    Args:
        message: Human-readable failure message.
        status_code: HTTP status code returned by the API.
        response_text: Optional response body.

    Returns:
        A specialized HttpStatusError subclass instance.
    """
    if status_code == RATE_LIMIT_STATUS_CODE:
        return RateLimitError(
            message,
            status_code=status_code,
            response_text=response_text,
        )

    if (
        CLIENT_ERROR_MIN_STATUS_CODE
        <= status_code
        <= CLIENT_ERROR_MAX_STATUS_CODE
    ):
        return ClientRequestError(
            message,
            status_code=status_code,
            response_text=response_text,
        )

    if (
        SERVER_ERROR_MIN_STATUS_CODE
        <= status_code
        <= SERVER_ERROR_MAX_STATUS_CODE
        or status_code in _CLOUDFLARE_SERVER_ERRORS
    ):
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
