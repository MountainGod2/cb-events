"""Exception hierarchy for cb_events.

Defines structured client and HTTP error types with optional status code and
truncated response text.
"""

from __future__ import annotations

from http import HTTPStatus
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from typing_extensions import override
else:
    try:
        from typing import override
    except ImportError:  # pragma: no cover
        from typing_extensions import override

AUTH_ERROR_STATUS_CODES: Final[frozenset[int]] = frozenset({
    HTTPStatus.UNAUTHORIZED.value,
    HTTPStatus.FORBIDDEN.value,
})
"""Status codes mapped to AuthError."""

CF_SERVER_ERROR_CODES: Final[frozenset[int]] = frozenset({521, 522, 523, 524})
"""Cloudflare status codes treated as server failures."""

TRUNCATE_LENGTH: Final[int] = 200
"""Maximum response_text length kept on exceptions."""

_RATE_LIMIT_STATUS_CODE: Final[int] = HTTPStatus.TOO_MANY_REQUESTS.value
"""Status code mapped to RateLimitError."""


def truncate_text(text: str, *, limit: int = TRUNCATE_LENGTH) -> str:
    """Truncate text with ellipsis if it exceeds the limit.

    Args:
        text: Text to truncate.
        limit: Maximum number of characters to retain.

    Returns:
        Text truncated to limit characters with ellipsis when needed.

    Raises:
        ValueError: If limit is negative.
    """
    if limit < 0:
        msg = f"truncate_text() limit must be non-negative, got {limit}"
        raise ValueError(msg)
    if len(text) <= limit:
        return text
    return f"{text[:limit]}..."


class EventsError(Exception):
    """Base exception for client and API failures.

    Carries optional HTTP status and response text details when available.
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
            truncate_text(response_text) if response_text is not None else response_text
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
    """Authentication failure.

    Raised for invalid credentials and malformed authentication URL components.
    """

    __slots__: tuple[str, ...] = ()


class HttpStatusError(EventsError):
    """Base error for HTTP status failures other than auth checks."""

    __slots__: tuple[str, ...] = ()


class ClientRequestError(HttpStatusError):
    """HTTP 4xx failure excluding auth and rate limiting."""

    __slots__: tuple[str, ...] = ()


class RateLimitError(HttpStatusError):
    """HTTP 429 failure after retry attempts are exhausted."""

    __slots__: tuple[str, ...] = ()


class ServerError(HttpStatusError):
    """HTTP 5xx or equivalent upstream server failure."""

    __slots__: tuple[str, ...] = ()


def build_http_error(
    message: str,
    *,
    status_code: int,
    response_text: str | None = None,
) -> EventsError:
    """Map a status code to the most specific error type.

    Args:
        message: Human-readable failure message.
        status_code: HTTP status code returned by the API.
        response_text: Optional response body.

    Returns:
        An EventsError subclass instance with message and HTTP details.
    """
    if status_code in AUTH_ERROR_STATUS_CODES:
        return AuthError(message, status_code=status_code, response_text=response_text)
    if status_code == _RATE_LIMIT_STATUS_CODE:
        return RateLimitError(message, status_code=status_code, response_text=response_text)
    if 400 <= status_code < 500:  # noqa: PLR2004
        return ClientRequestError(message, status_code=status_code, response_text=response_text)
    if 500 <= status_code < 600 or status_code in CF_SERVER_ERROR_CODES:  # noqa: PLR2004
        return ServerError(message, status_code=status_code, response_text=response_text)
    return HttpStatusError(message, status_code=status_code, response_text=response_text)
