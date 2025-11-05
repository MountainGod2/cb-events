"""Exceptions for the Chaturbate Events client."""


class EventsError(Exception):
    """Base exception for API failures.

    Attributes:
        status_code: HTTP status code if available.
        response_text: Raw response body if available.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        response_text: str | None = None,
    ) -> None:
        """Initialize error with message and optional HTTP details."""
        super().__init__(message)
        self.status_code = status_code
        self.response_text = response_text

    def __str__(self) -> str:
        """Return error message with HTTP status if available."""
        if self.status_code:
            return f"{super().__str__()} (HTTP {self.status_code})"
        return super().__str__()


class AuthError(EventsError):
    """Authentication failure (401/403)."""
