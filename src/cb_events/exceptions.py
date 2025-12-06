"""Exceptions for the Chaturbate Events client.

This module defines the exception hierarchy for API errors:

    EventsError: Base exception for all API failures.
    AuthError: Authentication failures (HTTP 401/403).

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

from typing import override


class EventsError(Exception):
    """Base exception for API failures with optional HTTP metadata.

    Raised for network errors, invalid responses, rate limiting, and other
    non-authentication failures. Includes HTTP status code and response body
    when available.

    Attributes:
        status_code: HTTP status code if available, otherwise None.
        response_text: Raw response body if available, otherwise None.

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
    """Raw response body if available."""

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
            response_text: Optional raw response body.
        """
        super().__init__(message)
        self.status_code: int | None = status_code
        self.response_text: str | None = response_text

    @override
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
