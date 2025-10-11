"""Exception classes for the Chaturbate Events client."""

from .constants import RESPONSE_PREVIEW_LENGTH
from .models import EventType


class EventsError(Exception):
    """Base exception for all Chaturbate Events API failures.

    This exception serves as the base class for all API-related errors and
    includes enhanced error information such as HTTP status codes and response
    text when available.

    Attributes:
        message: The error message describing what went wrong.
        status_code: HTTP status code from the failed request, if available.
        response_text: Raw response text from the API, if available.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        response_text: str | None = None,
    ) -> None:
        """Initialize EventsError with enhanced error information.

        Args:
            message: The error message describing what went wrong.
            status_code: HTTP status code from the failed request, if available.
            response_text: Raw response text from the API, if available.
        """
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.response_text = response_text

    def __str__(self) -> str:
        """Return user-friendly string representation of the error.

        Returns:
            The error message, optionally including the status code.
        """
        if self.status_code is not None:
            return f"{self.message} (HTTP {self.status_code})"
        return self.message

    def __repr__(self) -> str:
        """Return detailed string representation of the error.

        Returns:
            A string representation including the error message, status code,
            and a preview of the response text if available.
        """
        parts = [f"message='{self.message}'"]
        if self.status_code is not None:
            parts.append(f"status_code={self.status_code}")
        if self.response_text:
            preview = (
                self.response_text[:RESPONSE_PREVIEW_LENGTH] + "..."
                if len(self.response_text) > RESPONSE_PREVIEW_LENGTH
                else self.response_text
            )
            parts.append(f"response_text='{preview}'")
        return f"{self.__class__.__name__}({', '.join(parts)})"


class AuthError(EventsError):
    """Authentication or authorization failure with the Events API.

    Raised when API credentials are invalid, missing, expired, or when the user
    lacks sufficient permissions for the requested operation. This typically
    occurs with HTTP 401 (Unauthorized) or 403 (Forbidden) responses.

    Examples:
        >>> raise AuthError("Invalid API token")
        >>> raise AuthError("Authentication failed", status_code=401)
    """


class RouterError(Exception):
    """Error occurring in event handlers during dispatch.

    This exception wraps errors that occur while processing events through
    registered handlers, providing context about which handler failed and
    what event type was being processed. The original exception is preserved
    via exception chaining.

    Attributes:
        message: Description of what went wrong in the handler.
        event_type: The type of event being processed when the error occurred.
        handler_name: The name of the handler function where the error occurred.

    Note:
        This exception is always raised with exception chaining (`from` clause)
        to preserve the original exception traceback.
    """

    def __init__(
        self,
        message: str,
        *,
        event_type: EventType | None = None,
        handler_name: str | None = None,
    ) -> None:
        """Initialize RouterError with context about the handler failure.

        Args:
            message: Description of what went wrong in the handler.
            event_type: The type of event being processed when the error occurred.
            handler_name: The name of the handler function where the error occurred.
        """
        super().__init__(message)
        self.message = message
        self.event_type = event_type
        self.handler_name = handler_name

    def __str__(self) -> str:
        """Return user-friendly string representation of the error.

        Returns:
            The error message, optionally including event type and handler name.
        """
        parts = [self.message]
        if self.event_type is not None:
            parts.append(f"event_type={self.event_type.value}")
        if self.handler_name is not None:
            parts.append(f"handler={self.handler_name}")
        return " | ".join(parts)

    def __repr__(self) -> str:
        """Return detailed string representation of the router error.

        Returns:
            A string representation including the error message, event type,
            and handler name if available.
        """
        parts = [f"message='{self.message}'"]
        if self.event_type is not None:
            parts.append(f"event_type={self.event_type.value}")
        if self.handler_name is not None:
            parts.append(f"handler_name='{self.handler_name}'")
        return f"{self.__class__.__name__}({', '.join(parts)})"
