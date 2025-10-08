"""Exception classes for the Chaturbate Events client."""

from .constants import RESPONSE_PREVIEW_LENGTH


class EventsError(Exception):
    """Base exception for all Chaturbate Events API failures.

    This exception serves as the base class for all API-related errors and
    includes enhanced error information such as HTTP status codes and response
    text when available.

    Attributes:
        message: The error message.
        status_code: HTTP status code if available.
        response_text: Response text if available.
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
            message: The error message.
            status_code: HTTP status code if available.
            response_text: Response text if available.
        """
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.response_text = response_text

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
    """Authentication failure with the Events API.

    Raised when API credentials are invalid, missing, or when the user lacks
    sufficient permissions for the requested operation. This typically occurs
    with HTTP 401 (Unauthorized) or 403 (Forbidden) responses.
    """


class RouterError(EventsError):
    """Error that occurred during event routing or handler execution.

    Raised when an event handler fails during dispatch. Contains information
    about the event that was being processed and the original exception that
    occurred in the handler.

    Attributes:
        message: The error message.
        event_type: The type of event being processed when the error occurred.
        handler_name: The name of the handler that failed.
        original_error: The original exception that was raised by the handler.
    """

    def __init__(
        self,
        message: str,
        *,
        event_type: str | None = None,
        handler_name: str | None = None,
        original_error: Exception | None = None,
    ) -> None:
        """Initialize RouterError with handler execution details.

        Args:
            message: The error message.
            event_type: The type of event being processed.
            handler_name: The name of the handler that failed.
            original_error: The original exception raised by the handler.
        """
        super().__init__(message)
        self.event_type = event_type
        self.handler_name = handler_name
        self.original_error = original_error

    def __repr__(self) -> str:
        """Return detailed string representation of the error.

        Returns:
            A string representation including the error message, event type,
            handler name, and original error if available.
        """
        parts = [f"message='{self.message}'"]
        if self.event_type is not None:
            parts.append(f"event_type='{self.event_type}'")
        if self.handler_name is not None:
            parts.append(f"handler_name='{self.handler_name}'")
        if self.original_error is not None:
            parts.append(f"original_error={self.original_error!r}")
        return f"{self.__class__.__name__}({', '.join(parts)})"
