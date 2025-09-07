"""Exception classes for the Chaturbate Events client."""

RESPONSE_PREVIEW_LENGTH = 50


class EventsError(Exception):
    """Base exception for all Chaturbate Events API failures.

    This is the parent class for all exceptions that can be raised
    when interacting with the Events API.

    Attributes:
        message: The error message.
        status_code: HTTP status code if available.
        response_text: Response text if available.
        extra_info: Additional error context.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        response_text: str | None = None,
        **extra_info: float | str | bool | None,
    ) -> None:
        """Initialize EventsError with enhanced error information.

        Args:
            message: The error message.
            status_code: HTTP status code if available.
            response_text: Response text if available.
            **extra_info: Additional error context information.
        """
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.response_text = response_text
        self.extra_info = extra_info

    def __repr__(self) -> str:
        """Return detailed string representation of the error."""
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
        if self.extra_info:
            parts.append(f"extra_info={self.extra_info}")
        return f"{self.__class__.__name__}({', '.join(parts)})"


class AuthError(EventsError):
    """Authentication failure with the Events API.

    Raised when credentials are invalid or insufficient permissions
    are granted for the requested operation.
    """
