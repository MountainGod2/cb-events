"""Exceptions for the Chaturbate Events client."""

_REPR_TEXT_LENGTH = 50


class EventsError(Exception):
    """Base exception for API failures.

    Attributes:
        status_code: HTTP status code if available.
        response_text: Raw API response if available.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        response_text: str | None = None,
    ) -> None:
        """Initialize with error details.

        Args:
            message: Error description.
            status_code: HTTP status code if available.
            response_text: Raw API response if available.
        """
        super().__init__(message)
        self.status_code = status_code
        self.response_text = response_text

    def __str__(self) -> str:
        """Return error message with status code if available."""
        if self.status_code is not None:
            return f"{super().__str__()} (HTTP {self.status_code})"
        return super().__str__()

    def __repr__(self) -> str:
        """Return detailed representation for debugging."""
        parts = [f"message={self.args[0]!r}"]
        if self.status_code is not None:
            parts.append(f"status_code={self.status_code}")
        if self.response_text is not None:
            truncated = self.response_text[:_REPR_TEXT_LENGTH]
            ellipsis = "..." if len(self.response_text) > _REPR_TEXT_LENGTH else ""
            parts.append(f"response_text={truncated!r}{ellipsis}")
        return f"{self.__class__.__name__}({', '.join(parts)})"


class AuthError(EventsError):
    """Authentication or authorization failure (401/403)."""
