"""Shared utilities for cb-events."""

from typing import Final

TRUNCATE_LENGTH: Final[int] = 200
"""Maximum response_text length kept on exceptions."""


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
