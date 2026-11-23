"""Shared utilities for cb-events."""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Collection

    from yarl import URL

TRUNCATE_LENGTH: Final[int] = 200
"""Maximum response_text length kept on exceptions."""

_ELLIPSIS_LENGTH: Final[int] = 3


class UrlValidationReason(StrEnum):
    """Reason codes emitted by URL validation helpers."""

    SCHEME = "scheme"
    CUSTOM_PORT = "custom_port"
    MISSING_HOST = "missing_host"
    HOST_NOT_ALLOWED = "host_not_allowed"


class UrlValidationError(ValueError):
    """URL validation failure with a stable reason code."""

    reason: UrlValidationReason

    def __init__(self, reason: UrlValidationReason) -> None:
        """Initialize from a structured validation reason."""
        super().__init__(reason.value)
        self.reason = reason


def validate_https_host_no_port(url: URL, allowed_hosts: Collection[str]) -> str:
    """Validate URL scheme/port/host and return normalized host.

    Args:
        url: Parsed URL to validate.
        allowed_hosts: Case-insensitive allow-list of valid hostnames.

    Returns:
        Normalized lowercase host when validation succeeds.

    Raises:
        UrlValidationError: A structured URL validation failure.
    """
    if url.scheme != "https":
        raise UrlValidationError(UrlValidationReason.SCHEME)

    if url.explicit_port is not None:
        raise UrlValidationError(UrlValidationReason.CUSTOM_PORT)

    host = url.host
    if not host:
        raise UrlValidationError(UrlValidationReason.MISSING_HOST)

    normalized_host = host.lower()
    if normalized_host not in {allowed_host.lower() for allowed_host in allowed_hosts}:
        raise UrlValidationError(UrlValidationReason.HOST_NOT_ALLOWED)

    return normalized_host


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
    if limit <= _ELLIPSIS_LENGTH:
        return "." * limit
    return f"{text[: limit - _ELLIPSIS_LENGTH]}..."
