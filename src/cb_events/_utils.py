"""Shared utilities for cb-events."""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, Literal, TypeAlias

if TYPE_CHECKING:
    from collections.abc import Collection

    from yarl import URL

TRUNCATE_LENGTH: Final[int] = 200
"""Maximum response_text length kept on exceptions."""

_ELLIPSIS_LENGTH: Final[int] = 3

UrlValidationReason: TypeAlias = Literal[
    "user_info",
    "scheme",
    "custom_port",
    "missing_host",
    "host_not_allowed",
]


def validate_https_url(
    url: URL,
    *,
    allowed_hosts: Collection[str],
) -> UrlValidationReason | None:
    """Validate HTTPS URL credentials, port, host, and allow-list."""
    if url.user is not None or url.password is not None:
        return "user_info"
    if url.scheme != "https":
        return "scheme"
    if url.explicit_port is not None:
        return "custom_port"
    if not url.host:
        return "missing_host"
    if url.host.lower() not in {host.lower() for host in allowed_hosts}:
        return "host_not_allowed"
    return None


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
