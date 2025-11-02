"""Internal utilities."""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import quote

from .constants import LOG_TEXT_TRUNCATE_LENGTH, TOKEN_MASK_LENGTH

if TYPE_CHECKING:
    from pydantic import ValidationError


def mask_secret(secret: str, *, visible: int = TOKEN_MASK_LENGTH) -> str:
    """Mask a secret while keeping the tail visible.

    Args:
        secret: Value to obfuscate.
        visible: Number of trailing characters to leave unobscured.

    Returns:
        Secret with all but the trailing characters replaced by asterisks.
    """
    if visible <= 0 or len(secret) <= visible:
        return "*" * len(secret)
    hidden = "*" * (len(secret) - visible)
    return f"{hidden}{secret[-visible:]}"


def mask_secret_in_url(url: str, secret: str) -> str:
    """Mask a secret in both raw and percent-encoded forms within a URL.

    Args:
        url: URL that may contain the secret value.
        secret: Secret value to redact.

    Returns:
        URL with the secret replaced by a masked representation.
    """
    masked = mask_secret(secret)
    return url.replace(secret, masked).replace(quote(secret, safe=""), masked)


def format_validation_error_locations(error: ValidationError) -> str:
    """Format validation error locations as a sorted, comma-separated string.

    Args:
        error: Pydantic validation error.

    Returns:
        Comma-separated dotted paths indicating failing fields.
    """
    locations = {
        ".".join(str(entry) for entry in detail.get("loc", ())) or "<root>"
        for detail in error.errors()
    }
    return ", ".join(sorted(locations))


def trim_for_log(text: str, *, limit: int = LOG_TEXT_TRUNCATE_LENGTH) -> str:
    """Truncate text for logging.

    Args:
        text: Raw text to truncate.
        limit: Maximum length of returned string.

    Returns:
        Original text if within limit, otherwise truncated with ellipsis.
    """
    if len(text) <= limit:
        return text
    ellipsis = "..."
    if limit <= len(ellipsis):
        return ellipsis[:limit]
    return f"{text[: limit - len(ellipsis)]}{ellipsis}"
