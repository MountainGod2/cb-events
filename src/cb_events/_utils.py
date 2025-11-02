"""Internal helpers shared across the library."""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import quote

from .constants import LOG_TEXT_TRUNCATE_LENGTH, TOKEN_MASK_LENGTH

if TYPE_CHECKING:  # pragma: no cover - imported for type checkers only
    from pydantic import ValidationError


def mask_secret(secret: str, *, visible: int = TOKEN_MASK_LENGTH) -> str:
    """Mask a secret while keeping the tail visible.

    Args:
        secret: Value to obfuscate.
        visible: Number of trailing characters to leave unobscured.

    Returns:
        Secret with all but the trailing ``visible`` characters replaced by ``*``.
    """
    if visible <= 0:
        return "*" * len(secret)
    if len(secret) <= visible:
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
    """Render validation error locations as a sorted, comma-separated string.

    Args:
        error: Pydantic validation error raised while parsing API payloads.

    Returns:
        Comma-separated dotted paths that indicate failing fields.
    """
    locations = {
        ".".join(str(entry) for entry in detail.get("loc", ())) or "<root>"
        for detail in error.errors()
    }
    return ", ".join(sorted(locations))


def trim_for_log(text: str, *, limit: int = LOG_TEXT_TRUNCATE_LENGTH) -> str:
    """Shorten log output while signalling truncation.

    Args:
        text: Raw text destined for logs.
        limit: Maximum desired length of the returned string.

    Returns:
        Original text if already within the limit, otherwise a truncated version
        suffixed with an ellipsis.
    """
    if len(text) <= limit:
        return text
    ellipsis = "..."
    if limit <= len(ellipsis):
        return ellipsis[:limit]
    return f"{text[: limit - len(ellipsis)]}{ellipsis}"
