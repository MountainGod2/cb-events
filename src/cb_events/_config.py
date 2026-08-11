"""Client configuration model for EventClient.

Defines immutable settings for polling timeout, retries, and event
validation behavior.
"""

from __future__ import annotations

from http import HTTPStatus
from typing import TYPE_CHECKING, ClassVar, Final

from pydantic import BaseModel, ConfigDict, Field, model_validator

if TYPE_CHECKING:
    from typing import Self


_ALLOWED_AUTH_RETRY_STATUS_CODES: Final[frozenset[int]] = frozenset({
    HTTPStatus.UNAUTHORIZED.value,
    HTTPStatus.FORBIDDEN.value,
})


class ClientConfig(BaseModel):
    """Immutable settings for EventClient.

    Controls long-poll timeout, retry backoff, and strict validation mode.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    timeout: int = Field(default=10, gt=0)
    """Server long-poll timeout in seconds."""

    strict_validation: bool = False
    """Raise on invalid events vs. skip and log."""

    retry_attempts: int = Field(default=25, ge=1)
    """Total attempts including the initial request (must be >= 1)."""

    retry_backoff: float = Field(default=1.0, ge=0)
    """Initial retry delay in seconds."""

    retry_factor: float = Field(default=2.0, gt=0)
    """Backoff multiplier applied after each retry."""

    retry_max_delay: float = Field(default=300.0, ge=0)
    """Maximum delay between retries in seconds."""

    auth_retry_attempts: int = Field(default=1, ge=1)
    """Total auth-status attempts before returning the final 401/403."""

    auth_retry_delay: float = Field(default=0.0, ge=0)
    """Fixed delay in seconds between auth-status retry attempts."""

    auth_retry_status_codes: frozenset[int] = frozenset({
        HTTPStatus.UNAUTHORIZED.value,
        HTTPStatus.FORBIDDEN.value,
    })
    """HTTP status codes eligible for auth-status retry behavior."""

    @model_validator(mode="after")
    def _validate_config(self) -> Self:
        """Validate configuration.

        Returns:
            Validated configuration instance.

        Raises:
            ValueError: If retry_max_delay is smaller than retry_backoff.
        """
        if self.retry_max_delay < self.retry_backoff:
            msg = (
                f"retry_max_delay ({self.retry_max_delay}) must be >= "
                f"retry_backoff ({self.retry_backoff})."
            )
            raise ValueError(msg)

        invalid_auth_codes = self.auth_retry_status_codes - _ALLOWED_AUTH_RETRY_STATUS_CODES
        if invalid_auth_codes:
            allowed = ", ".join(str(code) for code in sorted(_ALLOWED_AUTH_RETRY_STATUS_CODES))
            invalid = ", ".join(str(code) for code in sorted(invalid_auth_codes))
            msg = (
                "auth_retry_status_codes may only include authentication statuses "
                f"({allowed}); got: {invalid}."
            )
            raise ValueError(msg)

        return self
