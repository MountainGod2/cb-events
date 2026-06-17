"""Client configuration model for EventClient.

Defines immutable settings for polling timeout, retries, and event
validation behavior.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from pydantic import BaseModel, ConfigDict, Field, model_validator

if TYPE_CHECKING:
    from typing_extensions import Self


class ClientConfig(BaseModel):
    """Immutable settings for EventClient.

    Controls long-poll timeout, retry backoff, and strict validation mode.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    timeout: int = Field(default=10, gt=0)
    """Server long-poll timeout in seconds."""

    strict_validation: bool = False
    """Raise on invalid events vs. skip and log."""

    retry_attempts: int = Field(default=20, ge=1)
    """Total attempts including the initial request (must be >= 1)."""

    retry_backoff: float = Field(default=1.0, ge=0)
    """Initial retry delay in seconds."""

    retry_factor: float = Field(default=2.0, gt=0)
    """Backoff multiplier applied after each retry."""

    retry_max_delay: float = Field(default=60.0, ge=0)
    """Maximum delay between retries in seconds."""

    @model_validator(mode="after")
    def validate_delays(self) -> Self:
        """Validate retry delay bounds.

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
        return self
