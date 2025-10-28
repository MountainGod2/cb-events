"""Configuration for the Chaturbate Events API client."""

from typing import Self

from pydantic import BaseModel, Field, model_validator

from .constants import (
    DEFAULT_RETRY_ATTEMPTS,
    DEFAULT_RETRY_BACKOFF,
    DEFAULT_RETRY_FACTOR,
    DEFAULT_RETRY_MAX_DELAY,
    DEFAULT_TIMEOUT,
)


class EventClientConfig(BaseModel):
    """Client configuration settings.

    Immutable after creation. To change settings, create a new config and client.

    Attributes:
        timeout: Request timeout in seconds.
        use_testbed: Use testbed API (https://testbed.cb.dev/) instead of production.
            Testbed provides 100k free tokens, all accounts verified/online, and a
            developer-only environment.
        retry_attempts: Number of retry attempts.
        retry_backoff: Initial backoff time in seconds.
        retry_factor: Exponential backoff multiplier.
        retry_max_delay: Maximum delay between retries in seconds.
    """

    model_config = {"frozen": True}

    timeout: int = Field(default=DEFAULT_TIMEOUT, gt=0)
    use_testbed: bool = False
    retry_attempts: int = Field(default=DEFAULT_RETRY_ATTEMPTS, ge=0)
    retry_backoff: float = Field(default=DEFAULT_RETRY_BACKOFF, ge=0)
    retry_factor: float = Field(default=DEFAULT_RETRY_FACTOR, gt=0)
    retry_max_delay: float = Field(default=DEFAULT_RETRY_MAX_DELAY, ge=0)

    @model_validator(mode="after")
    def validate_retry_delays(self) -> Self:
        """Validate retry_max_delay >= retry_backoff.

        Returns:
            Validated model instance.

        Raises:
            ValueError: If retry_max_delay < retry_backoff.
        """
        if self.retry_max_delay < self.retry_backoff:
            msg = (
                f"Retry max delay ({self.retry_max_delay}s) must be >= "
                f"retry backoff ({self.retry_backoff}s)"
            )
            raise ValueError(msg)
        return self
