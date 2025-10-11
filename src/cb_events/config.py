"""Configuration classes for the Chaturbate Events API client."""

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
    """Configuration for the Chaturbate Events API client.

    Attributes:
        timeout: Timeout for API requests in seconds.
        use_testbed: Whether to use the testbed API endpoint instead of production.
        retry_attempts: Number of retry attempts for failed requests.
        retry_backoff: Initial backoff time in seconds for exponential retry.
        retry_factor: Base multiplier for exponential backoff calculation.
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
        """Validate that retry_max_delay is at least as large as retry_backoff.

        Returns:
            The validated config instance.

        Raises:
            ValueError: If retry_max_delay is less than retry_backoff.
        """
        if self.retry_max_delay < self.retry_backoff:
            msg = "Retry max delay must be >= retry backoff"
            raise ValueError(msg)
        return self
