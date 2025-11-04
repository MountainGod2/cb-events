"""Configuration for the Chaturbate Events API client."""

from typing import Self

from pydantic import BaseModel, Field, model_validator

# Default configuration values
DEFAULT_TIMEOUT = 10
DEFAULT_RETRY_ATTEMPTS = 8
DEFAULT_RETRY_BACKOFF = 1.0
DEFAULT_RETRY_FACTOR = 2.0
DEFAULT_RETRY_MAX_DELAY = 30.0


class EventClientConfig(BaseModel):
    """Client configuration (immutable after creation).

    Attributes:
        timeout: Request timeout in seconds.
        use_testbed: Use testbed API with free test tokens.
        strict_validation: Raise ValidationError on invalid events instead
            of logging and skipping them.
        retry_attempts: Total request attempts (initial + retries).
        retry_backoff: Initial backoff before first retry in seconds.
        retry_factor: Exponential backoff multiplier.
        retry_max_delay: Maximum delay between retries in seconds.
    """

    model_config = {"frozen": True}

    timeout: int = Field(default=DEFAULT_TIMEOUT, gt=0)
    use_testbed: bool = False
    strict_validation: bool = True
    retry_attempts: int = Field(default=DEFAULT_RETRY_ATTEMPTS, ge=0)
    retry_backoff: float = Field(default=DEFAULT_RETRY_BACKOFF, ge=0)
    retry_factor: float = Field(default=DEFAULT_RETRY_FACTOR, gt=0)
    retry_max_delay: float = Field(default=DEFAULT_RETRY_MAX_DELAY, ge=0)

    @model_validator(mode="after")
    def validate_retry_delays(self) -> Self:
        """Ensure retry_max_delay >= retry_backoff.

        Returns:
            Self after validation.

        Raises:
            ValueError: If retry_max_delay < retry_backoff.
        """
        if self.retry_max_delay < self.retry_backoff:
            msg = (
                f"retry_max_delay ({self.retry_max_delay}s) must be >= "
                f"retry_backoff ({self.retry_backoff}s)"
            )
            raise ValueError(msg)
        return self
