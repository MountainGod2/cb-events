"""Configuration for the Chaturbate Events API client."""

from typing import ClassVar, Self

from pydantic import BaseModel, Field, model_validator
from pydantic.config import ConfigDict


class ClientConfig(BaseModel):
    """Client configuration.

    Attributes:
        timeout: Request timeout in seconds.
        use_testbed: Use testbed API instead of production.
        strict_validation: Raise on invalid events vs. skip and log.
        retry_attempts: Total attempts including initial request (>=1).
        retry_backoff: Initial retry delay in seconds.
        retry_factor: Backoff multiplier per retry.
        retry_max_delay: Maximum delay between retries.
        next_url_allowed_hosts: Optional list of hostnames permitted for
            'nextUrl' values returned by the API. If None, only the base API
            host (production or testbed) will be followed.
    """

    model_config: ClassVar[ConfigDict] = {"frozen": True}

    timeout: int = Field(default=10, gt=0)
    use_testbed: bool = False
    strict_validation: bool = True
    retry_attempts: int = Field(default=8, ge=1)
    retry_backoff: float = Field(default=1.0, ge=0)
    retry_factor: float = Field(default=2.0, gt=0)
    retry_max_delay: float = Field(default=30.0, ge=0)
    next_url_allowed_hosts: list[str] | None = None

    @model_validator(mode="after")
    def _check_delays(self) -> Self:
        """Validate retry delay configuration.

        Returns:
            Self: Validated configuration instance.

        Raises:
            ValueError: If ``retry_max_delay`` is less than ``retry_backoff``.
        """
        if self.retry_max_delay < self.retry_backoff:
            msg: str = (
                f"retry_max_delay ({self.retry_max_delay}) must be >= "
                f"retry_backoff ({self.retry_backoff}). "
                f"Consider setting retry_max_delay to at least "
                f"{self.retry_backoff} or reducing retry_backoff."
            )
            raise ValueError(msg)
        return self
