"""Configuration for the Chaturbate Events API client."""

from typing import ClassVar, Self

from pydantic import BaseModel, Field, model_validator
from pydantic.config import ConfigDict


class ClientConfig(BaseModel):
    """Immutable client configuration for API polling behavior."""

    model_config: ClassVar[ConfigDict] = {"frozen": True}

    timeout: int = Field(default=10, gt=0)
    """Request timeout in seconds."""

    use_testbed: bool = False
    """Use the testbed API instead of production."""

    strict_validation: bool = True
    """Raise on invalid events vs. skip and log."""

    retry_attempts: int = Field(default=8, ge=1)
    """Total attempts including the initial request (must be >= 1)."""

    retry_backoff: float = Field(default=1.0, ge=0)
    """Initial retry delay in seconds."""

    retry_factor: float = Field(default=2.0, gt=0)
    """Backoff multiplier applied after each retry."""

    retry_max_delay: float = Field(default=30.0, ge=0)
    """Maximum delay between retries in seconds."""

    next_url_allowed_hosts: list[str] | None = None
    """Hosts permitted for ``nextUrl`` responses; defaults to API host only."""

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
