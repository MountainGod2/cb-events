"""Configuration for the Chaturbate Events API client.

This module provides ClientConfig for customizing client behavior including
timeouts, retry logic, and validation strictness.

Example:
    Custom configuration::

        from cb_events import ClientConfig, EventClient

        config = ClientConfig(
            timeout=30,
            retry_attempts=5,
            strict_validation=False,
        )
        async with EventClient("user", "token", config=config) as client:
            async for event in client:
                print(event)
"""

from typing import ClassVar, Self

from pydantic import BaseModel, Field, model_validator
from pydantic.config import ConfigDict


class ClientConfig(BaseModel):
    """Immutable configuration for EventClient behavior.

    Controls timeouts, retry logic, validation strictness, and API endpoint
    selection. All fields have sensible defaults for typical usage.

    Attributes:
        timeout: Request timeout in seconds. Must be greater than 0.
        use_testbed: Use testbed API instead of production.
        strict_validation: Raise on invalid events instead of skipping.
        retry_attempts: Total attempts including initial request (>= 1).
        retry_backoff: Initial delay between retries in seconds.
        retry_factor: Multiplier applied to delay after each retry.
        retry_max_delay: Maximum delay between retries in seconds.
        next_url_allowed_hosts: Additional hosts allowed for nextUrl
            responses. The base API host is always permitted.

    Example:
        Lenient configuration for development::

            config = ClientConfig(
                use_testbed=True,
                strict_validation=False,
                retry_attempts=3,
            )

    Note:
        This class is immutable (frozen). Create a new instance to change
        configuration values.
    """

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
    """Hosts permitted for nextUrl responses; defaults to API host only."""

    @model_validator(mode="after")
    def _check_delays(self) -> Self:
        """Validate retry delay configuration.

        Returns:
            Self: Validated configuration instance.

        Raises:
            ValueError: If retry_max_delay is less than retry_backoff.
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
