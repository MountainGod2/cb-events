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
        async with EventClient(
            "https://eventsapi.chaturbate.com/events/user/token/",
            config=config,
        ) as client:
            async for event in client:
                print(event)
"""

from __future__ import annotations

from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field, model_validator
from typing_extensions import Self


class ClientConfig(BaseModel):
    """Immutable configuration for EventClient behavior.

    Controls timeouts, retry logic, and validation strictness.

    Example:
        Lenient configuration for development::

            config = ClientConfig(
                strict_validation=False,
                retry_attempts=3,
            )

    Note:
        This class is immutable (frozen). Create a new instance to change
        configuration values.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    timeout: int = Field(default=10, gt=0)
    """Server long-poll timeout in seconds."""

    strict_validation: bool = False
    """Raise on invalid events vs. skip and log."""

    retry_attempts: int = Field(default=8, ge=1)
    """Total attempts including the initial request (must be >= 1)."""

    retry_backoff: float = Field(default=1.0, ge=0)
    """Initial retry delay in seconds."""

    retry_factor: float = Field(default=2.0, gt=0)
    """Backoff multiplier applied after each retry."""

    retry_max_delay: float = Field(default=30.0, ge=0)
    """Maximum delay between retries in seconds."""

    @model_validator(mode="after")
    def validate_delays(self) -> Self:
        """Validate retry delay configuration.

        Returns:
            Self: Validated configuration instance.

        Raises:
            ValueError: If retry_max_delay is less than retry_backoff.
        """
        if self.retry_max_delay < self.retry_backoff:
            msg = (
                f"retry_max_delay ({self.retry_max_delay}) must be >= "
                f"retry_backoff ({self.retry_backoff}). "
                f"Consider setting retry_max_delay to at least "
                f"{self.retry_backoff} or reducing retry_backoff."
            )
            raise ValueError(msg)
        return self
