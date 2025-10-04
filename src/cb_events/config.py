"""Configuration classes for the Chaturbate Events API client."""

from dataclasses import dataclass

from .constants import (
    DEFAULT_RETRY_ATTEMPTS,
    DEFAULT_RETRY_BACKOFF,
    DEFAULT_RETRY_EXPONENTIAL_BASE,
    DEFAULT_RETRY_MAX_DELAY,
    DEFAULT_TIMEOUT,
)


@dataclass(frozen=True)
class EventClientConfig:
    """Configuration for the Chaturbate Events API client."""

    timeout: int = DEFAULT_TIMEOUT  # Timeout for API requests in seconds
    """int: Timeout for API requests in seconds."""
    use_testbed: bool = False  # Whether to use the testbed API endpoint
    """bool: Whether to use the testbed API endpoint."""
    retry_attempts: int = DEFAULT_RETRY_ATTEMPTS  # Number of retry attempts
    """int: Number of retry attempts."""
    retry_backoff: float = DEFAULT_RETRY_BACKOFF  # Initial backoff time in seconds
    """float: Initial backoff time in seconds."""
    retry_exponential_base: float = DEFAULT_RETRY_EXPONENTIAL_BASE  # Exponential backoff base
    """float: Exponential backoff base."""
    retry_max_delay: float = DEFAULT_RETRY_MAX_DELAY  # Maximum delay between retries
    """float: Maximum delay between retries."""

    def __post_init__(self) -> None:
        """Validate configuration values after initialization.

        Raises:
            ValueError: If any configuration value is invalid.
        """
        if self.timeout <= 0:
            msg = "Timeout must be greater than 0"
            raise ValueError(msg)
        if self.retry_attempts < 0:
            msg = "Retry attempts must be non-negative"
            raise ValueError(msg)
        if self.retry_backoff < 0:
            msg = "Retry backoff must be non-negative"
            raise ValueError(msg)
        if self.retry_exponential_base <= 0:
            msg = "Retry exponential base must be greater than 0"
            raise ValueError(msg)
        if self.retry_max_delay < 0:
            msg = "Retry max delay must be non-negative"
            raise ValueError(msg)
