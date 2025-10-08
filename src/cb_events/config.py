"""Configuration classes for the Chaturbate Events API client."""

from dataclasses import dataclass

from .constants import (
    DEFAULT_RETRY_ATTEMPTS,
    DEFAULT_RETRY_BACKOFF,
    DEFAULT_RETRY_FACTOR,
    DEFAULT_RETRY_MAX_DELAY,
    DEFAULT_TIMEOUT,
)


@dataclass(frozen=True)
class EventClientConfig:
    """Configuration for the Chaturbate Events API client.

    Attributes:
        timeout: Timeout for API requests in seconds.
        use_testbed: Whether to use the testbed API endpoint instead of production.
        retry_attempts: Number of retry attempts for failed requests.
        retry_backoff: Initial backoff time in seconds for exponential retry.
        retry_factor: Base multiplier for exponential backoff calculation.
        retry_max_delay: Maximum delay between retries in seconds.
    """

    timeout: int = DEFAULT_TIMEOUT
    use_testbed: bool = False
    retry_attempts: int = DEFAULT_RETRY_ATTEMPTS
    retry_backoff: float = DEFAULT_RETRY_BACKOFF
    retry_factor: float = DEFAULT_RETRY_FACTOR
    retry_max_delay: float = DEFAULT_RETRY_MAX_DELAY

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
        if self.retry_factor <= 0:
            msg = "Retry exponential base must be greater than 0"
            raise ValueError(msg)
        if self.retry_max_delay < 0:
            msg = "Retry max delay must be non-negative"
            raise ValueError(msg)
