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
    """Configuration object for EventClient initialization.

    Attributes:
        timeout (int): Timeout for API requests in seconds. Default is 10.
        use_testbed (bool): Whether to use the testbed API endpoint. Default is False.
        retry_attempts (int): Number of retry attempts for failed requests. Default is 8.
        retry_backoff (float): Initial backoff time in seconds between retries. Default is 1.0.
        retry_exponential_base (float): Base for exponential backoff calculation. Default is 2.0.
        retry_max_delay (float): Maximum delay in seconds between retries. Default is 30.0.
    """

    timeout: int = DEFAULT_TIMEOUT
    use_testbed: bool = False
    retry_attempts: int = DEFAULT_RETRY_ATTEMPTS
    retry_backoff: float = DEFAULT_RETRY_BACKOFF
    retry_exponential_base: float = DEFAULT_RETRY_EXPONENTIAL_BASE
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
        if self.retry_exponential_base <= 0:
            msg = "Retry exponential base must be greater than 0"
            raise ValueError(msg)
        if self.retry_max_delay < 0:
            msg = "Retry max delay must be non-negative"
            raise ValueError(msg)
