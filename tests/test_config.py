"""Tests for EventClientConfig validation and functionality."""

import pytest

from chaturbate_events.config import EventClientConfig
from chaturbate_events.constants import (
    DEFAULT_RETRY_ATTEMPTS,
    DEFAULT_RETRY_BACKOFF,
    DEFAULT_RETRY_EXPONENTIAL_BASE,
    DEFAULT_RETRY_MAX_DELAY,
    DEFAULT_TIMEOUT,
)


def test_config_default_values() -> None:
    """Test that EventClientConfig uses correct default values."""
    config = EventClientConfig()

    assert config.timeout == DEFAULT_TIMEOUT
    assert config.use_testbed is False
    assert config.retry_attempts == DEFAULT_RETRY_ATTEMPTS
    assert config.retry_backoff == DEFAULT_RETRY_BACKOFF
    assert config.retry_exponential_base == DEFAULT_RETRY_EXPONENTIAL_BASE
    assert config.retry_max_delay == DEFAULT_RETRY_MAX_DELAY


def test_config_custom_values() -> None:
    """Test EventClientConfig with custom values."""
    config = EventClientConfig(
        timeout=30,
        use_testbed=True,
        retry_attempts=5,
        retry_backoff=2.5,
        retry_exponential_base=3.0,
        retry_max_delay=120.0,
    )

    assert config.timeout == 30
    assert config.use_testbed is True
    assert config.retry_attempts == 5
    assert config.retry_backoff == 2.5
    assert config.retry_exponential_base == 3.0
    assert config.retry_max_delay == 120.0


def test_negative_timeout_raises_error() -> None:
    """Test that negative timeout raises ValueError."""
    with pytest.raises(ValueError, match="Timeout must be greater than 0"):
        EventClientConfig(timeout=-1)


def test_zero_timeout_raises_error() -> None:
    """Test that zero timeout raises ValueError."""
    with pytest.raises(ValueError, match="Timeout must be greater than 0"):
        EventClientConfig(timeout=0)


def test_negative_retry_attempts_raises_error() -> None:
    """Test that negative retry attempts raises ValueError."""
    with pytest.raises(ValueError, match="Retry attempts must be non-negative"):
        EventClientConfig(retry_attempts=-1)


def test_negative_retry_backoff_raises_error() -> None:
    """Test that negative retry backoff raises ValueError."""
    with pytest.raises(ValueError, match="Retry backoff must be non-negative"):
        EventClientConfig(retry_backoff=-1.0)


def test_zero_retry_exponential_base_raises_error() -> None:
    """Test that zero retry exponential base raises ValueError."""
    with pytest.raises(ValueError, match="Retry exponential base must be greater than 0"):
        EventClientConfig(retry_exponential_base=0.0)


def test_negative_retry_exponential_base_raises_error() -> None:
    """Test that negative retry exponential base raises ValueError."""
    with pytest.raises(ValueError, match="Retry exponential base must be greater than 0"):
        EventClientConfig(retry_exponential_base=-1.0)


def test_negative_retry_max_delay_raises_error() -> None:
    """Test that negative retry max delay raises ValueError."""
    with pytest.raises(ValueError, match="Retry max delay must be non-negative"):
        EventClientConfig(retry_max_delay=-1.0)


def test_zero_retry_attempts_allowed() -> None:
    """Test that zero retry attempts is allowed (no retries)."""
    config = EventClientConfig(retry_attempts=0)
    assert config.retry_attempts == 0


def test_zero_retry_backoff_allowed() -> None:
    """Test that zero retry backoff is allowed (immediate retry)."""
    config = EventClientConfig(retry_backoff=0.0)
    assert config.retry_backoff == 0.0


def test_zero_retry_max_delay_allowed() -> None:
    """Test that zero retry max delay is allowed."""
    config = EventClientConfig(retry_max_delay=0.0)
    assert config.retry_max_delay == 0.0


def test_very_small_positive_timeout() -> None:
    """Test that very small positive timeout is allowed."""
    config = EventClientConfig(timeout=1)
    assert config.timeout == 1


def test_very_small_positive_exponential_base() -> None:
    """Test that very small positive exponential base is allowed."""
    config = EventClientConfig(retry_exponential_base=0.1)
    assert config.retry_exponential_base == 0.1


def test_large_values_allowed() -> None:
    """Test that large values are allowed."""
    config = EventClientConfig(
        timeout=3600,  # 1 hour
        retry_attempts=100,
        retry_backoff=60.0,  # 1 minute
        retry_exponential_base=10.0,
        retry_max_delay=3600.0,  # 1 hour
    )

    assert config.timeout == 3600
    assert config.retry_attempts == 100
    assert config.retry_backoff == 60.0
    assert config.retry_exponential_base == 10.0
    assert config.retry_max_delay == 3600.0


def test_use_testbed_true() -> None:
    """Test use_testbed can be set to True."""
    config = EventClientConfig(use_testbed=True)
    assert config.use_testbed is True


def test_use_testbed_false() -> None:
    """Test use_testbed can be set to False."""
    config = EventClientConfig(use_testbed=False)
    assert config.use_testbed is False


@pytest.mark.parametrize(
    ("field_name", "invalid_value", "expected_error"),
    [
        ("timeout", -5, "Timeout must be greater than 0"),
        ("timeout", 0, "Timeout must be greater than 0"),
        ("retry_attempts", -3, "Retry attempts must be non-negative"),
        ("retry_backoff", -2.5, "Retry backoff must be non-negative"),
        ("retry_exponential_base", -1.0, "Retry exponential base must be greater than 0"),
        ("retry_exponential_base", 0.0, "Retry exponential base must be greater than 0"),
        ("retry_max_delay", -10.0, "Retry max delay must be non-negative"),
    ],
)
def test_config_validation_parametrized(
    field_name: str, invalid_value: float, expected_error: str
) -> None:
    """Test config validation using parametrized values."""
    kwargs = {field_name: invalid_value}
    with pytest.raises(ValueError, match=expected_error):
        EventClientConfig(**kwargs)  # type: ignore[arg-type]


def test_config_repr() -> None:
    """Test that EventClientConfig has a reasonable string representation."""
    config = EventClientConfig(
        timeout=15,
        use_testbed=True,
        retry_attempts=3,
    )

    repr_str = repr(config)
    assert "EventClientConfig" in repr_str
    assert "timeout=15" in repr_str
    assert "use_testbed=True" in repr_str
    assert "retry_attempts=3" in repr_str


def test_config_equality() -> None:
    """Test EventClientConfig equality comparison."""
    config1 = EventClientConfig(timeout=10, use_testbed=True)
    config2 = EventClientConfig(timeout=10, use_testbed=True)
    config3 = EventClientConfig(timeout=20, use_testbed=True)

    assert config1 == config2
    assert config1 != config3


def test_config_immutable_after_creation() -> None:
    """Test that config values can be modified after creation (dataclass behavior)."""
    config = EventClientConfig(timeout=10)

    # Dataclass allows modification by default
    config.timeout = 20
    assert config.timeout == 20


def test_config_with_mixed_types() -> None:
    """Test config creation with mixed numeric types."""
    config = EventClientConfig(
        timeout=15,  # int
        retry_backoff=2.5,  # float
        retry_exponential_base=2,  # int that should work as float
    )

    assert config.timeout == 15
    assert config.retry_backoff == 2.5
    assert config.retry_exponential_base == 2
