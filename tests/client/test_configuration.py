"""Validation tests for :class:`cb_events.EventClientConfig`."""

import pytest
from pydantic_core import ValidationError

from cb_events import EventClientConfig


def test_default_values() -> None:
    """Config should expose the documented defaults."""
    config = EventClientConfig()

    assert config.use_testbed is False
    assert config.timeout == 10
    assert config.retry_attempts == 8


def test_custom_values_round_trip() -> None:
    """Custom values should be preserved verbatim."""
    config = EventClientConfig(
        use_testbed=True,
        timeout=60,
        retry_attempts=5,
        retry_backoff=2.0,
        retry_factor=3.0,
        retry_max_delay=120.0,
    )

    assert config.use_testbed is True
    assert config.timeout == 60
    assert config.retry_attempts == 5
    assert config.retry_backoff == 2.0
    assert config.retry_factor == 3.0
    assert config.retry_max_delay == 120.0


@pytest.mark.parametrize("timeout", [0, -1])
def test_reject_non_positive_timeout(timeout: int) -> None:
    """Timeout must be strictly positive."""
    with pytest.raises(ValidationError):
        EventClientConfig(timeout=timeout)


@pytest.mark.parametrize("attempts", [-1, -5])
def test_reject_negative_retry_attempts(attempts: int) -> None:
    """Retry attempts cannot be negative."""
    with pytest.raises(ValidationError):
        EventClientConfig(retry_attempts=attempts)


def test_reject_max_delay_less_than_backoff() -> None:
    """Max delay must be greater than or equal to backoff."""
    with pytest.raises(ValidationError) as exc_info:
        EventClientConfig(retry_backoff=10.0, retry_max_delay=5.0)

    errors = exc_info.value.errors()
    assert errors
    message = str(errors[0].get("ctx", {}).get("error", ""))
    assert "must be >=" in message or "Retry max delay" in message


def test_allow_max_delay_equal_to_backoff() -> None:
    """Equal backoff and max delay should be accepted."""
    config = EventClientConfig(retry_backoff=5.0, retry_max_delay=5.0)

    assert config.retry_backoff == 5.0
    assert config.retry_max_delay == 5.0
