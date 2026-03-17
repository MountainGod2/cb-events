"""Validation tests for :class:`cb_events.ClientConfig`."""

import pytest
from pydantic import ValidationError

from cb_events import ClientConfig


def test_default_configuration() -> None:
    """Default config should have sensible retry and timeout values."""
    config = ClientConfig()

    assert config.use_testbed is False
    assert config.timeout == 10
    assert config.retry_attempts == 8


def test_custom_configuration() -> None:
    """Config should accept custom values for all parameters."""
    config = ClientConfig(
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
    assert config.retry_backoff == pytest.approx(2.0)
    assert config.retry_factor == pytest.approx(3.0)
    assert config.retry_max_delay == pytest.approx(120.0)


@pytest.mark.parametrize(
    "invalid_kwargs",
    [
        {"timeout": 0},
        {"timeout": -1},
        {"retry_attempts": 0},
        {"retry_attempts": -5},
    ],
)
def test_reject_non_positive_values(invalid_kwargs: dict[str, int]) -> None:
    """Timeout and retry attempts must be strictly positive."""
    with pytest.raises(ValidationError):
        ClientConfig(**invalid_kwargs)


def test_reject_max_delay_less_than_backoff() -> None:
    """Max delay must be greater than or equal to backoff."""
    with pytest.raises(
        ValidationError, match=r"retry_max_delay .* must be >= retry_backoff"
    ):
        ClientConfig(retry_backoff=10.0, retry_max_delay=5.0)


def test_allow_max_delay_equal_to_backoff() -> None:
    """Equal backoff and max delay should be accepted (no scaling)."""
    config = ClientConfig(retry_backoff=5.0, retry_max_delay=5.0)

    assert config.retry_backoff == pytest.approx(5.0)
    assert config.retry_max_delay == pytest.approx(5.0)
