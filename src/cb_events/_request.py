"""Request execution and retry helpers for EventClient."""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from http import HTTPStatus
from math import isfinite
from typing import TYPE_CHECKING, Final, NoReturn, TypeGuard

from aiohttp.client_exceptions import ClientError

from ._exceptions import EventsError, build_http_error

_logger = logging.getLogger(__name__)
_retry_sleep = asyncio.sleep

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from aiohttp import ClientSession
    from aiolimiter import AsyncLimiter

    from ._config import ClientConfig

_RETRY_STATUS_CODES: Final[frozenset[int]] = frozenset({
    HTTPStatus.INTERNAL_SERVER_ERROR.value,
    HTTPStatus.BAD_GATEWAY.value,
    HTTPStatus.SERVICE_UNAVAILABLE.value,
    HTTPStatus.GATEWAY_TIMEOUT.value,
    HTTPStatus.TOO_MANY_REQUESTS.value,
    521,
    522,
    523,
    524,
})


class _RetryableStatusError(Exception):
    """Internal exception used to trigger retry for HTTP status failures."""

    def __init__(
        self,
        msg: str,
        *,
        status_code: int,
        response_text: str,
        retry_after: str | None = None,
    ) -> None:
        """Initialize with message and HTTP metadata."""
        super().__init__(msg)
        self.status_code: int = status_code
        self.response_text: str = response_text
        self.retry_after: str | None = retry_after


def _format_retry_cause(exc: Exception) -> str:
    """Return a stable one-line reason string for retry diagnostics."""
    if isinstance(exc, _RetryableStatusError):
        return f"HTTP {exc.status_code}"
    return type(exc).__name__


async def perform_request_attempt(
    *,
    session: ClientSession,
    rate_limiter: AsyncLimiter,
    url: str,
    retry_auth_status_codes: frozenset[int],
) -> tuple[int, str]:
    """Perform one HTTP request attempt and return status/body.

    Args:
        session: Active HTTP client session.
        rate_limiter: Rate limiter applied before each request.
        url: Fully qualified endpoint URL.
        retry_auth_status_codes: Configured HTTP authentication statuses that
            should trigger the caller's fixed-delay retry.

    Returns:
        Tuple of (HTTP status code, response text).

    Raises:
        _RetryableStatusError: If the response status should be retried.
    """
    await rate_limiter.acquire()
    async with session.get(
        url,
        allow_redirects=False,
        raise_for_status=False,
    ) as response:
        status = response.status
        text = await response.text()
        retry_after = response.headers.get("Retry-After")

    if status in _RETRY_STATUS_CODES or status in retry_auth_status_codes:
        msg = f"HTTP {status}"
        raise _RetryableStatusError(
            msg,
            status_code=status,
            response_text=text,
            retry_after=retry_after,
        )

    return status, text


def _raise_request_failure(
    *,
    attempts_made: int,
    original_exception: Exception,
) -> NoReturn:
    """Raise a final error after retries are exhausted.

    Args:
        attempts_made: Number of request attempts that were made.
        original_exception: Last exception raised in the retry loop.

    Raises:
        EventsError: For network-level failures (ClientError, OSError, etc.).
        ServerError: If the final attempt failed with a 5xx or Cloudflare error code.
        RateLimitError: If the final attempt failed with HTTP 429.
        ClientRequestError: If the final attempt failed with another 4xx.
    """  # ruff: ignore[docstring-missing-exception, docstring-extraneous-exception]  # ruff wants the raised function listed, not the propagated error(s).
    attempt_label = "attempt" if attempts_made == 1 else "attempts"
    msg = f"Failed to fetch events after {attempts_made} {attempt_label}."

    if isinstance(original_exception, _RetryableStatusError):
        raise build_http_error(
            msg,
            status_code=original_exception.status_code,
            response_text=original_exception.response_text,
        ) from None

    raise EventsError(msg) from original_exception


def _retry_after_delay(value: str | None, *, now: datetime | None = None) -> float | None:
    """Parse a Retry-After value as delta seconds or an HTTP date."""
    if value is None:
        return None

    try:
        delay = float(value.strip())
    except ValueError:
        try:
            retry_at = parsedate_to_datetime(value)
        except (TypeError, ValueError, OverflowError):
            return None
        if retry_at.tzinfo is None:
            retry_at = retry_at.replace(tzinfo=UTC)
        delay = (retry_at - (now or datetime.now(UTC))).total_seconds()

    return max(0.0, delay) if isfinite(delay) else None


def _backoff_delay(config: ClientConfig, attempt: int) -> float:
    """Calculate capped exponential delay after a failed attempt."""
    if config.retry_backoff <= 0 or config.retry_max_delay <= 0:
        return 0.0

    delay = config.retry_backoff
    for _ in range(attempt - 1):
        if not isfinite(delay) or delay >= config.retry_max_delay:
            return config.retry_max_delay
        next_delay = delay * config.retry_factor
        if not isfinite(next_delay):
            return config.retry_max_delay
        delay = min(config.retry_max_delay, next_delay)
    return min(config.retry_max_delay, delay)


def _is_auth_retry(exc: Exception, config: ClientConfig) -> TypeGuard[_RetryableStatusError]:
    """Return whether a retryable exception is an enabled auth status."""
    return (
        isinstance(exc, _RetryableStatusError) and exc.status_code in config.auth_retry_status_codes
    )


async def request_with_retry(
    *,
    url: str,
    config: ClientConfig,
    perform_attempt: Callable[[str], Awaitable[tuple[int, str]]],
    username: str | None = None,
) -> tuple[int, str]:
    """Run one request under retry/backoff policy.

    Args:
        url: Fully qualified endpoint URL.
        config: Client retry/backoff configuration.
        perform_attempt: Callback performing a single request attempt.
        username: Account username attached to retry log records.

    Returns:
        Tuple of (HTTP status code, response text).

    """
    retriable_exc_types = (ClientError, OSError, _RetryableStatusError)
    attempts_made = 0
    auth_attempts = 0
    retry_attempts = 0

    while True:
        try:
            attempts_made += 1
            return await perform_attempt(url)
        except retriable_exc_types as exc:
            is_auth_retry = _is_auth_retry(exc, config)
            if is_auth_retry:
                auth_attempts += 1
                attempts_limit = config.auth_retry_attempts
                attempts_for_policy = auth_attempts
            else:
                retry_attempts += 1
                attempts_limit = config.retry_attempts
                attempts_for_policy = retry_attempts

            if attempts_for_policy >= attempts_limit:
                if is_auth_retry:
                    return exc.status_code, exc.response_text
                _raise_request_failure(
                    attempts_made=attempts_made,
                    original_exception=exc,
                )

            if is_auth_retry:
                delay = config.auth_retry_delay
                _logger.warning(
                    "Auth check attempt %d/%d failed for user %s (HTTP %d). Retrying...",
                    auth_attempts,
                    attempts_limit,
                    username or "<unknown>",
                    exc.status_code,
                    extra={"username": username},
                )
            else:
                delay = _backoff_delay(config, retry_attempts)
                if isinstance(exc, _RetryableStatusError):
                    retry_after = _retry_after_delay(exc.retry_after)
                    if retry_after is not None:
                        delay = min(
                            max(delay, retry_after),
                            config.retry_max_delay,
                        )
                _logger.warning(
                    "Retrying events request for user %s after attempt %d/%d (%s).",
                    username or "<unknown>",
                    retry_attempts,
                    attempts_limit,
                    _format_retry_cause(exc),
                    extra={"username": username},
                )
            if delay > 0:
                await _retry_sleep(delay)
