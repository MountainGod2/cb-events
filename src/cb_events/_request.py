"""Request execution and retry helpers for EventClient."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, ClassVar, NoReturn

import stamina
from aiohttp.client_exceptions import ClientError

from ._exceptions import AUTH_ERROR_STATUS_CODES, EventsError, build_http_error

_logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from aiohttp import ClientSession
    from aiolimiter import AsyncLimiter

    from ._config import ClientConfig


class _RetryableStatusError(Exception):
    """Internal exception used to trigger retry for HTTP status failures."""

    def __init__(self, msg: str, *, status_code: int, response_text: str) -> None:
        """Initialize with message and HTTP metadata."""
        super().__init__(msg)
        self.status_code: int = status_code
        self.response_text: str = response_text


@dataclass(frozen=True)
class AuthRetryOptions:
    """Small, fixed-delay retry budget for HTTP 401/403 responses.

    Kept separate from the exponential-backoff retry used for network/5xx
    failures: a persistently invalid token should still fail fast, but a
    lone 401/403 can also be a transient edge/WAF hiccup, so a few quick
    retries are attempted first.
    """

    ALLOWED_STATUS_CODES: ClassVar[frozenset[int]] = AUTH_ERROR_STATUS_CODES

    status_codes: frozenset[int] = frozenset()
    """HTTP statuses eligible for this retry budget (typically 401/403)."""

    attempts: int = 1
    """Total attempts before returning the auth-status response as final."""

    delay: float = 0.0
    """Fixed delay in seconds between auth-retry attempts."""

    def __post_init__(self) -> None:
        """Validate the supported auth-retry status subset."""
        invalid_codes = sorted(self.status_codes - self.ALLOWED_STATUS_CODES)
        if invalid_codes:
            invalid = ", ".join(str(code) for code in invalid_codes)
            msg = f"Auth retry status codes must be a subset of {{401, 403}}; received: {invalid}."
            raise ValueError(msg)
        if self.attempts < 1:
            msg = f"Auth retry attempts must be >= 1, got {self.attempts}."
            raise ValueError(msg)


async def perform_request_attempt(  # ruff: ignore[too-many-arguments]
    *,
    session: ClientSession,
    rate_limiter: AsyncLimiter,
    url: str,
    retry_status_codes: frozenset[int],
    auth_retry: AuthRetryOptions | None = None,
    username: str | None = None,
) -> tuple[int, str]:
    """Perform one HTTP request attempt and return status/body.

    Args:
        session: Active HTTP client session.
        rate_limiter: Rate limiter applied before each request.
        url: Fully qualified endpoint URL.
        retry_status_codes: HTTP statuses that should trigger the caller's
            exponential-backoff retry via ``_RetryableStatusError``.
        auth_retry: Optional small fixed-delay retry budget for 401/403
            responses. Defaults to no retry (single attempt).
        username: Account username attached to retry log records.

    Returns:
        Tuple of (HTTP status code, response text).

    Raises:
        _RetryableStatusError: If the response status should be retried.
    """
    options = auth_retry or AuthRetryOptions()

    status = 0
    text = ""
    attempts = options.attempts
    for attempt in range(1, attempts + 1):
        await rate_limiter.acquire()
        async with session.get(url, allow_redirects=False) as response:
            status = response.status
            text = await response.text()

        if status in retry_status_codes:
            msg = f"HTTP {status}"
            raise _RetryableStatusError(msg, status_code=status, response_text=text)

        if status not in options.status_codes or attempt >= attempts:
            break

        _logger.warning(
            "Auth check attempt %d/%d failed (HTTP %d). Retrying...",
            attempt,
            attempts,
            status,
            extra={"username": username},
        )
        if options.delay > 0:
            await asyncio.sleep(options.delay)

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

    status_code: int | None = None
    response_text: str | None = None
    cause: Exception | None = original_exception

    if isinstance(original_exception, _RetryableStatusError):
        status_code = original_exception.status_code
        response_text = original_exception.response_text
        cause = None

    if status_code is not None:
        raise build_http_error(
            msg,
            status_code=status_code,
            response_text=response_text,
        ) from cause

    raise EventsError(
        msg,
        status_code=status_code,
        response_text=response_text,
    ) from cause


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

    Raises:
        EventsError: If retries are exhausted or retry loop ends unexpectedly.
    """
    attempts_made = 0
    retriable_exc_types = (
        ClientError,
        TimeoutError,
        OSError,
        _RetryableStatusError,
    )

    try:
        retry_iterator = stamina.retry_context(
            on=retriable_exc_types,
            attempts=config.retry_attempts,
            timeout=None,
            wait_initial=config.retry_backoff,
            wait_max=config.retry_max_delay,
            wait_exp_base=config.retry_factor,
        ).with_name(
            f"events request for {username}" if username else "events request",
            (),
            {"username": username} if username else {},
        )
        async for attempt in retry_iterator:
            attempts_made = attempt.num
            with attempt:
                return await perform_attempt(url)

    except retriable_exc_types as original_exception:
        _raise_request_failure(
            attempts_made=attempts_made,
            original_exception=original_exception,
        )

    # Unreachable in practice: stamina always yields ≥1 attempt and
    # _raise_request_failure is NoReturn. Required for type-checker soundness.
    msg = "Unexpected error in request loop"
    raise EventsError(msg)
