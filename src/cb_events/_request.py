"""Request execution and retry helpers for EventClient."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, NoReturn

import stamina
from aiohttp.client_exceptions import ClientError

from ._exceptions import EventsError, build_http_error

if TYPE_CHECKING:
    import logging
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

    status_codes: frozenset[int] = frozenset()
    """HTTP statuses eligible for this retry budget (typically 401/403)."""

    attempts: int = 1
    """Total attempts before returning the auth-status response as final."""

    delay: float = 0.0
    """Fixed delay in seconds between auth-retry attempts."""

    username: str = ""
    """Username used for log context."""

    logger: logging.Logger | None = field(default=None)
    """Optional logger for per-attempt auth-retry warnings."""


async def perform_request_attempt(
    *,
    session: ClientSession,
    rate_limiter: AsyncLimiter,
    url: str,
    retry_status_codes: frozenset[int],
    auth_retry: AuthRetryOptions | None = None,
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

    Returns:
        Tuple of (HTTP status code, response text).

    Raises:
        _RetryableStatusError: If the response status should be retried.
    """
    options = auth_retry or AuthRetryOptions()
    status = 0
    text = ""
    attempts = max(options.attempts, 1)
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

        if options.logger is not None:
            options.logger.warning(
                "Auth check attempt %d/%d failed for user %s (HTTP %d). Retrying...",
                attempt,
                attempts,
                options.username,
                status,
            )
        if options.delay > 0:
            await asyncio.sleep(options.delay)

    return status, text


def _raise_request_failure(
    *,
    attempts_made: int,
    original_exception: Exception,
    username: str,
    logger: logging.Logger,
) -> NoReturn:
    """Raise a final error after retries are exhausted.

    Args:
        attempts_made: Number of request attempts that were made.
        original_exception: Last exception raised in the retry loop.
        username: Username used for logging context.
        logger: Logger instance.

    Raises:
        EventsError: For network-level failures (ClientError, OSError, etc.).
        ServerError: If the final attempt failed with a 5xx or Cloudflare error code.
        RateLimitError: If the final attempt failed with HTTP 429.
        ClientRequestError: If the final attempt failed with another 4xx.
    """  # ruff: ignore[docstring-missing-exception, docstring-extraneous-exception]  # ruff wants the raised function listed, not the propagated error(s).
    logger.error(
        "Request failed after %d attempts for user %s",
        attempts_made,
        username,
        exc_info=original_exception,
    )

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
    username: str,
    perform_attempt: Callable[[str], Awaitable[tuple[int, str]]],
    logger: logging.Logger,
) -> tuple[int, str]:
    """Run one request under retry/backoff policy.

    Args:
        url: Fully qualified endpoint URL.
        config: Client retry/backoff configuration.
        username: Username used for log context.
        perform_attempt: Callback performing a single request attempt.
        logger: Logger instance.

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
        async for attempt in stamina.retry_context(
            on=retriable_exc_types,
            attempts=config.retry_attempts,
            timeout=None,
            wait_initial=config.retry_backoff,
            wait_max=config.retry_max_delay,
            wait_exp_base=config.retry_factor,
        ):
            attempts_made = attempt.num
            with attempt:
                try:
                    return await perform_attempt(url)
                except retriable_exc_types as exc:
                    if attempts_made < config.retry_attempts:
                        logger.warning(
                            "Attempt %d/%d failed for user %s (%s). Retrying...",
                            attempts_made,
                            config.retry_attempts,
                            username,
                            str(exc) or type(exc).__name__,
                        )
                    raise

    except retriable_exc_types as original_exception:
        _raise_request_failure(
            attempts_made=attempts_made,
            original_exception=original_exception,
            username=username,
            logger=logger,
        )

    # Unreachable in practice: stamina always yields ≥1 attempt and
    # _raise_request_failure is NoReturn. Required for type-checker soundness.
    msg = "Unexpected error in request loop"
    raise EventsError(msg)
