"""Constants for the Chaturbate Events API client."""

from enum import IntEnum
from http import HTTPStatus

BASE_URL = "https://eventsapi.chaturbate.com/events"
"""Production API base URL."""

TESTBED_URL = "https://events.testbed.cb.dev/events"
"""Testbed API endpoint with free tokens for development."""

URL_TEMPLATE = "{base_url}/{username}/{token}/?timeout={timeout}"
"""URL template for API polling endpoints."""

DEFAULT_TIMEOUT = 10
"""Default request timeout in seconds."""

TOKEN_MASK_LENGTH = 4
"""Characters to show at end of masked tokens."""

LOG_TEXT_TRUNCATE_LENGTH = 200
"""Max response text length in log messages."""

RATE_LIMIT_MAX_RATE = 2000
"""Max requests per time period."""

RATE_LIMIT_TIME_PERIOD = 60
"""Rate limit time period in seconds."""

DEFAULT_RETRY_ATTEMPTS = 8
"""Default retry attempts for failed requests."""

DEFAULT_RETRY_BACKOFF = 1.0
"""Initial backoff time for exponential retry in seconds."""

DEFAULT_RETRY_FACTOR = 2.0
"""Exponential backoff multiplier."""

DEFAULT_RETRY_MAX_DELAY = 30.0
"""Max delay between retries in seconds."""

SESSION_TIMEOUT_BUFFER = 5
"""Buffer time added to session timeout to prevent early timeouts."""

AUTH_ERROR_STATUSES = {HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN}
"""HTTP status codes indicating auth failures."""


class CloudflareErrorCode(IntEnum):
    """Cloudflare error codes for retry handling.

    Status codes returned by Cloudflare for origin server issues.
    """

    WEB_SERVER_DOWN = 521
    """Origin server refused the connection."""

    CONNECTION_TIMEOUT = 522
    """Connection to origin server timed out."""

    ORIGIN_UNREACHABLE = 523
    """Origin server is unreachable."""

    TIMEOUT_OCCURRED = 524
    """Origin server timeout occurred."""


CLOUDFLARE_ERROR_CODES = {code.value for code in CloudflareErrorCode}
"""Cloudflare error status codes for retry logic."""

TIMEOUT_ERROR_INDICATOR = "waited too long"
"""Timeout error indicator in API responses."""
