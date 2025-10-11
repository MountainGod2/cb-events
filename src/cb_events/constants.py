"""Constants and configuration values for the Chaturbate Events API client."""

from enum import IntEnum
from http import HTTPStatus

# API Endpoints
BASE_URL = "https://eventsapi.chaturbate.com/events"
"""Production API base URL."""

TESTBED_URL = "https://events.testbed.cb.dev/events"
"""Testbed API base URL for development and testing."""

URL_TEMPLATE = "{base_url}/{username}/{token}/?timeout={timeout}"
"""URL template for constructing API polling endpoints."""

# Client Configuration Defaults
DEFAULT_TIMEOUT = 10
"""Default timeout for API requests in seconds."""

TOKEN_MASK_LENGTH = 4
"""Number of characters to show at the end of masked tokens."""

# Rate Limiting
RATE_LIMIT_MAX_RATE = 2000
"""Maximum number of requests allowed per time period."""

RATE_LIMIT_TIME_PERIOD = 60
"""Time period in seconds for rate limiting."""

# Retry Configuration
DEFAULT_RETRY_ATTEMPTS = 8
"""Default number of retry attempts for failed requests."""

DEFAULT_RETRY_BACKOFF = 1.0
"""Default initial backoff time in seconds for exponential retry."""

DEFAULT_RETRY_FACTOR = 2.0
"""Default multiplier for exponential backoff calculation."""

DEFAULT_RETRY_MAX_DELAY = 30.0
"""Default maximum delay between retries in seconds."""

# HTTP Status Codes
AUTH_ERROR_STATUSES = {HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN}
"""HTTP status codes that indicate authentication failures."""


class CloudflareErrorCode(IntEnum):
    """Cloudflare-specific error codes for retry handling.

    These HTTP status codes are returned by Cloudflare when there are
    issues connecting to or communicating with the origin server.
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
"""Set of Cloudflare error status codes for retry logic."""

# Response Handling
RESPONSE_PREVIEW_LENGTH = 50
"""Maximum length of response text to include in error messages."""

TIMEOUT_ERROR_INDICATOR = "waited too long"
"""String indicator in API response for timeout errors."""
