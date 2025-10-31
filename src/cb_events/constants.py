"""Constants for the Chaturbate Events API client."""

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

CLOUDFLARE_ERROR_CODES = {521, 522, 523, 524}
"""Cloudflare error status codes for retry logic.

Status codes:
    521: Web server is down (origin server refused connection)
    522: Connection timed out (connection to origin server timed out)
    523: Origin is unreachable (origin server is unreachable)
    524: A timeout occurred (origin server timeout occurred)
"""

TIMEOUT_ERROR_INDICATOR = "waited too long"
"""Timeout error indicator in API responses."""

FIELD_NEXT_URL = "nextUrl"
"""API response field for next polling URL."""

FIELD_EVENTS = "events"
"""API response field for event list."""

FIELD_STATUS = "status"
"""API response field for status message."""

FIELD_USER = "user"
"""Event data field for user information."""

FIELD_TIP = "tip"
"""Event data field for tip information."""

FIELD_MESSAGE = "message"
"""Event data field for message content."""

FIELD_SUBJECT = "subject"
"""Event data field for room subject."""

FIELD_BROADCASTER = "broadcaster"
"""Event data field for broadcaster username."""
