"""Constants and configuration values for the Chaturbate Events API client."""

from enum import IntEnum
from http import HTTPStatus

# API endpoints
BASE_URL = "https://eventsapi.chaturbate.com/events"
TESTBED_URL = "https://events.testbed.cb.dev/events"
URL_TEMPLATE = "{base_url}/{username}/{token}/?timeout={timeout}"

# Client configuration defaults
DEFAULT_TIMEOUT = 10
TOKEN_MASK_LENGTH = 4

# Rate limiting configuration
RATE_LIMIT_MAX_RATE = 2000
RATE_LIMIT_TIME_PERIOD = 60

# Retry configuration defaults
DEFAULT_RETRY_ATTEMPTS = 8
DEFAULT_RETRY_BACKOFF = 1.0
DEFAULT_RETRY_FACTOR = 2.0
DEFAULT_RETRY_MAX_DELAY = 30.0

# HTTP status codes for error handling
AUTH_ERROR_STATUSES = {HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN}


class CloudflareErrorCode(IntEnum):
    """Cloudflare-specific error codes for retry handling."""

    WEB_SERVER_DOWN = 521
    CONNECTION_TIMEOUT = 522
    ORIGIN_UNREACHABLE = 523
    TIMEOUT_OCCURRED = 524


# Cloudflare error codes set for efficient lookup
CLOUDFLARE_ERROR_CODES = {code.value for code in CloudflareErrorCode}

# Response parsing configuration
RESPONSE_PREVIEW_LENGTH = 50
TIMEOUT_ERROR_INDICATOR = "waited too long"
