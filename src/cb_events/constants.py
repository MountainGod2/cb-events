"""Constants and configuration values for the Chaturbate Events API client."""

from http import HTTPStatus

# Client configuration
DEFAULT_TIMEOUT = 10
TOKEN_MASK_LENGTH = 4
RATE_LIMIT_MAX_RATE = 2000
RATE_LIMIT_TIME_PERIOD = 60

# Retry configuration
DEFAULT_RETRY_ATTEMPTS = 8
DEFAULT_RETRY_BACKOFF = 1.0
DEFAULT_RETRY_EXPONENTIAL_BASE = 2.0
DEFAULT_RETRY_MAX_DELAY = 30.0

# API endpoints
BASE_URL = "https://eventsapi.chaturbate.com/events"
TESTBED_URL = "https://events.testbed.cb.dev/events"

# HTTP status codes for error handling
AUTH_ERROR_STATUSES = {HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN}

# Cloudflare-specific status codes for retry
CLOUDFLARE_WEB_SERVER_DOWN = 521
CLOUDFLARE_CONNECTION_TIMEOUT = 522
CLOUDFLARE_ORIGIN_UNREACHABLE = 523
CLOUDFLARE_TIMEOUT_OCCURRED = 524

# Response parsing
RESPONSE_PREVIEW_LENGTH = 50
TIMEOUT_ERROR_INDICATOR = "waited too long"
