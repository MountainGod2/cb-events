"""Constants and configuration values for the Chaturbate Events API client."""

from http import HTTPStatus

# Client configuration
DEFAULT_TIMEOUT = 10
TOKEN_MASK_LENGTH = 4
RATE_LIMIT_MAX_RATE = 2000
RATE_LIMIT_TIME_PERIOD = 60

# Retry configuration
DEFAULT_RETRY_ATTEMPTS = 3
DEFAULT_RETRY_BACKOFF = 1.0
DEFAULT_RETRY_MAX_DELAY = 30.0
DEFAULT_RETRY_EXPONENTIAL_BASE = 2.0

# API endpoints
BASE_URL = "https://eventsapi.chaturbate.com/events"
TESTBED_URL = "https://events.testbed.cb.dev/events"

# HTTP status codes for specific handling
TIMEOUT_ERROR_STATUSES = {HTTPStatus.BAD_REQUEST}
AUTH_ERROR_STATUSES = {HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN}

# Response parsing
RESPONSE_PREVIEW_LENGTH = 50
TIMEOUT_ERROR_INDICATOR = "waited too long"
