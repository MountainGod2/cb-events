"""Constants for the Chaturbate Events API client."""

from http import HTTPStatus

# API endpoints
BASE_URL = "https://eventsapi.chaturbate.com/events"
TESTBED_URL = "https://events.testbed.cb.dev/events"
URL_TEMPLATE = "{base_url}/{username}/{token}/?timeout={timeout}"

# Client defaults
DEFAULT_TIMEOUT = 10
DEFAULT_RETRY_ATTEMPTS = 8
DEFAULT_RETRY_BACKOFF = 1.0
DEFAULT_RETRY_FACTOR = 2.0
DEFAULT_RETRY_MAX_DELAY = 30.0

# Rate limiting
RATE_LIMIT_MAX_RATE = 2000
RATE_LIMIT_TIME_PERIOD = 60

# HTTP handling
SESSION_TIMEOUT_BUFFER = 5
AUTH_ERROR_STATUSES = {HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN}
RETRY_STATUS_CODES = {
    HTTPStatus.INTERNAL_SERVER_ERROR.value,
    HTTPStatus.BAD_GATEWAY.value,
    HTTPStatus.SERVICE_UNAVAILABLE.value,
    HTTPStatus.GATEWAY_TIMEOUT.value,
    HTTPStatus.TOO_MANY_REQUESTS.value,
    521,  # Cloudflare: origin down
    522,  # Cloudflare: connection timeout
    523,  # Cloudflare: origin unreachable
    524,  # Cloudflare: timeout occurred
}
