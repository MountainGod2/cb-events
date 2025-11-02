"""Constants for the Chaturbate Events API client."""

from http import HTTPStatus

BASE_URL = "https://eventsapi.chaturbate.com/events"
TESTBED_URL = "https://events.testbed.cb.dev/events"
URL_TEMPLATE = "{base_url}/{username}/{token}/?timeout={timeout}"

DEFAULT_TIMEOUT = 10
TOKEN_MASK_LENGTH = 4
LOG_TEXT_TRUNCATE_LENGTH = 200

RATE_LIMIT_MAX_RATE = 2000
RATE_LIMIT_TIME_PERIOD = 60

DEFAULT_RETRY_ATTEMPTS = 8
DEFAULT_RETRY_BACKOFF = 1.0
DEFAULT_RETRY_FACTOR = 2.0
DEFAULT_RETRY_MAX_DELAY = 30.0

SESSION_TIMEOUT_BUFFER = 5

AUTH_ERROR_STATUSES = {HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN}

# Cloudflare error codes: 521 (down), 522 (timeout), 523 (unreachable), 524 (timeout occurred)
CLOUDFLARE_ERROR_CODES = {521, 522, 523, 524}

TIMEOUT_ERROR_INDICATOR = "waited too long"

# API response field names
FIELD_NEXT_URL = "nextUrl"
FIELD_EVENTS = "events"
FIELD_STATUS = "status"
FIELD_USER = "user"
FIELD_TIP = "tip"
FIELD_MESSAGE = "message"
FIELD_SUBJECT = "subject"
FIELD_BROADCASTER = "broadcaster"
