# Configuration

## Client Configuration

```python
from cb_events import ClientConfig, EventClient

config = ClientConfig(
    timeout=10,  # Server long-poll timeout (seconds)
    strict_validation=False,  # Raise on invalid events vs skip
    retry_attempts=10,  # Total attempts (initial + retries)
    retry_backoff=1.0,  # Initial backoff (seconds)
    retry_factor=2.0,  # Backoff multiplier
    retry_max_delay=300.0,  # Max retry delay (seconds)
    auth_retry_attempts=1,  # 401/403 attempts (1 means disabled)
    auth_retry_delay=0.0,  # Fixed delay between auth retries
    auth_retry_status_codes={401, 403},  # Auth statuses eligible for retry
)

client = EventClient(events_url, config=config)
```

## Custom HTTP Session

Inject an `aiohttp.ClientSession` to configure a proxy, SSL context, connector,
cookies, headers, or other aiohttp behavior. `EventClient` uses the injected
session but does not close it; the caller retains ownership.

When you inject a session, its configured `ClientTimeout` is used as-is. Ensure
the session's `total` timeout is greater than `ClientConfig.timeout`, otherwise
the caller timeout can abort long polls early.

```python
from aiohttp import ClientSession

async with ClientSession(headers={"X-Client": "my-bot"}) as session:
    async with EventClient(events_url, session=session) as client:
        events = await client.poll()
```

## Timeout Settings

The `timeout` parameter controls the maximum time (in seconds) the Chaturbate server
waits before responding.

```python
config = ClientConfig(timeout=5)  # More frequent polls
config = ClientConfig(timeout=30)  # Server holds the connection longer
```

Default: 10 seconds

## Retry Configuration

```python
config = ClientConfig(
    retry_attempts=5,  # Try 5 times total
    retry_backoff=2.0,  # Start with 2s delay
    retry_factor=1.5,  # Increase by 1.5x each retry
    retry_max_delay=60.0,  # Cap delays at 60s
)
```

Retries are attempted on `429`, `500`, `502`, `503`, `504`, and Cloudflare
`521-524`.

With default retry settings, the scheduled exponential backoff totals 511 seconds
(about 8.5 minutes) before jitter, excluding request time. This is backoff delay
alone: the retry loop has no overall deadline and request durations add to elapsed time.

Authentication statuses can use a separate fixed-delay retry budget.
By default `auth_retry_attempts=1`, which preserves fail-fast behavior for
`401` and `403` (no retry).

```python
config = ClientConfig(
    auth_retry_attempts=3,
    auth_retry_delay=0.2,
    auth_retry_status_codes={401, 403},
)
```

## Validation Mode

!!! note "Choosing a validation mode"

    `strict_validation=False` (default) skips invalid events and logs a warning.
    In practice, this mainly matters if the upstream API schema changes or a
    malformed payload appears. However, the API has historically been stable.

    `strict_validation=True` raises `StrictValidationError` instead, which
    gives fail-fast behavior but requires your code to handle that custom
    exception. Unknown method names are accepted in either mode and preserved
    as `event.raw_method` while `event.type` is `EventType.UNKNOWN`.

## Environment Selection

Pass the upstream URL directly to `EventClient`. The hostname determines production
vs testbed automatically.

```python
prod_url = "https://eventsapi.chaturbate.com/events/username/token/"
testbed_url = "https://events.testbed.cb.dev/events/username/token/"

prod_client = EventClient(prod_url)
testbed_client = EventClient(testbed_url)
```

## Rate Limiting

Default: 2000 requests per 60 seconds per client.

### Custom Rate Limiter

```python
from aiolimiter import AsyncLimiter

limiter = AsyncLimiter(max_rate=1000, time_period=60)
client = EventClient(events_url, rate_limiter=limiter)
```

### Shared Rate Limiter

!!! warning

    Each client gets its own independent budget by default. Multiple clients without
    a shared limiter multiply the effective request rate.

```python
limiter = AsyncLimiter(max_rate=2000, time_period=60)

client1 = EventClient(url1, rate_limiter=limiter)
client2 = EventClient(url2, rate_limiter=limiter)
client3 = EventClient(url3, rate_limiter=limiter)
```

## Logging

Set the logger to `DEBUG` for verbose polling URLs and event dispatch details.
Retry warnings are emitted on `cb_events._request`.
Stamina also emits a separate `stamina.retry_scheduled` record for the same
retry. To keep the informative client warning without the duplicate, use stdlib
logging only when Stamina is using its stdlib logging backend:

```python
import logging

logging.getLogger("stamina").setLevel(logging.ERROR)
```

```python
import logging

logging.getLogger("cb_events").setLevel(logging.DEBUG)
```

**Example DEBUG output**:

```text
DEBUG:cb_events._client:Polling https://eventsapi.chaturbate.com/events/user/************************/?timeout=10
DEBUG:cb_events._parser:Received 1 events for user
DEBUG:cb_events._router:Dispatching chatMessage event 1775683684418-0 to 2 handlers
WARNING:cb_events._request:Retrying events request for user username after attempt 1/2 (HTTP 502).
```
