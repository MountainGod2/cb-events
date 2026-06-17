# Configuration

## Client Configuration

```python
from cb_events import ClientConfig, EventClient

config = ClientConfig(
    timeout=10,  # Server long-poll timeout (seconds)
    strict_validation=False,  # Raise on invalid events vs skip
    retry_attempts=20,  # Total attempts (initial + retries)
    retry_backoff=1.0,  # Initial backoff (seconds)
    retry_factor=2.0,  # Backoff multiplier
    retry_max_delay=60.0,  # Max retry delay (seconds)
)

client = EventClient(events_url, config=config)
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

Retries are attempted on `429`, `5xx`, and Cloudflare `521-524`. Retries are never
attempted for `401` or `403`.

## Validation Mode

!!! note "Choosing a validation mode"

    `strict_validation=False` (default) skips invalid events and logs a warning.
    In practice, this mainly matters if the upstream API schema changes or a
    malformed payload appears. However, the API has historically been stable.

    `strict_validation=True` raises `pydantic.ValidationError` instead, which
    gives fail-fast behavior but requires your code to handle those exceptions.

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

```python
import logging

logging.getLogger("cb_events").setLevel(logging.DEBUG)
```

**Example DEBUG output**:

```text
DEBUG:cb_events._client:Polling https://eventsapi.chaturbate.com/events/user/************************/?timeout=10
DEBUG:cb_events._client:Received 1 events for user
DEBUG:cb_events._router:Dispatching chatMessage event 1775683684418-0 to 2 handlers
```
