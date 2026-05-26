# Error Handling

## Exception Hierarchy

```text
EventsError (base)
├── AuthError (401/403)
└── HttpStatusError
    ├── ClientRequestError (4xx)
    ├── RateLimitError (429)
    └── ServerError (5xx/52x)
```

`AuthError` is a subclass of `EventsError`, so `except EventsError` catches both.
Catch `AuthError` first if you need separate handling.

## Basic Error Handling

```python
from cb_events import EventClient, EventRouter, EventsError

router = EventRouter()

events_url = "https://eventsapi.chaturbate.com/events/username/token/"

try:
    async with EventClient(events_url) as client:
        async for event in client:
            await router.dispatch(event)
except EventsError as err:
    print(f"Error: {err}")
    print(f"Status code: {err.status_code}")
    print(f"Response: {err.response_text}")
```

## Authentication Errors

`AuthError` (`401`/`403`) is never retried.

```python
from cb_events import AuthError, EventClient, EventRouter, EventsError

router = EventRouter()

events_url = "https://eventsapi.chaturbate.com/events/username/token/"

try:
    async with EventClient(events_url) as client:
        async for event in client:
            await router.dispatch(event)
except AuthError as err:
    print(f"Authentication failed: {err} (status {err.status_code})")
except EventsError as err:
    print(f"API error: {err}")
```

## Automatic Retries

Retriable: `429`, `500`, `502`, `503`, `504`, `521-524`.

Not retriable: `401`, `403`, and other `4xx` statuses.

```python
from cb_events import ClientConfig

config = ClientConfig(
    retry_attempts=5,  # Total attempts (1 initial + 4 retries)
    retry_backoff=1.0,  # Initial delay (seconds)
    retry_factor=2.0,  # Exponential multiplier
    retry_max_delay=30.0,  # Cap delay at 30s
)
```

## Validation Errors

Lenient mode (default) skips invalid events and logs a warning.

```python
from cb_events import ClientConfig, EventClient, EventRouter

router = EventRouter()
events_url = "https://eventsapi.chaturbate.com/events/username/token/"

config = ClientConfig(strict_validation=False)
async with EventClient(events_url, config=config) as client:
    async for event in client:
        await router.dispatch(event)
```

Strict mode raises `pydantic.ValidationError` on invalid event data.

```python
import pydantic
from cb_events import ClientConfig, EventClient, EventRouter

router = EventRouter()
events_url = "https://eventsapi.chaturbate.com/events/username/token/"

config = ClientConfig(strict_validation=True)
client = EventClient(events_url, config=config)

try:
    async for event in client:
        await router.dispatch(event)
except pydantic.ValidationError as err:
    print(f"Invalid event data: {err}")
```

## Handler Errors

```python
from cb_events import Event, EventRouter, EventType

router = EventRouter()

@router.on(EventType.TIP)
async def buggy_handler(event: Event) -> None:
    raise ValueError("Oops!")


@router.on(EventType.TIP)
async def working_handler(event: Event) -> None:
    print("This still runs")
```

## Graceful Shutdown

```python
import asyncio
import signal
from cb_events import EventClient, EventRouter

router = EventRouter()

events_url = "https://eventsapi.chaturbate.com/events/username/token/"


async def main() -> None:
    loop = asyncio.get_running_loop()
    task = asyncio.current_task()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, task.cancel)

    try:
        async with EventClient(events_url) as client:
            async for event in client:
                await router.dispatch(event)
    except asyncio.CancelledError:
        print("Shutting down")


asyncio.run(main())
```

!!! note
`loop.add_signal_handler()` is Unix-only and raises `NotImplementedError` on
Windows. For cross-platform support, catch `NotImplementedError` and use another
cancellation strategy such as `signal.signal()` with an `asyncio.Event`.

## Network Errors

```python
from cb_events import EventClient, EventRouter, EventsError

router = EventRouter()

events_url = "https://eventsapi.chaturbate.com/events/username/token/"

try:
    async with EventClient(events_url) as client:
        async for event in client:
            await router.dispatch(event)
except EventsError as err:
    if err.status_code:
        print(f"API error: {err.status_code}")
    else:
        print(f"Network error: {err}")
```

## End-to-End Loop Example

```python
import asyncio
import logging
from cb_events import AuthError, EventClient, EventRouter, EventsError

events_url = "https://eventsapi.chaturbate.com/events/username/token/"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
router = EventRouter()


async def run_client() -> None:
    while True:
        try:
            async with EventClient(events_url) as client:
                logger.info("Connected to Events API")
                async for event in client:
                    await router.dispatch(event)

        except AuthError as err:
            logger.error(f"Authentication failed: {err}")
            break

        except EventsError as err:
            logger.error(f"API error: {err}")
            await asyncio.sleep(5)

        except asyncio.CancelledError:
            logger.info("Shutting down")
            raise

        except Exception as err:  # noqa: BLE001
            logger.exception(f"Unexpected error: {err}")
            await asyncio.sleep(5)
```
