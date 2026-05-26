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
import asyncio
from cb_events import EventClient, EventsError, Router

router = Router()
events_url = "https://eventsapi.chaturbate.com/events/username/token/"


async def main() -> None:
    try:
        async with EventClient(events_url) as client:
            async for event in client:
                await router.dispatch(event)
    except EventsError as err:
        print(f"Error: {err}")
        print(f"Status code: {err.status_code}")
        print(f"Response: {err.response_text}")


asyncio.run(main())
```

## Authentication Errors

`AuthError` (`401`/`403`) is never retried.

```python
import asyncio
from cb_events import AuthError, EventClient, EventsError, Router

router = Router()
events_url = "https://eventsapi.chaturbate.com/events/username/token/"


async def main() -> None:
    try:
        async with EventClient(events_url) as client:
            async for event in client:
                await router.dispatch(event)
    except AuthError as err:
        print(f"Authentication failed: {err} (status {err.status_code})")
    except EventsError as err:
        print(f"API error: {err}")


asyncio.run(main())
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
import asyncio
from cb_events import ClientConfig, EventClient, Router

router = Router()
events_url = "https://eventsapi.chaturbate.com/events/username/token/"

config = ClientConfig(strict_validation=False)


async def main() -> None:
    async with EventClient(events_url, config=config) as client:
        async for event in client:
            await router.dispatch(event)


asyncio.run(main())
```

Strict mode raises `pydantic.ValidationError` on invalid event data.

```python
import asyncio
import pydantic
from cb_events import ClientConfig, EventClient, Router

router = Router()
events_url = "https://eventsapi.chaturbate.com/events/username/token/"

config = ClientConfig(strict_validation=True)


async def main() -> None:
    try:
        async with EventClient(events_url, config=config) as client:
            async for event in client:
                await router.dispatch(event)
    except pydantic.ValidationError as err:
        print(f"Invalid event data: {err}")


asyncio.run(main())
```

## Handler Errors

```python
from cb_events import Event, EventType, Router

router = Router()


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
from cb_events import EventClient, Router

router = Router()
events_url = "https://eventsapi.chaturbate.com/events/username/token/"


async def main() -> None:
    loop = asyncio.get_running_loop()
    task = asyncio.current_task()

    def _cancel_task(*_: object) -> None:
        if task is not None:
            task.cancel()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, _cancel_task)
        except NotImplementedError:
            signal.signal(sig, _cancel_task)

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
import asyncio
from cb_events import EventClient, EventsError, Router

router = Router()
events_url = "https://eventsapi.chaturbate.com/events/username/token/"


async def main() -> None:
    try:
        async with EventClient(events_url) as client:
            async for event in client:
                await router.dispatch(event)
    except EventsError as err:
        if err.status_code:
            print(f"API error: {err.status_code}")
        else:
            print(f"Network error: {err}")


asyncio.run(main())
```

## Combined Example

```python
import asyncio
import signal
from cb_events import AuthError, EventClient, EventsError, Router

router = Router()
events_url = "https://eventsapi.chaturbate.com/events/username/token/"


async def main() -> None:
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()

    def _stop(*_: object) -> None:
        stop.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, _stop)
        except NotImplementedError:
            signal.signal(sig, _stop)

    try:
        async with EventClient(events_url) as client:
            async for event in client:
                await router.dispatch(event)
                if stop.is_set():
                    break
    except AuthError as err:
        print(f"Authentication failed: {err}")
    except EventsError as err:
        print(f"API/network error: {err}")


asyncio.run(main())
```
