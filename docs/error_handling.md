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

## Recommended Pattern

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
        # Bad credentials / revoked token (401/403)
        print(f"Authentication failed: {err} (status {err.status_code})")
    except EventsError as err:
        # Other API/network errors
        print(f"Event API error: {err}")


asyncio.run(main())
```

## Retry Behavior

Built-in retries are enabled by default.

- Retried: `429`, `500`, `502`, `503`, `504`, `521-524`
- Not retried: `401`, `403`, and other `4xx` statuses

If needed, tune retry settings with `ClientConfig(retry_attempts=..., retry_backoff=...)`.

## Validation Mode

`strict_validation=False` (default): skip invalid events and log a warning.

`strict_validation=True`: raise `pydantic.ValidationError` on invalid events.

Use strict mode when you prefer fail-fast behavior and already handle those exceptions.

## Handler Exceptions

Handler exceptions are logged and dispatch continues to the next handler.
`asyncio.CancelledError` is re-raised immediately.

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
import contextlib
import signal
import threading
from cb_events import EventClient, Router

router = Router()
events_url = "https://eventsapi.chaturbate.com/events/username/token/"


async def stream_events() -> None:
    async with EventClient(events_url) as client:
        async for event in client:
            await router.dispatch(event)


async def main() -> None:
    event_loop = asyncio.get_running_loop()
    shutdown_event = asyncio.Event()
    stream_task = asyncio.create_task(stream_events())

    def _request_shutdown(*_: object) -> None:
        event_loop.call_soon_threadsafe(shutdown_event.set)

    if threading.current_thread() is threading.main_thread():
        try:
            event_loop.add_signal_handler(signal.SIGTERM, _request_shutdown)
            event_loop.add_signal_handler(signal.SIGINT, _request_shutdown)
        except (NotImplementedError, RuntimeError):
            # Windows fallback
            signal.signal(signal.SIGTERM, _request_shutdown)
            signal.signal(signal.SIGINT, _request_shutdown)

    shutdown_task = asyncio.create_task(shutdown_event.wait())
    done, _ = await asyncio.wait(
        {stream_task, shutdown_task},
        return_when=asyncio.FIRST_COMPLETED,
    )

    if shutdown_task in done:
        stream_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await stream_task
    else:
        # Propagate client errors
        await stream_task

    shutdown_task.cancel()
    print("Shutting down")


asyncio.run(main())
```

!!! note

    If the client runs in a worker thread, do not register OS signals there.
    Trigger shutdown by calling `shutdown_event.set()` (or
    `event_loop.call_soon_threadsafe(shutdown_event.set)`) from your host application.
