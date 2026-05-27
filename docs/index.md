______________________________________________________________________

## title: Home

# cb-events

[![PyPI](https://img.shields.io/pypi/v/cb-events)](https://pypi.org/project/cb-events/)
[![Python](https://img.shields.io/pypi/pyversions/cb-events)](https://pypi.org/project/cb-events/)
[![License](https://img.shields.io/github/license/MountainGod2/cb-events)](https://github.com/MountainGod2/cb-events/blob/main/LICENSE)
[![Builds](https://img.shields.io/github/actions/workflow/status/MountainGod2/cb-events/ci-cd.yml?label=builds)](https://github.com/MountainGod2/cb-events/actions/workflows/ci-cd.yml)

Async Python client for the Chaturbate Events API.

## Example

```python
import asyncio
from cb_events import Event, EventClient, EventType, Router

router = Router()

@router.on(EventType.TIP)
async def handle_tip(event: Event) -> None:
    if event.user and event.tip:
        print(f"{event.user.username} tipped {event.tip.tokens} tokens")

async def main() -> None:
    events_url = "https://eventsapi.chaturbate.com/events/username/token/"
    async with EventClient(events_url) as client:
        async for event in client:
            await router.dispatch(event)


asyncio.run(main())
```

## Project Links

- [GitHub Repository](https://github.com/MountainGod2/cb-events)
- [PyPI Package](https://pypi.org/project/cb-events/)
