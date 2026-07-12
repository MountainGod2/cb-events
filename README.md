# cb-events

Async Python client for the Chaturbate Events API.

[![PyPI](https://img.shields.io/pypi/v/cb-events)](https://pypi.org/project/cb-events/)
[![Tag](https://img.shields.io/github/v/tag/MountainGod2/cb-events)](https://github.com/MountainGod2/cb-events/releases)
[![Python](https://img.shields.io/pypi/pyversions/cb-events)](https://pypi.org/project/cb-events/)
[![OpenSSF Best Practices](https://img.shields.io/cii/summary/12375?label=openssf%20best%20practices)](https://www.bestpractices.dev/en/projects/12375)
[![Builds](https://img.shields.io/github/actions/workflow/status/MountainGod2/cb-events/release.yml?label=builds)](https://github.com/MountainGod2/cb-events/actions/workflows/release.yml)
[![License](https://img.shields.io/github/license/MountainGod2/cb-events?label=license)](https://github.com/MountainGod2/cb-events/blob/main/LICENSE)

Provides event polling, typed models, retries, and routing.

## Requirements

Python 3.10+

## Installation

```bash
pip install cb-events
```

With [uv](https://docs.astral.sh/uv/):

```bash
uv add cb-events
```

## Quick Start

```python
import asyncio
from cb_events import Event, EventClient, EventType, Router

router = Router()

events_url = "https://eventsapi.chaturbate.com/events/your_username/your_api_token/"


@router.on(EventType.TIP)
async def handle_tip(event: Event) -> None:
    if event.user and event.tip:
        print(f"{event.user.username} tipped {event.tip.tokens} tokens")


async def main() -> None:
    async with EventClient(events_url) as client:
        async for event in client:
            await router.dispatch(event)


asyncio.run(main())
```

> [!NOTE]
> Create an API token at https://chaturbate.com/statsapi/authtoken/ with Events API scope.

## Features

- Async iterator client for long-polling events.
- Typed event models for tips, chat/messages, follows, broadcasts, and other event types.
- Router handlers are registered by event type.
- Retry and rate-limiting support.
- Client configuration for timeouts, strict validation, and retries.

## Links

- [Documentation](https://mountaingod2.github.io/cb-events/)
- [Examples](https://github.com/MountainGod2/cb-events/tree/main/examples)
- [Changelog](https://github.com/MountainGod2/cb-events/blob/main/CHANGELOG.md)
- [PyPI](https://pypi.org/project/cb-events/)

## License

MIT

______________________________________________________________________

Not affiliated with Chaturbate.
