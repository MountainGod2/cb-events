# CB Events

Async Python client for the Chaturbate Events API.

[![PyPI](https://img.shields.io/pypi/v/cb-events)](https://pypi.org/project/cb-events/)
[![Tag](https://img.shields.io/github/v/tag/MountainGod2/cb-events)](https://github.com/MountainGod2/cb-events/releases)
[![Python](https://img.shields.io/pypi/pyversions/cb-events)](https://pypi.org/project/cb-events/)
[![OpenSSF Best Practices](https://img.shields.io/cii/summary/12375?label=openssf%20best%20practices)](https://www.bestpractices.dev/en/projects/12375)
[![Builds](https://img.shields.io/github/actions/workflow/status/MountainGod2/cb-events/ci-cd.yml?label=builds)](https://github.com/MountainGod2/cb-events/actions/workflows/ci-cd.yml)
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
from cb_events import EventClient, EventType, Router

router = Router()

username = "your_username"
token = "your_api_token"


@router.on(EventType.TIP)
async def handle_tip(event) -> None:
    if event.user and event.tip:
        print(f"{event.user.username} tipped {event.tip.tokens} tokens")


async def main() -> None:
    async with EventClient(username, token) as client:
        async for event in client:
            await router.dispatch(event)


asyncio.run(main())
```

> [!NOTE]
> Create an API token at https://chaturbate.com/statsapi/authtoken/ with Events API scope.
> You can create multiple tokens. Deleting a token revokes its access within up to one minute.

## Features

- Async iterator client for long-polling events.
- Typed event models for tips, chat/messages, follows, broadcasts, and other event types.
- Router handlers are registered by event type.
- Retry and rate-limiting support.
- Client configuration for timeouts, strict validation, and testbed usage.

## Links

- [Documentation](https://cb-events.readthedocs.io/latest/)
- [Examples](https://github.com/MountainGod2/cb-events/tree/main/examples)
- [Changelog](https://github.com/MountainGod2/cb-events/blob/main/CHANGELOG.md)
- [PyPI](https://pypi.org/project/cb-events/)

## Star History

<a href="https://www.star-history.com/?repos=mountaingod2%2Fcb-events&type=timeline&logscale=&legend=top-left">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=mountaingod2/cb-events&type=timeline&theme=dark&logscale&legend=top-left" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=mountaingod2/cb-events&type=timeline&logscale&legend=top-left" />
   <img alt="Star History Chart" src="https://api.star-history.com/chart?repos=mountaingod2/cb-events&type=timeline&logscale&legend=top-left" />
 </picture>
</a>

## License

MIT

---

Not affiliated with Chaturbate.
