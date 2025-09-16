"""Integration tests combining EventClient and EventRouter."""

from typing import Any
from unittest.mock import AsyncMock

import pytest

from chaturbate_events import EventClient, EventRouter, EventType


@pytest.mark.asyncio
async def test_client_router_integration(mock_aioresponse: Any) -> None:
    """Test integration between EventClient and EventRouter."""
    credentials = {"username": "test", "token": "test", "use_testbed": True}
    api_response = {
        "events": [
            {"method": "tip", "id": "1", "object": {"tip": {"tokens": 100}}},
            {
                "method": "chatMessage",
                "id": "2",
                "object": {"message": {"message": "hi"}},
            },
        ],
        "nextUrl": "next_url",
    }

    url = "https://events.testbed.cb.dev/events/test/test/?timeout=10"
    mock_aioresponse.get(url, payload=api_response)

    router = EventRouter()
    tip_handler = AsyncMock()
    chat_handler = AsyncMock()
    global_handler = AsyncMock()
    router.on(EventType.TIP)(tip_handler)
    router.on(EventType.CHAT_MESSAGE)(chat_handler)
    router.on_any()(global_handler)

    async with EventClient(
        username=str(credentials["username"]),
        token=str(credentials["token"]),
        use_testbed=bool(credentials["use_testbed"]),
    ) as client:
        events = await client.poll()
        for event in events:
            await router.dispatch(event)

    assert tip_handler.call_count == 1
    assert chat_handler.call_count == 1
    assert global_handler.call_count == 2
