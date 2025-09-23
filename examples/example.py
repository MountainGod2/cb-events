import asyncio
import contextlib
import os

from chaturbate_events import Event, EventClient, EventRouter, EventType
from chaturbate_events.exceptions import AuthError


async def main() -> None:
    # Get credentials from environment variables
    username = os.getenv("CB_USERNAME", "")
    token = os.getenv("CB_TOKEN", "")

    # Validate credentials
    if not username or not token:
        print("Please set CB_USERNAME and CB_TOKEN environment variables")
        return

    # Create event router
    router = EventRouter()

    @router.on(EventType.TIP)
    async def handle_tip(event: Event) -> None:
        if event.tip and event.user:
            tokens = event.tip.tokens
            username = event.user.username
            print(f"{username} tipped {tokens} tokens!")

    @router.on(EventType.CHAT_MESSAGE)
    async def handle_message(event: Event) -> None:
        if event.message and event.user:
            message = event.message.message
            username = event.user.username
            print(f"{username} says: {message}")

    @router.on_any()
    async def handle_any_event(event: Event) -> None:
        print(f"Event: {event.type}")

    # Connect and process events
    async with EventClient(username, token, use_testbed=True) as client:
        print("Listening for events... (Ctrl+C to stop)")
        async for event in client:
            await router.dispatch(event)


if __name__ == "__main__":
    # Run the main function with graceful shutdown
    with contextlib.suppress(KeyboardInterrupt, AuthError):
        asyncio.run(main())
