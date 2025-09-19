import asyncio
import contextlib
import os

from chaturbate_events import Event, EventClient, EventRouter, EventType


async def main() -> None:
    # Get credentials from environment variables
    username = os.getenv("CB_USERNAME", "")
    token = os.getenv("CB_TOKEN", "")

    # Validate credentials
    if not username or not token:
        print("Missing Chaturbate credentials")
        return

    # Create an event router for handling different event types
    router = EventRouter()

    # Define event handler(See EventType for all types)
    @router.on(EventType.TIP)
    async def handle_tip(event: Event) -> None:
        if event.tip and event.user:
            print(f"{event.user.username} tipped {event.tip.tokens} tokens")

    # Define a catch-all event handler
    @router.on_any()
    async def handle_any(event: Event) -> None:
        print(f"Event: {event.type}")

    # Connect and process events
    async with EventClient(username, token, use_testbed=True) as client:
        print("Listening for events... (Ctrl+C to stop)")
        async for event in client:
            await router.dispatch(event)


if __name__ == "__main__":
    # Run the main function
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(main())
