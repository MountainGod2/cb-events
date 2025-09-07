import asyncio
import contextlib
import os

from chaturbate_events import Event, EventClient, EventRouter, EventType


async def main() -> None:
    """Connect to the Chaturbate Events API and process incoming events."""
    # Get credentials from environment variables
    username = os.getenv("CB_USERNAME", "")
    token = os.getenv("CB_TOKEN", "")

    # Validate credentials
    if not username or not token:
        print("Missing Chaturbate credentials")
        return

    # Create an event router for handling different event types
    router = EventRouter()

    # Define event handler for tip events
    @router.on(EventType.TIP)
    async def handle_tip(event: Event) -> None:
        """Handle tip events by displaying tip amount and user."""
        tip = event.tip
        user = event.user
        if tip and user:
            print(f"{user.username} tipped {tip.tokens} tokens")

    # Define event handler for chat and private messages
    @router.on(EventType.CHAT_MESSAGE)
    @router.on(EventType.PRIVATE_MESSAGE)
    async def handle_message(event: Event) -> None:
        """Handle chat and private messages by displaying sender and content."""
        message = event.message
        user = event.user
        if message and user:
            print(f"{user.username}: {message.message}")

    # Define a catch-all event handler for debugging
    @router.on_any()
    async def handle_any(event: Event) -> None:
        """Log all events for debugging and monitoring purposes."""
        print(f"Event: {event.type}")

    # Connect and process events
    async with EventClient(username, token, use_testbed=True) as client:
        print("Listening for events... (Ctrl+C to stop)")
        async for event in client:
            await router.dispatch(event)


if __name__ == "__main__":
    # Run the main function, handling KeyboardInterrupt gracefully
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(main())
