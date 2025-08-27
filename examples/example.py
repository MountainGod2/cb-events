# /// script
# dependencies = [
#   "chaturbate-events==1.0.0",
#   "python-dotenv==1.1.1",
#   "rich==14.1.0"
# ]
# ///

import asyncio
import contextlib
import os

from dotenv import load_dotenv  # pyright: ignore[reportMissingImports]
from rich import print

from chaturbate_events import Event, EventClient, EventRouter, EventType

# Load environment variables from a .env file if present
load_dotenv(dotenv_path=".env")


async def main() -> None:
    """Connect to the Chaturbate Events API and handle incoming events."""
    # Get credentials from environment variables
    username = os.getenv("CB_USERNAME")
    token = os.getenv("CB_TOKEN")
    if not username or not token:
        print("Please set the CB_USERNAME and CB_TOKEN environment variables.")
        return

    # Create an event router for handling different event types
    router = EventRouter()

    # Define event handler for tip events
    @router.on(EventType.TIP)
    async def handle_tip(event: Event) -> None:
        """Process tip events."""
        tip = event.tip
        user = event.user
        if tip and user:
            print(f"{user.username} tipped {tip.tokens} tokens")

    # Define event handler for chat and private messages
    @router.on(EventType.CHAT_MESSAGE)
    @router.on(EventType.PRIVATE_MESSAGE)
    async def handle_message(event: Event) -> None:
        """Process chat messages."""
        message = event.message
        user = event.user
        if message and user:
            print(f"{user.username}: {message.message}")

    # Define a catch-all event handler for debugging
    @router.on_any()
    async def handle_any(event: Event) -> None:
        """Log all events for debugging."""
        print(f"Event: {event.type}")

    # Connect and process events
    async with EventClient(username, token, use_testbed=True) as client:
        print("Listening for events... (Ctrl+C to stop)")
        async for event in client:
            await router.dispatch(event)


if __name__ == "__main__":
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(main())
