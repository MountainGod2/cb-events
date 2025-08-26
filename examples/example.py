"""Simple example demonstrating the Chaturbate Events API wrapper."""

import asyncio
import logging
import os

from dotenv import load_dotenv

from chaturbate_events import Event, EventClient, EventRouter, EventType

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

# Load environment variables from a .env file if present
load_dotenv(dotenv_path=".env")


async def main() -> None:
    """Connect to the Chaturbate Events API and handle incoming events."""
    # Get credentials from environment variables
    username = os.getenv("CB_USERNAME")
    token = os.getenv("CB_TOKEN")
    if not username or not token:
        logger.error("Please set the CB_USERNAME and CB_TOKEN environment variables.")
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
            logger.info("%s tipped %d tokens", user.username, tip.tokens)

    # Define event handler for chat and private messages
    @router.on(EventType.CHAT_MESSAGE)
    @router.on(EventType.PRIVATE_MESSAGE)
    async def handle_message(event: Event) -> None:
        """Process chat messages."""
        message = event.message
        user = event.user
        if message and user:
            logger.info("%s: %s", user.username, message.message)

    # Define a catch-all event handler for debugging
    @router.on_any()
    async def handle_any(event: Event) -> None:
        """Log all events for debugging."""
        logger.debug("Event: %s", event.type)

    # Connect and process events
    async with EventClient(username, token, use_testbed=True) as client:
        logger.info("Listening for events... (Ctrl+C to stop)")
        async for event in client:
            await router.dispatch(event)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Stopped by user")
