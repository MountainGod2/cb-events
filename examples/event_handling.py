# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "cb-events ==7.1.2",
#     "python-dotenv ==1.2.2",
# ]
# ///

"""Example script demonstrating event handling with cb-events library."""

import asyncio
import logging
import os
import signal
import sys

from dotenv import load_dotenv

from cb_events import (
    AuthError,
    ClientConfig,
    Event,
    EventClient,
    EventType,
    Router,
)
from cb_events.exceptions import EventsError

logger = logging.getLogger(__name__)

load_dotenv()

router = Router()


@router.on(EventType.BROADCAST_START)
async def handle_broadcast_start(event: Event) -> None:
    """Handle broadcast start events."""
    if event.broadcaster:
        logger.info("Broadcast started for %s", event.broadcaster)


@router.on(EventType.BROADCAST_STOP)
async def handle_broadcast_stop(event: Event) -> None:
    """Handle broadcast stop events."""
    if event.broadcaster:
        logger.info("Broadcast stopped for %s", event.broadcaster)


@router.on(EventType.USER_ENTER)
async def handle_user_enter(event: Event) -> None:
    """Handle user enter events."""
    if event.user:
        logger.info("%s entered the room", event.user.username)


@router.on(EventType.USER_LEAVE)
async def handle_user_leave(event: Event) -> None:
    """Handle user leave events."""
    if event.user:
        logger.info("%s left the room", event.user.username)


@router.on(EventType.FOLLOW)
async def handle_follow(event: Event) -> None:
    """Handle follow events."""
    if event.user:
        logger.info("%s has followed", event.user.username)


@router.on(EventType.UNFOLLOW)
async def handle_unfollow(event: Event) -> None:
    """Handle unfollow events."""
    if event.user:
        logger.info("%s has unfollowed", event.user.username)


@router.on(EventType.FANCLUB_JOIN)
async def handle_fanclub_join(event: Event) -> None:
    """Handle fanclub join events."""
    if event.user:
        logger.info("%s joined the fan club", event.user.username)


@router.on(EventType.CHAT_MESSAGE)
async def handle_chat_message(event: Event) -> None:
    """Handle chat message events."""
    if event.user and event.message:
        logger.info(
            "%s sent chat message: %s",
            event.user.username,
            event.message.message,
        )


@router.on(EventType.PRIVATE_MESSAGE)
async def handle_private_message(event: Event) -> None:
    """Handle private message events."""
    if event.message and event.message.from_user and event.message.to_user:
        logger.info(
            "%s sent private message to %s: %s",
            event.message.from_user,
            event.message.to_user,
            event.message.message,
        )


@router.on(EventType.TIP)
async def handle_tip(event: Event) -> None:
    """Handle tip events."""
    if event.user and event.tip:
        anon_text = "anonymously " if event.tip.is_anon else ""
        clean_message = (
            event.tip.message.removeprefix("| ") if event.tip.message else ""
        )
        message_text = f"with message: {clean_message}" if clean_message else ""
        logger.info(
            "%s sent %s tokens %s",
            event.user.username,
            event.tip.tokens,
            f"{anon_text}{message_text}".strip(),
        )


@router.on(EventType.ROOM_SUBJECT_CHANGE)
async def handle_room_subject_change(event: Event) -> None:
    """Handle room subject change events."""
    if event.room_subject:
        logger.info("Room Subject changed to %s", event.room_subject.subject)


@router.on(EventType.MEDIA_PURCHASE)
async def handle_media_purchase(event: Event) -> None:
    """Handle media purchase events."""
    if event.user and event.media:
        logger.info(
            "%s purchased %s [%s] for %s tokens",
            event.user.username,
            event.media.type,
            event.media.name,
            event.media.tokens,
        )


@router.on_any()
async def handle_any_event(event: Event) -> None:
    """Handle any event (for debugging purposes)."""
    logger.debug("Event received: %s", event.type)


async def main() -> None:
    """Set up event handlers and start listening for events."""
    username = os.getenv("CB_USERNAME", "")
    token = os.getenv("CB_TOKEN", "")
    use_testbed = os.getenv("CB_USE_TESTBED", "false").lower() == "true"

    config = ClientConfig(use_testbed=use_testbed)

    loop = asyncio.get_running_loop()
    task = asyncio.current_task()
    try:
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, task.cancel)
    except NotImplementedError:
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(
                sig, lambda _s, _f: task.cancel() if task is not None else None
            )

    try:
        async with EventClient(username, token, config=config) as client:
            logger.info("Listening for events... (Ctrl+C to stop)")

            async for event in client:
                await router.dispatch(event)
    except asyncio.CancelledError:
        logger.info("Shutting down")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    try:
        asyncio.run(main())
    except (AuthError, EventsError):
        logger.exception("An error occurred")
        sys.exit(1)
