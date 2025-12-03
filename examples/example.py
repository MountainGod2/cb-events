# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "cb-events ==5.6.5",
#     "python-dotenv == 1.2.1",
#     "rich == 14.2.0"
# ]
# ///

"""Example script demonstrating event handling with cb-events library."""

import asyncio
import contextlib
import logging
import os
from logging import Logger
from typing import Literal, Never

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

logger: Logger = logging.getLogger(__name__)

load_dotenv()

username: str = os.getenv("CB_USERNAME", "")
token: str = os.getenv("CB_TOKEN", "")
use_testbed: bool = os.getenv("CB_USE_TESTBED", "false").lower() == "true"

router = Router()


@router.on(EventType.BROADCAST_START)
async def handle_broadcast_start(event: Event) -> None:
    """Handle broadcast start events."""
    logger.info("Broadcast started")


@router.on(EventType.BROADCAST_STOP)
async def handle_broadcast_stop(event: Event) -> None:
    """Handle broadcast stop events."""
    logger.info("Broadcast stopped")


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
async def handle_tip(event: Event):
    """Handle tip events."""
    if event.user and event.tip:
        anon_text: Literal["", "anonymously "] = (
            "anonymously " if event.tip.is_anon else ""
        )
        clean_message: str = (
            event.tip.message.removeprefix("| ") if event.tip.message else ""
        )
        message_text: str = (
            f"with message: {clean_message}" if clean_message else ""
        )
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
async def handle_unknown_event(event: Event) -> None:
    """Handle any unknown event types."""
    known_types: set[EventType] = {
        EventType.BROADCAST_START,
        EventType.BROADCAST_STOP,
        EventType.USER_ENTER,
        EventType.USER_LEAVE,
        EventType.FOLLOW,
        EventType.UNFOLLOW,
        EventType.FANCLUB_JOIN,
        EventType.CHAT_MESSAGE,
        EventType.PRIVATE_MESSAGE,
        EventType.TIP,
        EventType.ROOM_SUBJECT_CHANGE,
        EventType.MEDIA_PURCHASE,
    }
    if event.type not in known_types:
        logger.warning("Unknown method: %s", event.type)


async def main() -> Never:
    """Set up event handlers and start listening for events."""
    config = ClientConfig(use_testbed=use_testbed)

    async with EventClient(username, token, config=config) as client:
        logger.info("Listening for events... (Ctrl+C to stop)")

        async for event in client:
            await router.dispatch(event)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    with contextlib.suppress(KeyboardInterrupt):
        try:
            asyncio.run(main())
        except (AuthError, EventsError) as e:
            logger.error("%s", e)
    logger.info("Exiting.")
