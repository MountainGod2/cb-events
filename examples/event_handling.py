# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "cb-events >=9.1.0"
# ]
# ///

"""Example script demonstrating event handling with cb-events."""

import asyncio
import contextlib
import logging
import os
import signal
import sys
import threading

from cb_events import (
    AuthError,
    ClientConfig,
    Event,
    EventClient,
    EventsError,
    EventType,
    Router,
)

logger = logging.getLogger(__name__)


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
        clean_message = event.tip.message.removeprefix("| ") if event.tip.message else ""
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


@router.on_any
async def handle_any_event(event: Event) -> None:
    """Handle any event (for debugging purposes)."""
    logger.debug("Event received: %s", event.type)


async def stream_events(events_url: str, config: ClientConfig) -> None:
    """Poll events and dispatch each one to registered handlers."""
    async with EventClient(events_url, config=config) as client:
        logger.info("Listening for events... (Ctrl+C to stop)")

        async for event in client:
            await router.dispatch(event)


async def main() -> None:
    """Set up event handlers and start listening for events."""
    events_url = os.getenv("CB_EVENTS_URL")

    if not events_url:
        msg = "CB_EVENTS_URL environment variable is required"
        raise RuntimeError(msg)

    config = ClientConfig()

    event_loop = asyncio.get_running_loop()
    shutdown_event = asyncio.Event()
    stream_task = asyncio.create_task(stream_events(events_url, config))

    def request_shutdown(*_: object) -> None:
        event_loop.call_soon_threadsafe(shutdown_event.set)

    if threading.current_thread() is threading.main_thread():
        try:
            event_loop.add_signal_handler(signal.SIGTERM, request_shutdown)
            event_loop.add_signal_handler(signal.SIGINT, request_shutdown)
        except (NotImplementedError, RuntimeError):
            signal.signal(signal.SIGTERM, request_shutdown)
            signal.signal(signal.SIGINT, request_shutdown)

    shutdown_wait_task = asyncio.create_task(shutdown_event.wait())
    done, _ = await asyncio.wait(
        {stream_task, shutdown_wait_task},
        return_when=asyncio.FIRST_COMPLETED,
    )

    if shutdown_wait_task in done:
        stream_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await stream_task
        logger.info("Shutting down")
    else:
        await stream_task

    shutdown_wait_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await shutdown_wait_task


if __name__ == "__main__":
    log_level_name = os.getenv("LOG_LEVEL", "INFO").strip().upper()
    log_level = logging.getLevelNamesMapping().get(log_level_name, logging.INFO)
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(message)s",
    )

    try:
        asyncio.run(main())
    except AuthError:
        logger.info("Check your credentials and try again.")
        sys.exit(1)
    except EventsError:
        logger.exception("An error occurred.")
        sys.exit(1)
