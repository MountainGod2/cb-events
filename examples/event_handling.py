# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "cb-events >=9.1.2",
#     "rich >=15.0.0",
# ]
# ///

"""Example script demonstrating event handling with cb-events.

Usage:
    uv run examples/event_handling.py --events-url "https://eventsapi.chaturbate.com/events/<user>/<token>/"

Or, with CB_EVENTS_URL set in the environment:
    uv run examples/event_handling.py
"""

import argparse
import asyncio
import json
import logging
import os
import signal
import sys
import threading
from collections.abc import Sequence

import stamina
from rich.logging import RichHandler

from cb_events import (
    AuthError,
    ClientConfig,
    Event,
    EventClient,
    EventsError,
    EventType,
    Router,
    __version__,
)

# Suppress stamina's default retry hook; cb-events logs retries
# (user, attempt count) via its own per-attempt warning.
stamina.instrumentation.set_on_retry_hooks([])

logger = logging.getLogger(__name__)

router = Router()


@router.on_any
async def handle_any_event(event: Event) -> None:
    """Handle any event (for debugging purposes)."""
    logger.debug("Event received: %s", event.type)


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
        suffix = f"{anon_text}{message_text}".strip()
        logger.info("%s sent %s tokens %s", event.user.username, event.tip.tokens, suffix)


@router.on(EventType.ROOM_SUBJECT_CHANGE)
async def handle_room_subject_change(event: Event) -> None:
    """Handle room subject change events."""
    if event.room_subject:
        logger.info("Room subject changed to %s", event.room_subject.subject)


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


class _JsonLineFormatter(logging.Formatter):
    """Render each log record as one JSON object, for piping into other tools."""

    def format(self, record: logging.LogRecord) -> str:
        """Return the record as a single-line JSON string.

        Returns:
            A JSON-encoded log line.
        """
        payload: dict[str, object] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(*, level: int, json_lines: bool) -> None:
    """Set up console logging, either human-readable or as JSON lines."""
    handler: logging.Handler
    if json_lines:
        handler = logging.StreamHandler()
        handler.setFormatter(_JsonLineFormatter())
    else:
        handler = RichHandler(show_path=False, rich_tracebacks=True, markup=False)
    logging.basicConfig(level=level, handlers=[handler], format="%(message)s")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments, falling back to environment variables.

    Returns:
        Parsed arguments, with ``events_url`` guaranteed to be set.
    """
    parser = argparse.ArgumentParser(
        description="Stream and log events from the Chaturbate Events API.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--events-url",
        default=os.getenv("CB_EVENTS_URL"),
        metavar="URL",
        help="Events API URL. Defaults to the CB_EVENTS_URL environment variable.",
    )
    parser.add_argument(
        "--log-level",
        type=str.upper,
        default=os.getenv("LOG_LEVEL", "INFO"),
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging verbosity. Defaults to the LOG_LEVEL environment variable.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=ClientConfig.model_fields["timeout"].default,
        metavar="SECONDS",
        help="Server long-poll timeout in seconds.",
    )
    parser.add_argument(
        "--retry-attempts",
        type=int,
        default=ClientConfig.model_fields["retry_attempts"].default,
        metavar="N",
        help="Total request attempts, including the first, before giving up.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Raise on invalid events instead of skipping and logging them.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit one JSON object per log line instead of formatted console output.",
    )
    parser.add_argument("--version", action="version", version=f"cb-events {__version__}")

    args = parser.parse_args(argv)
    if not args.events_url:
        parser.error("--events-url or the CB_EVENTS_URL environment variable is required")
    return args


async def run(events_url: str, config: ClientConfig) -> None:
    """Set up signal handlers and stream events to registered handlers."""
    loop = asyncio.get_running_loop()
    main_task = asyncio.current_task()

    def request_shutdown(*_: object) -> None:
        # call_soon_threadsafe is safe whether invoked from the signal delivery
        # thread (the loop.add_signal_handler path) or from the main thread
        # between bytecodes (the signal.signal fallback on Windows/sub-threads).
        if main_task is not None:
            loop.call_soon_threadsafe(main_task.cancel)

    if threading.current_thread() is threading.main_thread():
        try:
            loop.add_signal_handler(signal.SIGTERM, request_shutdown)
            loop.add_signal_handler(signal.SIGINT, request_shutdown)
        except (NotImplementedError, RuntimeError):
            signal.signal(signal.SIGTERM, request_shutdown)
            signal.signal(signal.SIGINT, request_shutdown)

    try:
        async with EventClient(events_url, config=config) as client:
            logger.info("Listening for events... (Ctrl+C to stop)")
            async for event in client:
                await router.dispatch(event)
    except asyncio.CancelledError:
        logger.info("Shutting down")


def main() -> None:
    """Parse CLI arguments, configure logging, and run the event stream."""
    args = parse_args()
    configure_logging(
        level=logging.getLevelNamesMapping()[args.log_level],
        json_lines=args.json,
    )
    config = ClientConfig(
        timeout=args.timeout,
        retry_attempts=args.retry_attempts,
        strict_validation=args.strict,
    )

    try:
        asyncio.run(run(args.events_url, config))
    except AuthError:
        logger.error("Check your credentials and try again.")
        sys.exit(1)
    except EventsError:
        logger.exception("An error occurred.")
        sys.exit(1)


if __name__ == "__main__":
    main()
