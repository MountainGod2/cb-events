"""An example script that demonstrates handling various events from Chatubate."""

import asyncio
import contextlib
import os

from cb_events import (
    AuthError,
    Event,
    EventClient,
    EventClientConfig,
    EventRouter,
    EventType,
)


async def main() -> None:
    """Set up event handlers and start listening for events."""
    username = os.getenv("CB_USERNAME")
    token = os.getenv("CB_TOKEN")

    if not username or not token:
        print("Please set CB_USERNAME and CB_TOKEN environment variables")
        return

    router = EventRouter()

    @router.on(EventType.BROADCAST_START)
    async def handle_broadcast_start(event: Event) -> None:
        """Handle broadcast start events."""
        print("Broadcast started")

    @router.on(EventType.BROADCAST_STOP)
    async def handle_broadcast_stop(event: Event) -> None:
        """Handle broadcast stop events."""
        print("Broadcast stopped")

    @router.on(EventType.USER_ENTER)
    async def handle_user_enter(event: Event) -> None:
        """Handle user enter events."""
        if event.user:
            print(f"{event.user.username} entered the room")

    @router.on(EventType.USER_LEAVE)
    async def handle_user_leave(event: Event) -> None:
        """Handle user leave events."""
        if event.user:
            print(f"{event.user.username} left the room")

    @router.on(EventType.FOLLOW)
    async def handle_follow(event: Event) -> None:
        """Handle follow events."""
        if event.user:
            print(f"{event.user.username} has followed")

    @router.on(EventType.UNFOLLOW)
    async def handle_unfollow(event: Event) -> None:
        """Handle unfollow events."""
        if event.user:
            print(f"{event.user.username} has unfollowed")

    @router.on(EventType.FANCLUB_JOIN)
    async def handle_fanclub_join(event: Event) -> None:
        """Handle fanclub join events."""
        if event.user:
            print(f"{event.user.username} joined the fan club")

    @router.on(EventType.CHAT_MESSAGE)
    async def handle_chat_message(event: Event) -> None:
        """Handle chat message events."""
        if event.user and event.message:
            print(f"{event.user.username} sent chat message: {event.message.message}")

    @router.on(EventType.PRIVATE_MESSAGE)
    async def handle_private_message(event: Event) -> None:
        """Handle private message events."""
        if event.message and event.message.from_user and event.message.to_user:
            print(
                f"{event.message.from_user} sent private message to "
                f"{event.message.to_user}: {event.message.message}"
            )

    @router.on(EventType.TIP)
    async def handle_tip(event: Event) -> None:
        """Handle tip events."""
        if event.user and event.tip:
            anon_text = "anonymously " if event.tip.is_anon else ""
            clean_message = event.tip.message.removeprefix("| ") if event.tip.message else ""
            message_text = f"with message: {clean_message}" if clean_message else ""
            print(
                f"{event.user.username} sent {event.tip.tokens} tokens "
                f"{anon_text}{message_text}".strip()
            )

    @router.on(EventType.ROOM_SUBJECT_CHANGE)
    async def handle_room_subject_change(event: Event) -> None:
        """Handle room subject change events."""
        if event.room_subject:
            print(f"Room Subject changed to {event.room_subject.subject}")

    @router.on(EventType.MEDIA_PURCHASE)
    async def handle_media_purchase(event: Event) -> None:
        """Handle media purchase events."""
        if event.user and "media" in event.data:
            media = event.data["media"]
            print(f"{event.user.username} purchased {media['type']} set: {media['name']}")

    @router.on_any()
    async def handle_unknown_event(event: Event) -> None:
        """Handle any unknown event types."""
        known_types = {
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
            print(f"Unknown method: {event.type}")

    config = EventClientConfig(use_testbed=True)

    async with EventClient(username, token, config=config) as client:
        print("Listening for events... (Ctrl+C to stop)")

        async for event in client:
            await router.dispatch(event)


if __name__ == "__main__":
    with contextlib.suppress(KeyboardInterrupt, AuthError):
        asyncio.run(main())
