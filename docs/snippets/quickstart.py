import asyncio

from cb_events import Event, EventClient, EventType, Router

router = Router()

events_url = "https://eventsapi.chaturbate.com/events/your_username/your_api_token/"


@router.on(EventType.USER_ENTER)
async def handle_user_enter(event: Event) -> None:
    if event.user:
        print(f"{event.user.username} entered the room")


@router.on(EventType.TIP)
async def handle_tip(event: Event) -> None:
    if event.user and event.tip:
        print(f"{event.user.username} tipped {event.tip.tokens} tokens")


async def main() -> None:
    async with EventClient(events_url) as client:
        async for event in client:
            await router.dispatch(event)


if __name__ == "__main__":
    asyncio.run(main())
