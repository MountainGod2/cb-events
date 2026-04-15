Quick Start
===========

.. code-block:: python

   import asyncio
   from cb_events import EventClient, Router, EventType, Event

   router = Router()

   username = "your_username"
   token = "your_api_token"

   @router.on(EventType.USER_ENTER)
   async def handle_user_enter(event: Event) -> None:
       if event.user:
           print(f"{event.user.username} entered the room")

   @router.on(EventType.TIP)
   async def handle_tip(event: Event) -> None:
       if event.user and event.tip:
           print(f"{event.user.username} tipped {event.tip.tokens} tokens")

   async def main():
       async with EventClient(username, token) as client:
           async for event in client:
               await router.dispatch(event)

   asyncio.run(main())

**Example Output:**

.. code-block:: text

   mountaingod2 entered the room
   mountaingod2 tipped 100 tokens

Event Types
-----------

Available event types:

- ``TIP`` — User sends a tip
- ``FANCLUB_JOIN`` — User joins fan club
- ``MEDIA_PURCHASE`` — User purchases media
- ``CHAT_MESSAGE`` — Public chat message
- ``PRIVATE_MESSAGE`` — Private message received
- ``USER_ENTER`` — User enters room
- ``USER_LEAVE`` — User leaves room
- ``FOLLOW`` — User follows broadcaster
- ``UNFOLLOW`` — User unfollows broadcaster
- ``BROADCAST_START`` — Broadcast begins
- ``BROADCAST_STOP`` — Broadcast ends
- ``ROOM_SUBJECT_CHANGE`` — Room subject updated

Catch-All Handler
-----------------

.. code-block:: python

   @router.on_any()
   async def handle_all(event: Event) -> None:
       print(f"Event type: {event.type}")

Multiple Handlers
-----------------

.. code-block:: python

   @router.on(EventType.TIP)
   async def log_tip(event: Event) -> None:
       logging.info(f"Tip received: {event.tip.tokens}")

   @router.on(EventType.TIP)
   async def thank_tipper(event: Event) -> None:
       await send_thank_you(event.user.username)

.. note::

   Handlers run sequentially in registration order. Regular handler exceptions
   are logged and dispatch continues — a failing handler does not stop the
   others. ``asyncio.CancelledError`` will propagate immediately.
