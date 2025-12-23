cb-events
=========

Async Python client for the Chaturbate Events API.

.. image:: https://img.shields.io/pypi/v/cb-events
   :target: https://pypi.org/project/cb-events/
.. image:: https://img.shields.io/pypi/pyversions/cb-events
   :target: https://pypi.org/project/cb-events/
.. image:: https://img.shields.io/github/license/MountainGod2/cb-events
   :target: https://github.com/MountainGod2/cb-events/blob/main/LICENSE
.. image:: https://img.shields.io/readthedocs/cb-events
   :target: https://cb-events.readthedocs.io/

---

Installation
------------

.. code-block:: bash

   pip install cb-events

Quick Start
-----------

.. code-block:: python

   import asyncio
   from cb_events import EventClient, Router, EventType, Event

   router = Router()

   @router.on(EventType.TIP)
   async def handle_tip(event: Event) -> None:
       if event.user and event.tip:
           print(f"{event.user.username} tipped {event.tip.tokens} tokens")

   async def main():
       async with EventClient(username, token) as client:
           async for event in client:
               await router.dispatch(event)

   asyncio.run(main())

Event Types
-----------

The following event types are supported:

TIP · FANCLUB_JOIN · MEDIA_PURCHASE · CHAT_MESSAGE · PRIVATE_MESSAGE · USER_ENTER · USER_LEAVE · FOLLOW · UNFOLLOW · BROADCAST_START · BROADCAST_STOP · ROOM_SUBJECT_CHANGE

Configuration
-------------

.. code-block:: python

   from cb_events import ClientConfig

   config = ClientConfig(
       timeout=10,                   # Request timeout (seconds)
       use_testbed=False,            # Use testbed endpoint
       strict_validation=True,       # Raise on invalid events
       retry_attempts=8,             # Total attempts (initial + retries)
       retry_backoff=1.0,            # Initial backoff (seconds)
       retry_factor=2.0,             # Backoff multiplier
       retry_max_delay=30.0,         # Max retry delay (seconds)
   )

   client = EventClient(username, token, config=config)

Rate Limiting
-------------

Default: 2000 requests per 60 seconds. Share a limiter across clients:

.. code-block:: python

   from aiolimiter import AsyncLimiter

   limiter = AsyncLimiter(max_rate=2000, time_period=60)
   client1 = EventClient(username1, token1, rate_limiter=limiter)
   client2 = EventClient(username2, token2, rate_limiter=limiter)

Event Properties
----------------

Properties return ``None`` for incompatible event types:

.. code-block:: python

   event.user          # User object (most events)
   event.tip           # Tip object (TIP only)
   event.message       # Message object (CHAT_MESSAGE, PRIVATE_MESSAGE)
   event.room_subject  # RoomSubject object (ROOM_SUBJECT_CHANGE)
   event.broadcaster   # Broadcaster username string

Error Handling
--------------

.. code-block:: python

   from cb_events import AuthError, EventsError

   try:
       async with EventClient(username, token) as client:
           async for event in client:
               await router.dispatch(event)
   except AuthError:
       # Authentication failed (401/403)
       pass
   except EventsError as e:
       # API/network errors - check e.status_code, e.response_text
       pass

**Retries:** Automatic on 429, 5xx, and Cloudflare errors. Auth errors don't retry.

Logging
-------

.. code-block:: python

   import logging

   logging.getLogger("cb_events").setLevel(logging.DEBUG)

Requirements
------------

Python ≥3.12 — See `pyproject.toml <https://github.com/MountainGod2/cb-events/blob/main/pyproject.toml>`_ for dependencies.

License
-------

`MIT <https://github.com/MountainGod2/cb-events/blob/main/LICENSE>`_

---

.. toctree::
   :maxdepth: 2
   :caption: API Reference
   :hidden:

   api/cb_events/index
