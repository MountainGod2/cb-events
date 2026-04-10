Error Handling
==============

Exception Hierarchy
-------------------

.. code-block:: text

   EventsError (base)
   ├── AuthError (401/403)
   └── HttpStatusError
       ├── ClientRequestError (4xx)
       ├── RateLimitError (429)
       └── ServerError (5xx/52x)

``AuthError`` is a subclass of ``EventsError``, so ``except EventsError`` catches
both. Put ``AuthError`` first if you need to handle the two cases differently.

Basic Error Handling
--------------------

.. code-block:: python

   from cb_events import EventClient, EventsError

   try:
       async with EventClient(username, token) as client:
           async for event in client:
               await router.dispatch(event)
   except EventsError as e:
       print(f"Error: {e}")
       print(f"Status code: {e.status_code}")
       print(f"Response: {e.response_text}")

Authentication Errors
----------------------

:class:`~cb_events.exceptions.AuthError` (401/403) is never retried:

.. code-block:: python

   from cb_events import EventClient, AuthError, EventsError

   try:
       async with EventClient(username, token) as client:
           async for event in client:
               await router.dispatch(event)
   except AuthError as e:
       print(f"Authentication failed: {e} (status {e.status_code})")
   except EventsError as e:
       print(f"API error: {e}")

Automatic Retries
-----------------

**Retriable**: 429, 500, 502, 503, 504, 521-524

**Not retriable**: 401, 403, other 4xx

.. code-block:: python

   from cb_events import ClientConfig

   config = ClientConfig(
       retry_attempts=5,       # Total attempts (1 initial + 4 retries)
       retry_backoff=1.0,      # Initial delay (seconds)
       retry_factor=2.0,       # Exponential multiplier
       retry_max_delay=30.0,   # Cap delay at 30s
   )

Validation Errors
-----------------

Lenient mode (default) skips invalid events and logs them as a warning:

.. code-block:: python

   config = ClientConfig(strict_validation=False)
   async with EventClient(username, token, config=config) as client:
       async for event in client:
           await router.dispatch(event)

Strict mode raises ``pydantic.ValidationError`` on invalid event data:

.. code-block:: python

   config = ClientConfig(strict_validation=True)
   client = EventClient(username, token, config=config)

   try:
       async for event in client:
           await router.dispatch(event)
   except pydantic.ValidationError as e:
       print(f"Invalid event data: {e}")

Handler Errors
--------------

.. code-block:: python

   @router.on(EventType.TIP)
   async def buggy_handler(event: Event) -> None:
       raise ValueError("Oops!")

   @router.on(EventType.TIP)
   async def working_handler(event: Event) -> None:
       print("This still runs")

Graceful Shutdown
-----------------

.. code-block:: python

   import asyncio
   import signal
   from cb_events import EventClient

   async def main():
       loop = asyncio.get_running_loop()
       task = asyncio.current_task()
       for sig in (signal.SIGTERM, signal.SIGINT):
           loop.add_signal_handler(sig, task.cancel)

       try:
           async with EventClient(username, token) as client:
               async for event in client:
                   await router.dispatch(event)
       except asyncio.CancelledError:
           print("Shutting down")

   asyncio.run(main())

Network Errors
--------------

.. code-block:: python

   from cb_events import EventsError

   try:
       async with EventClient(username, token) as client:
           async for event in client:
               await router.dispatch(event)
   except EventsError as e:
       if e.status_code:
           print(f"API error: {e.status_code}")
       else:
           print(f"Network error: {e}")

Example
-------

.. code-block:: python

   import asyncio
   import logging
   from cb_events import EventClient, AuthError, EventsError

   logging.basicConfig(level=logging.INFO)
   logger = logging.getLogger(__name__)

   async def run_client():
       while True:
           try:
               async with EventClient(username, token) as client:
                   logger.info("Connected to Events API")
                   async for event in client:
                       await router.dispatch(event)

           except AuthError as e:
               logger.error(f"Authentication failed: {e}")
               break

           except EventsError as e:
               logger.error(f"API error: {e}")
               await asyncio.sleep(5)

           except asyncio.CancelledError:
               logger.info("Shutting down")
               raise

           except Exception as e:
               logger.exception(f"Unexpected error: {e}")
               await asyncio.sleep(5)
