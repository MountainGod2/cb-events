Configuration
=============

Client Configuration
--------------------

.. code-block:: python

   from cb_events import EventClient, ClientConfig

   config = ClientConfig(
       timeout=10,                   # Server long-poll timeout (seconds)
       use_testbed=False,            # Use testbed endpoint
       strict_validation=False,      # Raise on invalid events vs. skip
       retry_attempts=8,             # Total attempts (initial + retries)
       retry_backoff=1.0,            # Initial backoff (seconds)
       retry_factor=2.0,             # Backoff multiplier
       retry_max_delay=30.0,         # Max retry delay (seconds)
       next_url_allowed_hosts=None,  # List of allowed hostnames for next_url
   )

   client = EventClient(username, token, config=config)

Timeout Settings
----------------

The ``timeout`` parameter controls the maximum time (in seconds) the
Chaturbate server will wait before sending back a response.

.. code-block:: python

   config = ClientConfig(timeout=5)   # More frequent polls
   config = ClientConfig(timeout=30)  # Server holds connection longer

Default: 10 seconds

Retry Configuration
-------------------

.. code-block:: python

   config = ClientConfig(
       retry_attempts=5,      # Try 5 times total
       retry_backoff=2.0,     # Start with 2s delay
       retry_factor=1.5,      # Increase by 1.5x each retry
       retry_max_delay=60.0,  # Cap delays at 60s
   )

Retries on 429, 5xx, Cloudflare 521-524. Never retries 401/403.

Validation Mode
---------------

Lenient mode (default):

.. code-block:: python

   config = ClientConfig(strict_validation=False)

skips invalid events and logs them as a warning.

Strict mode:

.. code-block:: python

   config = ClientConfig(strict_validation=True)

Raises ``pydantic.ValidationError`` on invalid event data. Non-strict paths still raise :class:`~cb_events.exceptions.EventsError`.

.. note::

   In production, ``strict_validation=False`` is often safer: a bad payload is skipped and
   logged rather than crashing the listener.

Testbed Environment
-------------------

.. code-block:: python

   config = ClientConfig(use_testbed=True)
   client = EventClient(username, token, config=config)

Connects to ``https://events.testbed.cb.dev/events``.

Rate Limiting
-------------

Default: 2000 requests per 60 seconds per client.

Custom Rate Limiter
~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from aiolimiter import AsyncLimiter

   limiter = AsyncLimiter(max_rate=1000, time_period=60)
   client = EventClient(username, token, rate_limiter=limiter)

Shared Rate Limiter
~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   limiter = AsyncLimiter(max_rate=2000, time_period=60)

   client1 = EventClient(username1, token1, rate_limiter=limiter)
   client2 = EventClient(username2, token2, rate_limiter=limiter)
   client3 = EventClient(username3, token3, rate_limiter=limiter)

Allowed Hosts
-------------

``next_url_allowed_hosts=None`` restricts ``nextUrl`` to the configured API host
only. Pass a list to permit extra hostnames:

.. code-block:: python

   config = ClientConfig(
       next_url_allowed_hosts=["eventsapi.chaturbate.com", "events.testbed.cb.dev"]
   )

.. warning::

   ``None`` does **not** mean allow any host — it means the API host only.
   An explicit list extends that set; it does not replace it.

Logging
-------

Set the logger to ``DEBUG`` for verbose polling URLs and event dispatch data:

.. code-block:: python

   import logging
   logging.getLogger("cb_events").setLevel(logging.DEBUG)

**Example DEBUG Output:**

.. code-block:: text

   DEBUG:cb_events.client:Polling https://eventsapi.chaturbate.com/events/user/************************/?timeout=10
   DEBUG:cb_events.client:Received 1 events for user
   DEBUG:cb_events.router:Dispatching chatMessage event 1775683684418-0 to 2 handlers
