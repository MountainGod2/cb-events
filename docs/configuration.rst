Configuration
=============

Client Configuration
--------------------

.. code-block:: python

   from cb_events import EventClient, ClientConfig

   config = ClientConfig(
       timeout=10,                   # Request timeout (seconds)
       use_testbed=False,            # Use testbed endpoint
       strict_validation=True,       # Raise on invalid events vs. skip
       retry_attempts=8,             # Total attempts (initial + retries)
       retry_backoff=1.0,            # Initial backoff (seconds)
       retry_factor=2.0,             # Backoff multiplier
       retry_max_delay=30.0,         # Max retry delay (seconds)
       next_url_allowed_hosts=None,  # List of allowed hostnames for next_url
   )

   client = EventClient(username, token, config=config)

Timeout Settings
----------------

.. code-block:: python

   config = ClientConfig(timeout=5)   # Fast-fail
   config = ClientConfig(timeout=30)  # Unreliable networks

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

Strict mode (default):

.. code-block:: python

   config = ClientConfig(strict_validation=True)

Raises :class:`~cb_events.exceptions.EventsError` on invalid event data.

Lenient mode:

.. code-block:: python

   config = ClientConfig(strict_validation=False)

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

.. code-block:: python

   import logging

   logging.getLogger("cb_events").setLevel(logging.DEBUG)
