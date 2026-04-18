cb-events
=========

.. image:: https://img.shields.io/pypi/v/cb-events
   :target: https://pypi.org/project/cb-events/
   :alt: PyPI version

.. image:: https://img.shields.io/pypi/pyversions/cb-events
   :target: https://pypi.org/project/cb-events/
   :alt: Python versions

.. image:: https://img.shields.io/github/license/MountainGod2/cb-events
   :target: https://github.com/MountainGod2/cb-events/blob/main/LICENSE
   :alt: License

.. image:: https://img.shields.io/readthedocs/cb-events
   :target: https://cb-events.readthedocs.io/
   :alt: Documentation

Async Python client for the Chaturbate Events API.

Example
-------

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

Documentation
-------------

.. toctree::
   :maxdepth: 2
   :caption: User Guide

   installation
   quickstart
   event_models
   configuration
   error_handling

.. toctree::
   :maxdepth: 2
   :caption: Reference

   api/cb_events/index

.. toctree::
   :maxdepth: 1
   :caption: Project

   changelog
   GitHub Repository <https://github.com/MountainGod2/cb-events>
   PyPI Package <https://pypi.org/project/cb-events/>
