Installation
============

Requirements
------------

Python ≥3.12

Install
-------

.. code-block:: bash

   pip install cb-events

Or with uv:

.. code-block:: bash

   uv add cb-events

Development
-----------

.. code-block:: bash

   git clone https://github.com/MountainGod2/cb-events.git
   cd cb-events
   make dev-setup

API Token
---------

Generate a token at https://chaturbate.com/statsapi/authtoken/ with the **Events API** scope.

.. code-block:: bash

   export CB_USERNAME="your_username"
   export CB_TOKEN="your_api_token"
