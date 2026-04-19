Event Models
============

Property accessors return the nested model or ``None`` if absent or wrong event type.

.. code-block:: python

   event.user          # User object (most events)
   event.tip           # Tip object (TIP only)
   event.message       # Message object (CHAT_MESSAGE, PRIVATE_MESSAGE)
   event.media         # Media object (MEDIA_PURCHASE)
   event.room_subject  # RoomSubject object (ROOM_SUBJECT_CHANGE)
   event.broadcaster   # Broadcaster username string, or None if missing

.. warning::

   All string fields (e.g. ``message.message``, ``user.username``,
   ``tip.message``) originate from untrusted user input and are **not**
   sanitized by this library. Escape or validate them before use in HTML,
   SQL, or shell contexts.

----

User
----

Carried by most event types. Check ``event.user`` before accessing fields.

.. list-table::
   :header-rows: 1
   :widths: 25 20 55

   * - Field
     - Type
     - Description
   * - ``username``
     - ``str``
     - Display name of the user.
   * - ``in_fanclub``
     - ``bool``
     - Whether the user is in the fan club.
   * - ``is_mod``
     - ``bool``
     - Whether the user is a moderator.
   * - ``is_follower``
     - ``bool``
     - Whether the user is a follower.
   * - ``is_owner``
     - ``bool``
     - Whether the user is the room owner.
   * - ``has_tokens``
     - ``bool``
     - Whether the user has tokens.
   * - ``is_broadcasting``
     - ``bool``
     - Whether the user is currently broadcasting.
   * - ``in_private_show``
     - ``bool``
     - Whether the user is in a private show.
   * - ``is_spying``
     - ``bool``
     - Whether the user is spying on a private show.
   * - ``is_silenced``
     - ``bool``
     - Whether the user is silenced.
   * - ``has_darkmode``
     - ``bool``
     - Whether the user has dark mode enabled.
   * - ``fc_auto_renew``
     - ``bool``
     - Whether fan club auto-renewal is enabled.
   * - ``color_group``
     - ``str | None``
     - Color group of the user.
   * - ``gender``
     - ``str | None``
     - Gender of the user.
   * - ``language``
     - ``str | None``
     - Language preference of the user.
   * - ``recent_tips``
     - ``Literal["none", "few", "some", "lots", "tons"] | None``
     - Recent tip activity level.
   * - ``subgender``
     - ``str | None``
     - Subgender of the user.

----

Tip
---

Present on ``TIP`` events only. Access via ``event.tip``.

.. list-table::
   :header-rows: 1
   :widths: 25 20 55

   * - Field
     - Type
     - Description
   * - ``tokens``
     - ``int``
     - Number of tokens tipped.
   * - ``is_anon``
     - ``bool``
     - Whether the tip is anonymous.
   * - ``message``
     - ``str | None``
     - Optional message attached to the tip.

----

Message
-------

Present on ``CHAT_MESSAGE`` and ``PRIVATE_MESSAGE`` events. Access via
``event.message``.

.. list-table::
   :header-rows: 1
   :widths: 25 20 55

   * - Field
     - Type
     - Description
   * - ``message``
     - ``str``
     - Content of the message.
   * - ``from_user``
     - ``str | None``
     - Username of the sender (private messages only).
   * - ``to_user``
     - ``str | None``
     - Username of the recipient (private messages only).
   * - ``color``
     - ``str | None``
     - Text color of the message.
   * - ``bg_color``
     - ``str | None``
     - Background color of the message.
   * - ``font``
     - ``str | None``
     - Font style of the message.
   * - ``orig``
     - ``str | None``
     - Original (untranslated) message content.
   * - ``is_private`` *(property)*
     - ``bool``
     - ``True`` when both ``from_user`` and ``to_user`` are set.

----

Media
-----

Present on ``MEDIA_PURCHASE`` events. Access via ``event.media``.

.. list-table::
   :header-rows: 1
   :widths: 25 20 55

   * - Field
     - Type
     - Description
   * - ``id``
     - ``str``
     - Identifier of the purchased media.
   * - ``name``
     - ``str``
     - Name of the purchased media.
   * - ``type``
     - ``"video" | "photos"``
     - Type of the purchased media.
   * - ``tokens``
     - ``int``
     - Number of tokens spent on the purchase.

----

RoomSubject
-----------

Present on ``ROOM_SUBJECT_CHANGE`` events. Access via ``event.room_subject``.

.. list-table::
   :header-rows: 1
   :widths: 25 20 55

   * - Field
     - Type
     - Description
   * - ``subject``
     - ``str``
     - The updated room subject or title.
