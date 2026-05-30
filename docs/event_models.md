# Event Models

Property accessors return the nested model or `None` if absent or on the wrong event type.

```python
event.user  # User object (most events)
event.tip  # Tip object (TIP only)
event.message  # Message object (CHAT_MESSAGE, PRIVATE_MESSAGE)
event.media  # Media object (MEDIA_PURCHASE)
event.room_subject  # RoomSubject object (ROOM_SUBJECT_CHANGE)
event.broadcaster  # Broadcaster username string, or None if missing
```

!!! warning

    All string fields (for example `message.message`, `user.username`, and
    `tip.message`) originate from untrusted user input and are **not** sanitized by
    this library. Escape or validate values before using them in HTML, SQL, or shell
    contexts.

## Field Availability By Event

Use this quick reference to distinguish fields that exist on every event envelope
from nested fields that depend on the event type.

### Present On All Events

| Field  | Accessor   | Type                  | Description                                       |
| ------ | ---------- | --------------------- | ------------------------------------------------- |
| method | event.type | EventType             | Event category (for example TIP or CHAT_MESSAGE). |
| id     | event.id   | str                   | Unique event identifier.                          |
| object | event.data | dict of str to object | Raw event payload map.                            |

### Event-Specific Nested Fields

| Accessor     | Payload key | Event type(s)                 | Description                                                   |
| ------------ | ----------- | ----------------------------- | ------------------------------------------------------------- |
| tip          | tip         | TIP                           | Tip payload.                                                  |
| message      | message     | CHAT_MESSAGE, PRIVATE_MESSAGE | Chat or private message payload.                              |
| media        | media       | MEDIA_PURCHASE                | Media purchase payload.                                       |
| room_subject | subject     | ROOM_SUBJECT_CHANGE           | Room subject payload.                                         |
| user         | user        | Any                           | Present when payload includes valid user data.                |
| broadcaster  | broadcaster | Any                           | Present when payload includes a non-empty broadcaster string. |

Model tables below use Python field names.

API payload keys follow camelCase equivalents of Python snake_case names.

## User

Carried by most event types. Check `event.user` before accessing fields.

| Field           | Type                   | Description                                   |
| --------------- | ---------------------- | --------------------------------------------- |
| username        | str                    | Display name of the user.                     |
| in_fanclub      | bool                   | Whether the user is in the fan club.          |
| is_mod          | bool                   | Whether the user is a moderator.              |
| is_follower     | bool                   | Whether the user is a follower.               |
| is_owner        | bool                   | Whether the user is the room owner.           |
| has_tokens      | bool                   | Whether the user has tokens.                  |
| is_broadcasting | bool                   | Whether the user is currently broadcasting.   |
| in_private_show | bool                   | Whether the user is in a private show.        |
| is_spying       | bool                   | Whether the user is spying on a private show. |
| is_silenced     | bool                   | Whether the user is silenced.                 |
| has_darkmode    | bool                   | Whether the user has dark mode enabled.       |
| fc_auto_renew   | bool                   | Whether fan club auto-renewal is enabled.     |
| color_group     | UserColorGroup or None | Color group of the user.                      |
| gender          | UserGender or None     | Gender of the user.                           |
| language        | UserLanguage or None   | Language preference of the user.              |
| recent_tips     | UserRecentTips or None | Recent tip activity level.                    |
| subgender       | UserSubgender or None  | Subgender of the user.                        |

User enum values:

- UserColorGroup: o, m, f, l, p, tr, t, g
- UserGender: m, f, c, t
- UserLanguage: de, en, es, fr, it, ja, ko, pl, pt, ru, zh
- UserRecentTips: none, few, some, lots, tons
- UserSubgender: tf, tm, tn

!!! warning

    `recent_tips` may be the string `"none"`, which is truthy in Python.
    Do not use `if user.recent_tips:` to detect missing data.
    Compare explicitly:

    ```python
    user.recent_tips == "none"  # literal value
    user.recent_tips is None      # field is absent
    ```

## Tip

Present on `TIP` events only. Access via `event.tip`.

| Field   | Type        | Description                           |
| ------- | ----------- | ------------------------------------- |
| tokens  | int         | Number of tokens tipped.              |
| is_anon | bool        | Whether the tip is anonymous.         |
| message | str or None | Optional message attached to the tip. |

## Message

Present on `CHAT_MESSAGE` and `PRIVATE_MESSAGE` events. Access via `event.message`.

| Field                 | Type        | Description                                        |
| --------------------- | ----------- | -------------------------------------------------- |
| message               | str         | Content of the message.                            |
| from_user             | str or None | Username of the sender (private messages only).    |
| to_user               | str or None | Username of the recipient (private messages only). |
| color                 | str or None | Text color of the message.                         |
| bg_color              | str or None | Background color of the message.                   |
| font                  | str or None | Font style of the message.                         |
| orig                  | str or None | Original (untranslated) message content.           |
| is_private (property) | bool        | True when both from_user and to_user are set.      |

## Media

Present on `MEDIA_PURCHASE` events. Access via `event.media`.

| Field  | Type                | Description                             |
| ------ | ------------------- | --------------------------------------- |
| id     | str                 | Identifier of the purchased media.      |
| name   | str                 | Name of the purchased media.            |
| type   | "video" or "photos" | Type of purchased media.                |
| tokens | int                 | Number of tokens spent on the purchase. |

## RoomSubject

Present on `ROOM_SUBJECT_CHANGE` events. Access via `event.room_subject`.

| Field   | Type | Description                    |
| ------- | ---- | ------------------------------ |
| subject | str  | Updated room subject or title. |
