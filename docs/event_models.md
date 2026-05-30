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

| API field | Python accessor | Type                | Notes                                               |
| --------- | --------------- | ------------------- | --------------------------------------------------- |
| `method`  | `event.type`    | `EventType`         | Event category (for example `TIP`, `CHAT_MESSAGE`). |
| `id`      | `event.id`      | `str`               | Unique event identifier.                            |
| `object`  | `event.data`    | `dict[str, object]` | Raw event payload map.                              |

### Event-Specific Nested Fields

| Python accessor      | Backing payload key  | Present for event type(s)                                                                                    |
| -------------------- | -------------------- | ------------------------------------------------------------------------------------------------------------ |
| `event.tip`          | `object.tip`         | `TIP`                                                                                                        |
| `event.message`      | `object.message`     | `CHAT_MESSAGE`, `PRIVATE_MESSAGE`                                                                            |
| `event.media`        | `object.media`       | `MEDIA_PURCHASE`                                                                                             |
| `event.room_subject` | `object.subject`     | `ROOM_SUBJECT_CHANGE`                                                                                        |
| `event.user`         | `object.user`        | Not restricted by event type; available when the payload includes valid user data (most user-driven events). |
| `event.broadcaster`  | `object.broadcaster` | Not restricted by event type; available when the payload includes a non-empty broadcaster string.            |

## User

Carried by most event types. Check `event.user` before accessing fields.

| Field             | Type                                                                                  | Description                                   |
| ----------------- | ------------------------------------------------------------------------------------- | --------------------------------------------- |
| `username`        | `str`                                                                                 | Display name of the user.                     |
| `in_fanclub`      | `bool`                                                                                | Whether the user is in the fan club.          |
| `is_mod`          | `bool`                                                                                | Whether the user is a moderator.              |
| `is_follower`     | `bool`                                                                                | Whether the user is a follower.               |
| `is_owner`        | `bool`                                                                                | Whether the user is the room owner.           |
| `has_tokens`      | `bool`                                                                                | Whether the user has tokens.                  |
| `is_broadcasting` | `bool`                                                                                | Whether the user is currently broadcasting.   |
| `in_private_show` | `bool`                                                                                | Whether the user is in a private show.        |
| `is_spying`       | `bool`                                                                                | Whether the user is spying on a private show. |
| `is_silenced`     | `bool`                                                                                | Whether the user is silenced.                 |
| `has_darkmode`    | `bool`                                                                                | Whether the user has dark mode enabled.       |
| `fc_auto_renew`   | `bool`                                                                                | Whether fan club auto-renewal is enabled.     |
| `color_group`     | `Optional[Literal["o", "m", "f", "l", "p", "tr", "t", "g"]]`                          | Color group of the user.                      |
| `gender`          | `Optional[Literal["m", "f", "c", "t"]]`                                               | Gender of the user.                           |
| `language`        | `Optional[Literal["de", "en", "es", "fr", "it", "ja", "ko", "pl", "pt", "ru", "zh"]]` | Language preference of the user.              |
| `recent_tips`     | `Optional[Literal["none", "few", "some", "lots", "tons"]]`                            | Recent tip activity level.                    |
| `subgender`       | `Optional[Literal["tf", "tm", "tn"]]`                                                 | Subgender of the user.                        |

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

| Field     | Type            | Description                           |
| --------- | --------------- | ------------------------------------- |
| `tokens`  | `int`           | Number of tokens tipped.              |
| `is_anon` | `bool`          | Whether the tip is anonymous.         |
| `message` | `Optional[str]` | Optional message attached to the tip. |

## Message

Present on `CHAT_MESSAGE` and `PRIVATE_MESSAGE` events. Access via `event.message`.

| Field                   | Type            | Description                                         |
| ----------------------- | --------------- | --------------------------------------------------- |
| `message`               | `str`           | Content of the message.                             |
| `from_user`             | `Optional[str]` | Username of the sender (private messages only).     |
| `to_user`               | `Optional[str]` | Username of the recipient (private messages only).  |
| `color`                 | `Optional[str]` | Text color of the message.                          |
| `bg_color`              | `Optional[str]` | Background color of the message.                    |
| `font`                  | `Optional[str]` | Font style of the message.                          |
| `orig`                  | `Optional[str]` | Original (untranslated) message content.            |
| `is_private` (property) | `bool`          | `True` when both `from_user` and `to_user` are set. |

## Media

Present on `MEDIA_PURCHASE` events. Access via `event.media`.

| Field    | Type                         | Description                             |
| -------- | ---------------------------- | --------------------------------------- |
| `id`     | `str`                        | Identifier of the purchased media.      |
| `name`   | `str`                        | Name of the purchased media.            |
| `type`   | `Literal["video", "photos"]` | Type of purchased media.                |
| `tokens` | `int`                        | Number of tokens spent on the purchase. |

## RoomSubject

Present on `ROOM_SUBJECT_CHANGE` events. Access via `event.room_subject`.

| Field     | Type  | Description                    |
| --------- | ----- | ------------------------------ |
| `subject` | `str` | Updated room subject or title. |
