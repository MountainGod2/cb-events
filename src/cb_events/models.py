"""Data models for Chaturbate Events API.

This module defines Pydantic models for deserializing and validating events
from the Chaturbate Events API. All models are immutable (frozen) and use
camelCase aliases to match the API's JSON format.

Model Hierarchy:
    BaseEventModel: Base class with shared configuration.
    Event: Main event container with type and nested data.
    User: User information attached to events.
    Message: Chat or private message content.
    Tip: Tip transaction details.
    Media: Media purchase information.
    RoomSubject: Room subject/title changes.

Example:
    Accessing nested event data::

        event = Event.model_validate(api_response)
        if event.type == EventType.TIP and event.tip:
            print(f"Received {event.tip.tokens} tokens")
        if event.user:
            print(f"From: {event.user.username}")
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import TYPE_CHECKING, Literal, TypeVar, cast

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    ValidationError,
    field_validator,
)
from pydantic.alias_generators import to_camel
from typing_extensions import override

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)
"""Logger for the cb_events.models module."""

_SENTINEL: object = object()
"""Module-level sentinel for cache-miss detection."""


class EventType(str, Enum):
    """Event types from the Chaturbate Events API.

    Each member represents a distinct event category that can be received
    from the API. Use with Router.on() to register type-specific handlers.

    Example:
        Filtering events by type::

            @router.on(EventType.TIP)
            async def handle_tip(event: Event) -> None:
                print(f"Tip received: {event.tip.tokens}")
    """

    BROADCAST_START = "broadcastStart"
    """Broadcaster has started streaming."""
    BROADCAST_STOP = "broadcastStop"
    """Broadcaster has stopped streaming."""
    ROOM_SUBJECT_CHANGE = "roomSubjectChange"
    """Room subject or title has changed."""
    USER_ENTER = "userEnter"
    """User has entered the room."""
    USER_LEAVE = "userLeave"
    """User has left the room."""
    FOLLOW = "follow"
    """User has followed the broadcaster."""
    UNFOLLOW = "unfollow"
    """User has unfollowed the broadcaster."""
    FANCLUB_JOIN = "fanclubJoin"
    """User has joined the fan club."""
    CHAT_MESSAGE = "chatMessage"
    """Chat message has been sent."""
    PRIVATE_MESSAGE = "privateMessage"
    """Private message has been sent."""
    TIP = "tip"
    """User has sent a tip."""
    MEDIA_PURCHASE = "mediaPurchase"
    """User has purchased media."""

    @override
    def __str__(self) -> str:
        """Return the raw API value for string formatting.

        This preserves the previous StrEnum behavior on Python 3.10.
        """
        return self.value


class BaseEventModel(BaseModel):
    """Base model for all event-related data structures.

    Provides shared Pydantic configuration for JSON deserialization with
    camelCase to snake_case conversion and immutability.
    """

    model_config = ConfigDict(  # pyright: ignore[reportUnannotatedClassAttribute] # pylint: disable=line-too-long
        alias_generator=to_camel,
        extra="ignore",
        frozen=True,
    )


_BaseEventModelT = TypeVar("_BaseEventModelT", bound=BaseEventModel)


class User(BaseEventModel):
    """User information attached to events.

    Contains details about the user who triggered the event, including
    display name, membership status, and various flags.
    """

    username: str
    """Display name of the user."""
    color_group: str | None = None
    """Color group of the user.

    Known values: ``"o"`` (owner), ``"m"`` (moderator), ``"f"`` (fanclub),
    ``"l"`` (dark purple), ``"p"`` (light purple), ``"tr"`` (dark blue),
    ``"t"`` (light blue), ``"g"`` (grey).
    """
    fc_auto_renew: bool = False
    """Whether the user's fanclub membership is a recurring subscription."""
    gender: str | None = None
    """Gender of the user.

    Known values: ``"m"`` (male), ``"f"`` (female), ``"c"`` (couple),
    ``"t"`` (trans).
    """
    has_darkmode: bool = False
    """Whether the user has dark mode enabled."""
    has_tokens: bool = False
    """Whether the user has at least 1 token."""
    in_fanclub: bool = False
    """Whether the user is in the fan club."""
    in_private_show: bool = False
    """Whether the user is in the broadcaster's private show."""
    is_broadcasting: bool = False
    """Whether the user is currently broadcasting."""
    is_follower: bool = False
    """Whether the user is a follower."""
    is_mod: bool = False
    """Whether the user is a moderator."""
    is_owner: bool = False
    """Whether the user is the room owner."""
    is_silenced: bool = False
    """Whether the user is silenced."""
    is_spying: bool = False
    """Whether the user is spying on a private show."""
    language: str | None = None
    """User's preferred language.

    Known values: ``"de"`` (German), ``"en"`` (English), ``"es"`` (Spanish),
    ``"fr"`` (French), ``"it"`` (Italian), ``"ja"`` (Japanese),
    ``"ko"`` (Korean), ``"pl"`` (Polish), ``"pt"`` (Portuguese),
    ``"ru"`` (Russian), ``"zh"`` (Chinese).
    """
    recent_tips: Literal["none", "few", "some", "lots", "tons"] | None = None
    """How much the user has tipped recently.

    Possible values: ``"none"`` (no recent tips, no tokens — grey username),
    ``"few"`` (few or no recent tips, has tokens — light blue),
    ``"some"`` (some recent tips — dark blue), ``"lots"`` (lots — purple),
    ``"tons"`` (tons — dark purple).
    """
    subgender: Literal["tf", "tm", "tn"] | None = None
    """Subgender of the user (only set when ``gender`` is ``"t"`` / trans).

    Possible values: ``"tf"`` (transfemme), ``"tm"`` (transmasc),
    ``"tn"`` (non-binary). ``None`` when the user is not trans.
    """

    @field_validator("subgender", mode="before")
    @classmethod
    def _empty_subgender_to_none(cls, v: object) -> object:
        """Coerce empty string subgender to None.

        Returns:
            None if v is an empty string, otherwise v unchanged.
        """
        if not v:
            return None
        return v


class Message(BaseEventModel):
    """Chat or private message content.

    Represents message data from chatMessage and privateMessage events.
    """

    message: str
    """Content of the message."""
    bg_color: str | None = None
    """Background color of the message."""
    color: str | None = None
    """Text color of the message."""
    font: str | None = None
    """Font style of the message."""
    orig: str | None = None
    """Original message content."""
    from_user: str | None = None
    """Username of the sender."""
    to_user: str | None = None
    """Username of the recipient."""

    @property
    def is_private(self) -> bool:
        """True if this is a private message."""
        return self.from_user is not None and self.to_user is not None


class Tip(BaseEventModel):
    """Tip transaction details.

    Contains information about a tip event including the amount and
    optional message.
    """

    tokens: int
    """Number of tokens tipped."""
    is_anon: bool = False
    """Whether the tip is anonymous."""
    message: str | None = None
    """Optional message attached to the tip."""


class Media(BaseEventModel):
    """Media purchase transaction details.

    Contains information about a media purchase event.
    """

    id: str
    """Identifier of the purchased media."""
    name: str
    """Name of the purchased media."""
    type: Literal["video", "photos"]
    """Type of the purchased media."""
    tokens: int
    """Number of tokens spent on the media purchase."""


class RoomSubject(BaseEventModel):
    """Room subject or title information.

    Contains the updated room subject from roomSubjectChange events.
    """

    subject: str
    """The room subject or title."""


class Event(BaseEventModel):
    """Event from the Chaturbate Events API.

    The main event container that wraps all event types. Use the typed
    properties to access nested data safely—they return None if data is missing
    or invalid for the event type.

    Example:
        Safe access to nested data::

            if event.type == EventType.TIP:
                if tip := event.tip:
                    print(f"Tip: {tip.tokens} tokens")
                if user := event.user:
                    print(f"From: {user.username}")

    Note:
        Failures to parse nested data are logged as a warning and return None.

    Warning:
        All string fields in event data (e.g. ``message.message``,
        ``user.username``, ``tip.message``) originate from untrusted
        user input and are not sanitized by this library. Escape or
        validate them before use in HTML, SQL, or shell contexts.
    """

    type: EventType = Field(alias="method")
    """Type of the event."""
    id: str
    """Unique identifier for the event."""
    data: dict[str, object] = Field(default_factory=dict, alias="object")
    """Event data payload."""
    _cache: dict[str, object] = PrivateAttr(default_factory=dict)

    @property
    def user(self) -> User | None:
        """User data if present and valid."""
        return self._extract("user", User.model_validate)

    @property
    def message(self) -> Message | None:
        """Message data if present and valid."""
        return self._extract(
            "message",
            Message.model_validate,
            allowed_types=(
                EventType.CHAT_MESSAGE,
                EventType.PRIVATE_MESSAGE,
            ),
        )

    @property
    def broadcaster(self) -> str:
        """Broadcaster username."""
        cache = self._cache
        cached = cache.get("broadcaster", _SENTINEL)
        if cached is not _SENTINEL:
            return cast("str", cached)
        value: object | None = self.data.get("broadcaster")
        if not isinstance(value, str) or not value:
            logger.warning(
                "Missing or invalid broadcaster in event %s", self.id
            )
            result = ""
        else:
            result = value
        cache["broadcaster"] = result
        return result

    @property
    def tip(self) -> Tip | None:
        """Tip data if present and valid (TIP events only)."""
        return self._extract(
            "tip",
            Tip.model_validate,
            allowed_types=(EventType.TIP,),
        )

    @property
    def media(self) -> Media | None:
        """Media purchase data if present and valid (MEDIA_PURCHASE only)."""
        return self._extract(
            "media",
            Media.model_validate,
            allowed_types=(EventType.MEDIA_PURCHASE,),
        )

    @property
    def room_subject(self) -> RoomSubject | None:
        """Room subject if present and valid (ROOM_SUBJECT_CHANGE only)."""
        return self._extract(
            "subject",
            lambda v: RoomSubject.model_validate({"subject": v}),
            allowed_types=(EventType.ROOM_SUBJECT_CHANGE,),
        )

    def _extract(
        self,
        key: str,
        loader: Callable[[object], _BaseEventModelT],
        *,
        allowed_types: tuple[EventType, ...] | None = None,
    ) -> _BaseEventModelT | None:
        """Extract and validate nested model from event data.

        Results are cached so repeated access avoids re-parsing.

        Args:
            key: Key within data to look up.
            loader: Callable that validates/constructs the nested model.
            allowed_types: Event types eligible for extraction.

        Returns:
            Validated model instance or None if unavailable or invalid.
        """
        if allowed_types and self.type not in allowed_types:
            return None

        cache = self._cache
        cached = cache.get(key, _SENTINEL)
        if cached is not _SENTINEL:
            return cast("_BaseEventModelT | None", cached)

        payload: object | None = self.data.get(key)
        if payload is None:
            cache[key] = None
            return None

        try:
            result = loader(payload)
        except ValidationError as exc:
            fields: set[str] = {
                ".".join(str(p) for p in e.get("loc", ())) or key
                for e in exc.errors()
            }
            logger.warning(
                "Invalid %s in event %s (invalid fields: %s)",
                key,
                self.id,
                ", ".join(sorted(fields)),
            )
            cache[key] = None
            return None

        cache[key] = result
        return result
