"""Pydantic event models used by cb_events.

Models are immutable and accept camelCase API payloads while exposing
snake_case attributes.
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import TYPE_CHECKING, ClassVar, TypeVar

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    ValidationError,
    field_validator,
)
from pydantic.alias_generators import to_camel

from ._compat import override

if TYPE_CHECKING:
    from collections.abc import Callable

_logger = logging.getLogger(__name__)
"""Logger for the cb_events.models module."""


class EventType(str, Enum):
    """Event type values emitted by the API."""

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
        """Return the raw API value.

        This keeps string formatting stable across Python versions.
        """
        return self.value


class BaseEventModel(BaseModel):
    """Shared base model for event payload objects."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        alias_generator=to_camel,
        extra="ignore",
        frozen=True,
    )


_T = TypeVar("_T", bound=BaseEventModel)


class User(BaseEventModel):
    """User metadata attached to an event."""

    username: str
    """Display name of the user."""
    color_group: str | None = None
    """User name-color group.

    Known values: ``"o"`` (owner), ``"m"`` (moderator), ``"f"`` (fanclub),
    ``"l"`` (dark purple), ``"p"`` (light purple), ``"tr"`` (dark blue),
    ``"t"`` (light blue), ``"g"`` (grey).
    """
    fc_auto_renew: bool = False
    """Whether the user's fanclub membership is a recurring subscription."""
    gender: str | None = None
    """User gender code.

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
    recent_tips: str | None = None
    """Recent tipping activity bucket.

    Possible values: "none", "few", "some", "lots", "tons".

    Note:
        The string value "none" is truthy. Compare explicitly with
        recent_tips is None versus recent_tips == "none".
    """
    subgender: str | None = None
    """Subgender code when gender is "t".

    Possible values: "tf", "tm", "tn". None when not provided.
    """

    @field_validator("subgender", mode="before")
    @classmethod
    def _empty_subgender_to_none(cls, v: object) -> object:
        """Convert an empty subgender string to None.

        Returns:
            None for an empty string, otherwise the input value unchanged.
        """
        if isinstance(v, str) and not v:
            return None
        return v


class Message(BaseEventModel):
    """Payload for chatMessage and privateMessage events."""

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
    """Payload for tip events."""

    tokens: int
    """Number of tokens tipped."""
    is_anon: bool = False
    """Whether the tip is anonymous."""
    message: str | None = None
    """Optional message attached to the tip."""


class Media(BaseEventModel):
    """Payload for mediaPurchase events."""

    id: str
    """Identifier of the purchased media."""
    name: str
    """Name of the purchased media."""
    type: str
    """Type of the purchased media.

    Possible values: "photos", "video".
    """
    tokens: int
    """Number of tokens spent on the media purchase."""


class RoomSubject(BaseEventModel):
    """Payload for roomSubjectChange events."""

    subject: str
    """The room subject or title."""


class Event(BaseEventModel):
    """Top-level event container.

    Typed convenience accessors parse nested payload fields on demand and
    return None for missing or invalid values.

    Warning:
        String fields in payload data are untrusted user input.
    """

    type: EventType = Field(alias="method")
    """Type of the event."""
    id: str
    """Unique identifier for the event."""
    data: dict[str, object] = Field(default_factory=dict, alias="object")
    """Event data payload."""

    # Private attributes hold the results of one-time sub-model parsing.
    _user: User | None = PrivateAttr(default=None)
    _message: Message | None = PrivateAttr(default=None)
    _broadcaster: str | None = PrivateAttr(default=None)
    _tip: Tip | None = PrivateAttr(default=None)
    _media: Media | None = PrivateAttr(default=None)
    _room_subject: RoomSubject | None = PrivateAttr(default=None)

    @override
    def model_post_init(self, context: object, /) -> None:  # noqa: ARG002
        """Parse and cache all typed sub-models after field initialisation.

        Called once by Pydantic during ``__init__`` and ``model_validate``.
        """
        self._user = self._extract("user", User.model_validate)
        self._message = self._extract(
            "message",
            Message.model_validate,
            allowed_types=(EventType.CHAT_MESSAGE, EventType.PRIVATE_MESSAGE),
        )
        self._broadcaster = self._extract_non_empty_string("broadcaster")
        self._tip = self._extract(
            "tip",
            Tip.model_validate,
            allowed_types=(EventType.TIP,),
        )
        self._media = self._extract(
            "media",
            Media.model_validate,
            allowed_types=(EventType.MEDIA_PURCHASE,),
        )
        self._room_subject = self._extract(
            "subject",
            lambda v: RoomSubject.model_validate({"subject": v}),
            allowed_types=(EventType.ROOM_SUBJECT_CHANGE,),
        )

    @property
    def user(self) -> User | None:
        """User data if present and valid."""
        return self._user

    @property
    def message(self) -> Message | None:
        """Message data if present and valid."""
        return self._message

    @property
    def broadcaster(self) -> str | None:
        """Broadcaster username, or ``None`` if missing or invalid."""
        return self._broadcaster

    @property
    def tip(self) -> Tip | None:
        """Tip data if present and valid (TIP events only)."""
        return self._tip

    @property
    def media(self) -> Media | None:
        """Media purchase data if present and valid (MEDIA_PURCHASE only)."""
        return self._media

    @property
    def room_subject(self) -> RoomSubject | None:
        """Room subject if present and valid (ROOM_SUBJECT_CHANGE only)."""
        return self._room_subject

    def _extract_non_empty_string(self, key: str) -> str | None:
        """Extract a non-empty string from event data.

        Args:
            key: Key within data to look up.

        Returns:
            The string value, or None if missing, empty, or not a string.
        """
        value: object | None = self.data.get(key)
        if isinstance(value, str) and value:
            return value
        return None

    def _extract(
        self,
        key: str,
        loader: Callable[[object], _T],
        *,
        allowed_types: tuple[EventType, ...] | None = None,
    ) -> _T | None:
        """Extract and validate nested model from event data.

        Args:
            key: Key within data to look up.
            loader: Callable that validates/constructs the nested model.
            allowed_types: Event types eligible for extraction.

        Returns:
            Validated model instance or None if unavailable or invalid.
        """
        if allowed_types is not None and self.type not in allowed_types:
            return None

        payload: object | None = self.data.get(key)
        if payload is None:
            return None

        try:
            result = loader(payload)
        except ValidationError as exc:
            fields: set[str] = {
                ".".join(str(p) for p in e.get("loc", ())) or key for e in exc.errors()
            }
            _logger.warning(
                "Invalid %s in event %s (invalid fields: %s)",
                key,
                self.id,
                ", ".join(sorted(fields)),
            )
            return None

        return result
