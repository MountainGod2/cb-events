"""Pydantic event models used by cb_events.

Models are immutable and accept camelCase API payloads while exposing
snake_case attributes.
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import TYPE_CHECKING, ClassVar, Final, Literal, TypeVar, cast

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


_BaseEventModelT = TypeVar("_BaseEventModelT", bound=BaseEventModel)

UserColorGroup = Literal["o", "m", "f", "l", "p", "tr", "t", "g"]
"""Allowed values for User.color_group."""

UserGender = Literal["m", "f", "c", "t"]
"""Allowed values for User.gender."""

UserLanguage = Literal["de", "en", "es", "fr", "it", "ja", "ko", "pl", "pt", "ru", "zh"]
"""Allowed values for User.language."""

UserRecentTips = Literal["none", "few", "some", "lots", "tons"]
"""Allowed values for User.recent_tips."""

UserSubgender = Literal["tf", "tm", "tn"]
"""Allowed values for User.subgender."""


class User(BaseEventModel):
    """User metadata attached to an event."""

    username: str
    """Display name of the user."""
    color_group: UserColorGroup | None = None
    """User name-color group.

    Known values: ``"o"`` (owner), ``"m"`` (moderator), ``"f"`` (fanclub),
    ``"l"`` (dark purple), ``"p"`` (light purple), ``"tr"`` (dark blue),
    ``"t"`` (light blue), ``"g"`` (grey).
    """
    fc_auto_renew: bool = False
    """Whether the user's fanclub membership is a recurring subscription."""
    gender: UserGender | None = None
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
    language: UserLanguage | None = None
    """User's preferred language.

    Known values: ``"de"`` (German), ``"en"`` (English), ``"es"`` (Spanish),
    ``"fr"`` (French), ``"it"`` (Italian), ``"ja"`` (Japanese),
    ``"ko"`` (Korean), ``"pl"`` (Polish), ``"pt"`` (Portuguese),
    ``"ru"`` (Russian), ``"zh"`` (Chinese).
    """
    recent_tips: UserRecentTips | None = None
    """Recent tipping activity bucket.

    Possible values: "none", "few", "some", "lots", "tons".

    Note:
        The string value "none" is truthy. Compare explicitly with
        recent_tips is None versus recent_tips == "none".
    """
    subgender: UserSubgender | None = None
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
    type: Literal["video", "photos"]
    """Type of the purchased media."""
    tokens: int
    """Number of tokens spent on the media purchase."""


class RoomSubject(BaseEventModel):
    """Payload for roomSubjectChange events."""

    subject: str
    """The room subject or title."""


_SENTINEL: Final[object] = object()
"""Sentinel value for Event accessor cache misses."""


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
    # PrivateAttr is exempt from frozen - mutation is intentional.
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
    def broadcaster(self) -> str | None:
        """Broadcaster username, or ``None`` if missing or invalid."""
        return self._extract_non_empty_string("broadcaster")

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

    def _extract_non_empty_string(self, key: str) -> str | None:
        """Extract a non-empty string from event data.

        Results are cached after the first lookup.

        Args:
            key: Key within data to look up.

        Returns:
            The string value, or None if missing, empty, or not a string.
        """
        cache_key = f"str:{key}"

        cache = self._cache
        cached = cache.get(cache_key, _SENTINEL)
        if cached is not _SENTINEL:
            return cast("str | None", cached)

        value: object | None = self.data.get(key)
        if isinstance(value, str) and value:
            result: str | None = value
        else:
            result = None

        cache[cache_key] = result
        return result

    def _extract(
        self,
        key: str,
        loader: Callable[[object], _BaseEventModelT],
        *,
        allowed_types: tuple[EventType, ...] | None = None,
    ) -> _BaseEventModelT | None:
        """Extract and validate nested model from event data.

        Results are cached after the first parse.

        Args:
            key: Key within data to look up.
            loader: Callable that validates/constructs the nested model.
            allowed_types: Event types eligible for extraction.

        Returns:
            Validated model instance or None if unavailable or invalid.
        """
        if allowed_types is not None and self.type not in allowed_types:
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
                ".".join(str(p) for p in e.get("loc", ())) or key for e in exc.errors()
            }
            _logger.warning(
                "Invalid %s in event %s (invalid fields: %s)",
                key,
                self.id,
                ", ".join(sorted(fields)),
            )
            cache[key] = None
            return None

        cache[key] = result
        return result
