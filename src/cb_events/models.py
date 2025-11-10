"""Data models for Chaturbate Events API."""

from __future__ import annotations

import logging
from enum import StrEnum
from functools import cached_property
from typing import TYPE_CHECKING, Any, TypeVar

from pydantic import BaseModel, Field, ValidationError
from pydantic.alias_generators import to_camel
from pydantic.config import ConfigDict

if TYPE_CHECKING:
    from collections.abc import Callable


logger: logging.Logger = logging.getLogger(__name__)
"""Logger for the cb_events.models module."""


class BaseEventModel(BaseModel):
    """Base for all event models with snake_case conversion."""

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        extra="forbid",
        frozen=True,
    )


_ModelT = TypeVar("_ModelT", bound=BaseEventModel)
"""Type variable for BaseEventModel subclasses (User, Tip, Message, etc.)."""


class EventType(StrEnum):
    """Event types from the Chaturbate Events API."""

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


class User(BaseEventModel):
    """User information from events."""

    username: str
    """Display name of the user."""
    color_group: str | None = None
    """Color group of the user."""
    fc_auto_renew: bool = False
    """Whether the user has enabled fan club auto-renewal."""
    gender: str | None = None
    """Gender of the user."""
    has_darkmode: bool = False
    """Whether the user has dark mode enabled."""
    has_tokens: bool = False
    """Whether the user has tokens."""
    in_fanclub: bool = False
    """Whether the user is in the fan club."""
    in_private_show: bool = False
    """Whether the user is in a private show."""
    is_broadcasting: bool = False
    """Whether the user is broadcasting."""
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
    """Language preference of the user."""
    recent_tips: str | None = None
    """Recent tips information."""
    subgender: str | None = None
    """Subgender of the user."""


class Message(BaseEventModel):
    """Chat or private message."""

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
    """Tip transaction."""

    tokens: int
    """Number of tokens tipped."""
    is_anon: bool = False
    """Whether the tip is anonymous."""
    message: str | None = None
    """Optional message attached to the tip."""


class RoomSubject(BaseEventModel):
    """Room subject/title."""

    subject: str
    """The room subject or title."""


class Event(BaseEventModel):
    """Event from the Chaturbate Events API.

    Use properties to access nested data. Properties return None if
    data is missing or invalid for the event type.

    Note:
        Properties are cached after first access for performance. Invalid
        nested data is logged as a warning and returns None instead of raising.
    """

    type: EventType = Field(alias="method")
    """Type of the event."""
    id: str
    """Unique identifier for the event."""
    data: dict[str, Any] = Field(default_factory=dict, alias="object")
    """Event data payload."""

    @cached_property
    def user(self) -> User | None:
        """User data if present and valid."""
        return self._extract("user", User.model_validate)

    @cached_property
    def tip(self) -> Tip | None:
        """Tip data if present and valid (TIP events only)."""
        return self._extract(
            "tip",
            Tip.model_validate,
            allowed_types=(EventType.TIP,),
        )

    @cached_property
    def message(self) -> Message | None:
        """Message data if present and valid."""
        return self._extract(
            "message",
            Message.model_validate,
            allowed_types=(EventType.CHAT_MESSAGE, EventType.PRIVATE_MESSAGE),
        )

    @cached_property
    def room_subject(self) -> RoomSubject | None:
        """Room subject if present and valid (ROOM_SUBJECT_CHANGE only)."""
        return self._extract(
            "subject",
            RoomSubject.model_validate,
            allowed_types=(EventType.ROOM_SUBJECT_CHANGE,),
            transform=lambda v: {"subject": v},
        )

    @cached_property
    def broadcaster(self) -> str | None:
        """Broadcaster username if present."""
        value: Any | None = self.data.get("broadcaster")
        return value if isinstance(value, str) and value else None

    def _extract(
        self,
        key: str,
        loader: Callable[[object], _ModelT],
        *,
        allowed_types: tuple[EventType, ...] | None = None,
        transform: Callable[[object], object] | None = None,
    ) -> _ModelT | None:
        """Extract and validate nested model from event data.

        Returns:
            Validated model instance or None if unavailable/invalid.
        """
        if allowed_types and self.type not in allowed_types:
            return None

        payload: Any | None = self.data.get(key)
        if payload is None:
            return None

        if transform:
            payload = transform(payload)

        try:
            return loader(payload)
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
            return None
