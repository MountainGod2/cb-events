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


class BaseEventModel(BaseModel):
    """Base for all event models with snake_case conversion."""

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        extra="forbid",
        frozen=True,
    )


_ModelT = TypeVar("_ModelT", bound=BaseEventModel)


class EventType(StrEnum):
    """Event types from the Chaturbate Events API."""

    BROADCAST_START = "broadcastStart"
    BROADCAST_STOP = "broadcastStop"
    ROOM_SUBJECT_CHANGE = "roomSubjectChange"
    USER_ENTER = "userEnter"
    USER_LEAVE = "userLeave"
    FOLLOW = "follow"
    UNFOLLOW = "unfollow"
    FANCLUB_JOIN = "fanclubJoin"
    CHAT_MESSAGE = "chatMessage"
    PRIVATE_MESSAGE = "privateMessage"
    TIP = "tip"
    MEDIA_PURCHASE = "mediaPurchase"


class User(BaseEventModel):
    """User information from events."""

    username: str
    color_group: str | None = None
    fc_auto_renew: bool = False
    gender: str | None = None
    has_darkmode: bool = False
    has_tokens: bool = False
    in_fanclub: bool = False
    in_private_show: bool = False
    is_broadcasting: bool = False
    is_follower: bool = False
    is_mod: bool = False
    is_owner: bool = False
    is_silenced: bool = False
    is_spying: bool = False
    language: str | None = None
    recent_tips: str | None = None
    subgender: str | None = None


class Message(BaseEventModel):
    """Chat or private message."""

    message: str
    bg_color: str | None = None
    color: str | None = None
    font: str | None = None
    orig: str | None = None
    from_user: str | None = None
    to_user: str | None = None

    @property
    def is_private(self) -> bool:
        """True if this is a private message."""
        return self.from_user is not None and self.to_user is not None


class Tip(BaseEventModel):
    """Tip transaction."""

    tokens: int
    is_anon: bool = False
    message: str | None = None


class RoomSubject(BaseEventModel):
    """Room subject/title."""

    subject: str


class Event(BaseEventModel):
    """Event from the Chaturbate Events API.

    Use properties to access nested data. Properties return None if
    data is missing or invalid for the event type.
    """

    type: EventType = Field(alias="method")
    id: str
    data: dict[str, Any] = Field(default_factory=dict, alias="object")

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
                "Invalid %s in event %s: %s",
                key,
                self.id,
                ", ".join(sorted(fields)),
            )
            return None
