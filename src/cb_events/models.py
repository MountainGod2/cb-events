"""Data models for Chaturbate Events API."""

from __future__ import annotations

import logging
from enum import StrEnum
from functools import cached_property
from logging import Logger
from typing import TYPE_CHECKING, Any, TypeVar

from pydantic import BaseModel, Field, ValidationError
from pydantic.alias_generators import to_snake
from pydantic.config import ConfigDict

if TYPE_CHECKING:
    from collections.abc import Callable


logger: Logger = logging.getLogger(__name__)


class BaseEventModel(BaseModel):
    """Base for all event models with snake_case conversion."""

    model_config = ConfigDict(
        alias_generator=to_snake,
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
    color_group: str | None = Field(default=None, alias="colorGroup")
    fc_auto_renew: bool = Field(default=False, alias="fcAutoRenew")
    gender: str | None = Field(default=None)
    has_darkmode: bool = Field(default=False, alias="hasDarkmode")
    has_tokens: bool = Field(default=False, alias="hasTokens")
    in_fanclub: bool = Field(default=False, alias="inFanclub")
    in_private_show: bool = Field(default=False, alias="inPrivateShow")
    is_broadcasting: bool = Field(default=False, alias="isBroadcasting")
    is_follower: bool = Field(default=False, alias="isFollower")
    is_mod: bool = Field(default=False, alias="isMod")
    is_owner: bool = Field(default=False, alias="isOwner")
    is_silenced: bool = Field(default=False, alias="isSilenced")
    is_spying: bool = Field(default=False, alias="isSpying")
    language: str | None = Field(default=None)
    recent_tips: str | None = Field(default=None, alias="recentTips")
    subgender: str | None = Field(default=None)


class Message(BaseEventModel):
    """Chat or private message."""

    message: str
    bg_color: str | None = Field(default=None, alias="bgColor")
    color: str | None = Field(default=None)
    font: str | None = Field(default=None)
    orig: str | None = Field(default=None)
    from_user: str | None = Field(default=None, alias="fromUser")
    to_user: str | None = Field(default=None, alias="toUser")

    @property
    def is_private(self) -> bool:
        """True if this is a private message (has sender and recipient)."""
        return self.from_user is not None and self.to_user is not None


class Tip(BaseEventModel):
    """Tip transaction."""

    tokens: int
    is_anon: bool = Field(default=False, alias="isAnon")
    message: str | None = Field(default=None)


class RoomSubject(BaseEventModel):
    """Room subject/title."""

    subject: str


class Event(BaseEventModel):
    """Event from the Chaturbate Events API.

    Use properties (user, tip, message, room_subject) to access nested data.
    Properties return None if data is missing or invalid for the event type.
    """

    type: EventType = Field(alias="method")
    id: str
    data: dict[str, Any] = Field(default_factory=dict, alias="object")

    @cached_property
    def user(self) -> User | None:
        """User data if present and valid."""
        return self._extract_model(key="user", loader=User.model_validate)

    @cached_property
    def tip(self) -> Tip | None:
        """Tip data if present and valid (TIP events only)."""
        return self._extract_model(
            key="tip",
            loader=Tip.model_validate,
            allowed_types=(EventType.TIP,),
        )

    @cached_property
    def message(self) -> Message | None:
        """Message data if present and valid.

        Only for CHAT_MESSAGE/PRIVATE_MESSAGE events.
        """
        return self._extract_model(
            key="message",
            loader=Message.model_validate,
            allowed_types=(EventType.CHAT_MESSAGE, EventType.PRIVATE_MESSAGE),
        )

    @cached_property
    def room_subject(self) -> RoomSubject | None:
        """Room subject if present and valid (ROOM_SUBJECT_CHANGE only)."""
        return self._extract_model(
            key="subject",
            loader=RoomSubject.model_validate,
            allowed_types=(EventType.ROOM_SUBJECT_CHANGE,),
            transform=lambda value: {"subject": value},
        )

    @cached_property
    def broadcaster(self) -> str | None:
        """Broadcaster username if present."""
        value: Any | None = self.data.get("broadcaster")
        return value if isinstance(value, str) and value else None

    def _extract_model(
        self,
        *,
        key: str,
        loader: Callable[[object], _ModelT],
        allowed_types: tuple[EventType, ...] | None = None,
        transform: Callable[[object], object] | None = None,
    ) -> _ModelT | None:
        """Extract and validate a nested model from event data.

        Args:
            key: Field name in event data.
            loader: Model validator function.
            allowed_types: Event types allowed to have this field.
            transform: Transform raw data before validation.

        Returns:
            Validated model or None if unavailable/invalid.
        """
        if allowed_types and self.type not in allowed_types:
            return None

        payload = self.data.get(key)
        if payload is None:
            return None

        if transform is not None:
            payload = transform(payload)

        try:
            return loader(payload)
        except ValidationError as exc:
            locations: set[str] = {
                ".".join(str(p) for p in e.get("loc", ())) or key
                for e in exc.errors()
            }
            logger.warning(
                "Invalid %s in event %s: %s",
                key,
                self.id,
                ", ".join(sorted(locations)),
            )
            return None
