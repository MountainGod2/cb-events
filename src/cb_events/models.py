"""Data models for the Chaturbate Events API."""

from __future__ import annotations

import logging
from enum import StrEnum
from functools import cached_property
from typing import TYPE_CHECKING, Any, TypeVar

from pydantic import BaseModel, Field, ValidationError
from pydantic.alias_generators import to_snake
from pydantic.config import ConfigDict

if TYPE_CHECKING:
    from collections.abc import Callable


logger = logging.getLogger(__name__)


def _format_validation_errors(error: ValidationError) -> str:
    """Format validation error locations as a comma-separated string.

    Args:
        error: Validation error from Pydantic.

    Returns:
        Comma-separated field paths.
    """
    locations = {
        ".".join(str(part) for part in err.get("loc", ())) or "<root>"
        for err in error.errors()
    }
    return ", ".join(sorted(locations))


class BaseEventModel(BaseModel):
    """Base for all event models.

    Converts camelCase to snake_case, immutable, forbids extra fields.
    """

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
    """User information attached to events."""

    username: str
    color_group: str = Field(default="", alias="colorGroup")
    fc_auto_renew: bool = Field(default=False, alias="fcAutoRenew")
    gender: str = Field(default="")
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
    language: str = Field(default="")
    recent_tips: str = Field(default="", alias="recentTips")
    subgender: str = Field(default="")


class Message(BaseEventModel):
    """Chat or private message content."""

    message: str
    bg_color: str | None = Field(default=None, alias="bgColor")
    color: str = Field(default="")
    font: str = Field(default="default")
    orig: str | None = Field(default=None)
    from_user: str | None = Field(default=None, alias="fromUser")
    to_user: str | None = Field(default=None, alias="toUser")

    @property
    def is_private(self) -> bool:
        """True if this is a private message (has sender and recipient)."""
        return self.from_user is not None and self.to_user is not None


class Tip(BaseEventModel):
    """Tip transaction details."""

    tokens: int
    is_anon: bool = Field(default=False, alias="isAnon")
    message: str = Field(default="")


class RoomSubject(BaseEventModel):
    """Room subject/title text."""

    subject: str


class Event(BaseEventModel):
    """Event from the Chaturbate Events API.

    Properties like user, tip, message, and room_subject return None if the data
    is missing or invalid.
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
        value = self.data.get("broadcaster")
        return value if isinstance(value, str) and value else None

    def _extract_model(
        self,
        *,
        key: str,
        loader: Callable[[object], _ModelT],
        allowed_types: tuple[EventType, ...] | None = None,
        transform: Callable[[object], object] | None = None,
    ) -> _ModelT | None:
        """Extract and validate a model from event data.

        Returns:
            Validated model or None if type doesn't match, data missing,
            or validation fails.
        """
        if allowed_types and self.type not in allowed_types:
            return None

        if key not in self.data:
            return None

        payload = self.data[key]
        if payload is None:
            logger.warning("event_id=%s locations=%s", self.id, key)
            return None

        if transform is not None:
            payload = transform(payload)

        try:
            return loader(payload)
        except ValidationError as exc:
            logger.warning(
                "event_id=%s locations=%s",
                self.id,
                _format_validation_errors(exc),
            )
            return None
