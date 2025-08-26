# pylint: disable=no-member
"""Data models for the Chaturbate Events API.

This module contains the data models used to represent events and related data
from the Chaturbate Events API. It provides strongly-typed classes for all event
types and their associated data structures.
"""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field
from pydantic.alias_generators import to_snake
from pydantic.config import ConfigDict


class EventType(StrEnum):
    """Event types supported by the Chaturbate Events API.

    These constants represent all the possible event types that can be
    received from the Events API. Use these for type checking and routing.
    """

    # Broadcast state events
    BROADCAST_START = "broadcastStart"
    BROADCAST_STOP = "broadcastStop"
    ROOM_SUBJECT_CHANGE = "roomSubjectChange"

    # User activity events
    USER_ENTER = "userEnter"
    USER_LEAVE = "userLeave"
    FOLLOW = "follow"
    UNFOLLOW = "unfollow"
    FANCLUB_JOIN = "fanclubJoin"

    # Content events
    CHAT_MESSAGE = "chatMessage"
    PRIVATE_MESSAGE = "privateMessage"
    TIP = "tip"
    MEDIA_PURCHASE = "mediaPurchase"


class User(BaseModel):
    """User information from events."""

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

    model_config = ConfigDict(
        alias_generator=to_snake,
        populate_by_name=True,
        extra="ignore",
        frozen=True,
    )


class Message(BaseModel):
    """Chat message content from message events."""

    message: str
    bg_color: str | None = Field(default=None, alias="bgColor")
    color: str = Field(default="")
    font: str = Field(default="default")
    orig: str | None = Field(default=None)
    # Private message specific fields
    from_user: str | None = Field(default=None, alias="fromUser")
    to_user: str | None = Field(default=None, alias="toUser")

    model_config = ConfigDict(
        alias_generator=to_snake,
        populate_by_name=True,
        extra="ignore",
        frozen=True,
    )


class Tip(BaseModel):
    """Tip information from tip events."""

    tokens: int
    is_anon: bool = Field(default=False, alias="isAnon")
    message: str = Field(default="")

    model_config = ConfigDict(
        alias_generator=to_snake,
        populate_by_name=True,
        extra="ignore",
        frozen=True,
    )


class RoomSubject(BaseModel):
    """Room subject information from subject change events."""

    subject: str

    model_config = ConfigDict(
        alias_generator=to_snake,
        populate_by_name=True,
        extra="ignore",
        frozen=True,
    )


class Event(BaseModel):
    """Event from the Chaturbate Events API."""

    type: EventType = Field(alias="method")
    id: str
    data: dict[str, Any] = Field(default_factory=dict, alias="object")

    model_config = ConfigDict(
        alias_generator=to_snake,
        populate_by_name=True,
        extra="ignore",
        frozen=True,
    )

    @property
    def user(self) -> User | None:
        """The user associated with this event."""
        if user_data := self.data.get("user"):
            return User.model_validate(user_data)
        return None

    @property
    def tip(self) -> Tip | None:
        """Tip information if this is a tip event."""
        if self.type == EventType.TIP and (tip_data := self.data.get("tip")):
            return Tip.model_validate(tip_data)
        return None

    @property
    def message(self) -> Message | None:
        """Message information if this is a message event."""
        if self.type in {EventType.CHAT_MESSAGE, EventType.PRIVATE_MESSAGE} and (
            message_data := self.data.get("message")
        ):
            return Message.model_validate(message_data)
        return None

    @property
    def room_subject(self) -> RoomSubject | None:
        """Room subject information if this is a room subject change event."""
        if self.type == EventType.ROOM_SUBJECT_CHANGE and "subject" in self.data:
            return RoomSubject.model_validate({"subject": self.data["subject"]})
        return None

    @property
    def broadcaster(self) -> str | None:
        """The broadcaster associated with this event."""
        return self.data.get("broadcaster")
