"""Data models for the Chaturbate Events API."""

import logging
from collections.abc import Callable
from enum import StrEnum
from typing import Any, TypeVar, cast

from pydantic import BaseModel, Field, ValidationError
from pydantic.alias_generators import to_snake
from pydantic.config import ConfigDict

from .constants import (
    FIELD_BROADCASTER,
    FIELD_MESSAGE,
    FIELD_SUBJECT,
    FIELD_TIP,
    FIELD_USER,
)

logger = logging.getLogger(__name__)
"""Logger for models module."""


class BaseEventModel(BaseModel):
    """Base model for event-related models.

    Converts API camelCase to snake_case, freezes instances for immutability,
    and forbids extra fields.

    Note:
        extra="forbid" will raise ValidationError if the API returns unexpected
        fields.
    """

    model_config = ConfigDict(
        alias_generator=to_snake,
        populate_by_name=True,
        extra="forbid",
        frozen=True,
    )


class EventType(StrEnum):
    """Event types from the Chaturbate Events API.

    String constants for type-safe event checking and router registration.
    """

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
    """User information from events.

    User data including auth status, permissions, display preferences, and state.
    Booleans default to False, strings to empty.

    Attributes:
        username: Chaturbate username.
        color_group: Chat display color group.
        fc_auto_renew: Fanclub auto-renewal enabled.
        gender: Gender identity.
        has_darkmode: Dark mode enabled.
        has_tokens: Currently has tokens.
        in_fanclub: Fanclub member.
        in_private_show: Currently in private show.
        is_broadcasting: Currently broadcasting.
        is_follower: Following the broadcaster.
        is_mod: Room moderator.
        is_owner: Room owner/broadcaster.
        is_silenced: Silenced in chat.
        is_spying: Spying on private show.
        language: Preferred language code.
        recent_tips: Recent tips representation.
        subgender: Subgender identity.
    """

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
    """Message content and metadata.

    Chat message text with formatting and routing info for public and private
    messages. Use is_private to distinguish message types.

    Attributes:
        message: Message text.
        bg_color: Background color (optional).
        color: Text color.
        font: Font style.
        orig: Original text before processing (optional).
        from_user: Sender username for private messages (optional).
        to_user: Recipient username for private messages (optional).
    """

    message: str
    bg_color: str | None = Field(default=None, alias="bgColor")
    color: str = Field(default="")
    font: str = Field(default="default")
    orig: str | None = Field(default=None)
    from_user: str | None = Field(default=None, alias="fromUser")
    to_user: str | None = Field(default=None, alias="toUser")

    @property
    def is_private(self) -> bool:
        """Check if message is private.

        Returns:
            True if private message (has both from_user and to_user).
        """
        return self.from_user is not None and self.to_user is not None


class Tip(BaseEventModel):
    """Tip transaction details.

    Token amount and metadata including anonymous status and optional message.

    Attributes:
        tokens: Tokens tipped.
        is_anon: Sent anonymously.
        message: Optional tip message.
    """

    tokens: int
    is_anon: bool = Field(default=False, alias="isAnon")
    message: str = Field(default="")


class RoomSubject(BaseEventModel):
    """Room subject from subject change events.

    Updated room subject/title displayed at the top of the chat room.

    Attributes:
        subject: New room subject text.
    """

    subject: str


T = TypeVar("T")


class Event(BaseEventModel):
    """Event from the Chaturbate Events API.

    Type-safe access to event data through properties.

    Important:
        Properties return None for incompatible event types. For example,
        event.tip returns None for non-TIP events. Check the event type or
        verify the property is not None before accessing attributes.

    Attributes:
        type: Event type (e.g., TIP, CHAT_MESSAGE, USER_ENTER).
        id: Unique event identifier.
        data: Raw event data dictionary.
    """

    type: EventType = Field(alias="method")
    id: str
    data: dict[str, Any] = Field(default_factory=dict, alias="object")

    def _get_cached_value(self, attr: str, factory: Callable[[], T]) -> T:
        cache = cast("dict[str, Any]", self.__dict__.setdefault("_cache", {}))
        if attr in cache:
            return cast("T", cache[attr])

        value = factory()
        cache[attr] = value
        return value

    @property
    def user(self) -> User | None:
        """Get user info from this event.

        Returns:
            User object if user data present and valid, None otherwise.
        """
        return self._get_cached_value("_cached_user", self._build_user)

    def _build_user(self) -> User | None:
        if (user_data := self.data.get(FIELD_USER)) is not None:
            try:
                return User.model_validate(user_data)
            except ValidationError as e:
                logger.warning("Invalid user data in event %s: %s", self.id, e)
        return None

    @property
    def tip(self) -> Tip | None:
        """Get tip info for tip events.

        Returns:
            Tip object for tip events with valid tip data, None otherwise.
        """
        return self._get_cached_value("_cached_tip", self._build_tip)

    def _build_tip(self) -> Tip | None:
        if self.type == EventType.TIP and (tip_data := self.data.get(FIELD_TIP)) is not None:
            try:
                return Tip.model_validate(tip_data)
            except ValidationError as e:
                logger.warning("Invalid tip data in event %s: %s", self.id, e)
        return None

    @property
    def message(self) -> Message | None:
        """Get message info for chat and private message events.

        Returns:
            Message object for message events with valid message data, None otherwise.
        """
        return self._get_cached_value("_cached_message", self._build_message)

    def _build_message(self) -> Message | None:
        if (
            self.type in {EventType.CHAT_MESSAGE, EventType.PRIVATE_MESSAGE}
            and (message_data := self.data.get(FIELD_MESSAGE)) is not None
        ):
            try:
                return Message.model_validate(message_data)
            except ValidationError as e:
                logger.warning("Invalid message data in event %s: %s", self.id, e)
        return None

    @property
    def room_subject(self) -> RoomSubject | None:
        """Get room subject for subject change events.

        Returns:
            RoomSubject object for subject change events with valid data, None otherwise.
        """
        return self._get_cached_value("_cached_room_subject", self._build_room_subject)

    def _build_room_subject(self) -> RoomSubject | None:
        if self.type == EventType.ROOM_SUBJECT_CHANGE and FIELD_SUBJECT in self.data:
            try:
                return RoomSubject.model_validate({FIELD_SUBJECT: self.data[FIELD_SUBJECT]})
            except ValidationError as e:
                logger.warning("Invalid room subject data in event %s: %s", self.id, e)
        return None

    @property
    def broadcaster(self) -> str | None:
        """Get broadcaster username from this event.

        Returns:
            Broadcaster username if present, otherwise None.
        """
        return self.data.get(FIELD_BROADCASTER)
