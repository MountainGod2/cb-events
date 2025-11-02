"""Data models for the Chaturbate Events API."""

import logging
from enum import StrEnum
from functools import cached_property
from typing import Any

from pydantic import BaseModel, Field, ValidationError
from pydantic.alias_generators import to_snake
from pydantic.config import ConfigDict

from ._utils import format_validation_error_locations
from .constants import FIELD_BROADCASTER, FIELD_MESSAGE, FIELD_SUBJECT, FIELD_TIP, FIELD_USER

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


class Event(BaseEventModel):
    """Normalized event payload from the Chaturbate Events API.

    Provides typed helpers for optional payload fragments such as user, tip, and
    subject data. Accessors return ``None`` when the data is missing or fails
    validation.
    """

    type: EventType = Field(alias="method")
    id: str
    data: dict[str, Any] = Field(default_factory=dict, alias="object")

    @cached_property
    def user(self) -> User | None:
        """Attached user payload if present and valid.

        Returns:
            Parsed :class:`User` payload or ``None`` when missing or invalid.
        """
        return self._build_user()

    def _build_user(self) -> User | None:
        """Parse the embedded user payload if present.

        Returns:
            Validated :class:`User` model or ``None`` when parsing fails.
        """
        user_data = self.data.get(FIELD_USER)
        if user_data is None:
            return None
        try:
            return User.model_validate(user_data)
        except ValidationError as exc:
            logger.warning(
                "event_id=%s locations=%s",
                self.id,
                format_validation_error_locations(exc),
            )
            return None

    @cached_property
    def tip(self) -> Tip | None:
        """Tip payload for tip events.

        Returns:
            Parsed :class:`Tip` payload or ``None`` when missing or invalid.
        """
        return self._build_tip()

    def _build_tip(self) -> Tip | None:
        """Parse tip payload for tip events.

        Returns:
            Validated :class:`Tip` model or ``None`` when parsing fails.
        """
        if self.type != EventType.TIP:
            return None
        tip_data = self.data.get(FIELD_TIP)
        if tip_data is None:
            return None
        try:
            return Tip.model_validate(tip_data)
        except ValidationError as exc:
            logger.warning(
                "event_id=%s locations=%s",
                self.id,
                format_validation_error_locations(exc),
            )
            return None

    @cached_property
    def message(self) -> Message | None:
        """Chat or private message payload if available.

        Returns:
            Parsed :class:`Message` payload or ``None`` when unavailable.
        """
        return self._build_message()

    def _build_message(self) -> Message | None:
        """Parse message payload for chat or private message events.

        Returns:
            Validated :class:`Message` model or ``None`` when parsing fails.
        """
        if self.type not in {EventType.CHAT_MESSAGE, EventType.PRIVATE_MESSAGE}:
            return None
        message_data = self.data.get(FIELD_MESSAGE)
        if message_data is None:
            return None
        try:
            return Message.model_validate(message_data)
        except ValidationError as exc:
            logger.warning(
                "event_id=%s locations=%s",
                self.id,
                format_validation_error_locations(exc),
            )
            return None

    @cached_property
    def room_subject(self) -> RoomSubject | None:
        """Room subject payload for subject change events.

        Returns:
            Parsed :class:`RoomSubject` payload or ``None`` when unavailable.
        """
        return self._build_room_subject()

    def _build_room_subject(self) -> RoomSubject | None:
        """Parse room subject payload for subject change events.

        Returns:
            Validated :class:`RoomSubject` model or ``None`` when parsing fails.
        """
        if self.type != EventType.ROOM_SUBJECT_CHANGE:
            return None
        if FIELD_SUBJECT not in self.data:
            return None
        try:
            return RoomSubject.model_validate({FIELD_SUBJECT: self.data[FIELD_SUBJECT]})
        except ValidationError as exc:
            logger.warning(
                "event_id=%s locations=%s",
                self.id,
                format_validation_error_locations(exc),
            )
            return None

    @cached_property
    def broadcaster(self) -> str | None:
        """Broadcaster username when present in the payload.

        Returns:
            Broadcaster username or ``None`` when absent or empty.
        """
        value = self.data.get(FIELD_BROADCASTER)
        return value if isinstance(value, str) and value else None
