"""Data models for the Chaturbate Events API."""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field
from pydantic.alias_generators import to_snake
from pydantic.config import ConfigDict


class BaseEventModel(BaseModel):
    """Base model with shared configuration for all event-related models.

    Provides common Pydantic configuration including automatic snake_case
    conversion from API camelCase, frozen instances for immutability, and
    extra field ignoring for forward compatibility.
    """

    model_config = ConfigDict(
        alias_generator=to_snake,
        populate_by_name=True,
        extra="ignore",
        frozen=True,
    )


class EventType(StrEnum):
    """Supported event types from the Chaturbate Events API.

    Defines string constants for all event types that can be received from the
    API. Use these constants for type-safe event type checking and event handler
    registration with the EventRouter.
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
    """User information from Chaturbate events.

    Represents user data associated with various event types including
    authentication status, permissions, display preferences, and user state.
    All boolean fields default to False, and string fields default to empty
    strings to handle optional data from the API.

    Attributes:
        username: The user's Chaturbate username.
        color_group: User's color group for chat display.
        fc_auto_renew: Whether the user has fanclub auto-renewal enabled.
        gender: User's gender identity.
        has_darkmode: Whether the user has dark mode enabled.
        has_tokens: Whether the user currently has tokens.
        in_fanclub: Whether the user is a fanclub member.
        in_private_show: Whether the user is currently in a private show.
        is_broadcasting: Whether the user is currently broadcasting.
        is_follower: Whether the user is following the broadcaster.
        is_mod: Whether the user is a room moderator.
        is_owner: Whether the user is the room owner/broadcaster.
        is_silenced: Whether the user is silenced in chat.
        is_spying: Whether the user is spying on a private show.
        language: User's preferred language code.
        recent_tips: String representation of the user's recent tips.
        subgender: User's subgender identity.
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
    """Chat message content and metadata from message events.

    Contains the message text along with formatting options and routing information
    for both public chat messages and private messages. The is_private property
    can be used to distinguish between chat and private message types.

    Attributes:
        message: The message text content.
        bg_color: Background color for the message (optional).
        color: Text color for the message.
        font: Font style for the message (defaults to 'default').
        orig: Original message text before processing (optional).
        from_user: Username of the sender for private messages (optional).
        to_user: Username of the recipient for private messages (optional).
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
        """Check if this message is a private message.

        Returns:
            True if this is a private message (has both from_user and to_user),
            False if this is a public chat message.
        """
        return bool(self.from_user and self.to_user)


class Tip(BaseEventModel):
    """Tip transaction details from tip events.

    Contains the token amount and metadata for tip transactions including
    anonymous tip status and optional tip messages that accompany the tip.

    Attributes:
        tokens: Number of tokens tipped.
        is_anon: Whether the tip was sent anonymously.
        message: Optional message sent with the tip.
    """

    tokens: int
    is_anon: bool = Field(default=False, alias="isAnon")
    message: str = Field(default="")


class RoomSubject(BaseEventModel):
    """Room subject information from subject change events.

    Contains the updated room subject/title when a broadcaster changes their
    room description. This is typically displayed at the top of the chat room.

    Attributes:
        subject: The new room subject text.
    """

    subject: str


class Event(BaseEventModel):
    """Event from the Chaturbate Events API.

    Represents a single event with type-safe access to associated data through
    properties. Event data is dynamically parsed based on the event type, providing
    strongly-typed access to user, tip, message, and room subject information.

    The raw event data is stored in the data dictionary and parsed on-demand
    through properties, ensuring type safety while maintaining flexibility for
    future API changes.

    Attributes:
        type: The type of event (e.g., TIP, CHAT_MESSAGE, USER_ENTER).
        id: Unique identifier for this event.
        data: Raw event data dictionary containing type-specific information.
    """

    type: EventType = Field(alias="method")
    id: str
    data: dict[str, Any] = Field(default_factory=dict, alias="object")

    @property
    def user(self) -> User | None:
        """Get user information associated with this event.

        Returns:
            User object if user data is present in the event, otherwise None.
        """
        if (user_data := self.data.get("user")) is not None:
            return User.model_validate(user_data)
        return None

    @property
    def tip(self) -> Tip | None:
        """Get tip information for tip events.

        Returns:
            Tip object if this is a tip event with tip data, otherwise None.
        """
        if self.type == EventType.TIP and (tip_data := self.data.get("tip")) is not None:
            return Tip.model_validate(tip_data)
        return None

    @property
    def message(self) -> Message | None:
        """Get message information for chat and private message events.

        Returns:
            Message object if this is a message event with message data,
            otherwise None.
        """
        if (
            self.type in {EventType.CHAT_MESSAGE, EventType.PRIVATE_MESSAGE}
            and (message_data := self.data.get("message")) is not None
        ):
            return Message.model_validate(message_data)
        return None

    @property
    def room_subject(self) -> RoomSubject | None:
        """Get room subject information for room subject change events.

        Returns:
            RoomSubject object if this is a room subject change event,
            otherwise None.
        """
        if self.type == EventType.ROOM_SUBJECT_CHANGE and "subject" in self.data:
            return RoomSubject.model_validate({"subject": self.data["subject"]})
        return None

    @property
    def broadcaster(self) -> str | None:
        """Get the broadcaster username associated with this event.

        Returns:
            The broadcaster username if present in the event data, otherwise None.
        """
        return self.data.get("broadcaster")
