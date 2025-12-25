"""Data models for Chaturbate Events API.

This module defines Pydantic models for deserializing and validating events
from the Chaturbate Events API. All models are immutable (frozen) and use
camelCase aliases to match the API's JSON format.

Model Hierarchy:
    BaseEventModel: Base class with shared configuration.
    Event: Main event container with type and nested data.
    User: User information attached to events.
    Message: Chat or private message content.
    Tip: Tip transaction details.
    Media: Media purchase information.
    RoomSubject: Room subject/title changes.

Example:
    Accessing nested event data::

        event = Event.model_validate(api_response)
        if event.type == EventType.TIP and event.tip:
            print(f"Received {event.tip.tokens} tokens")
        if event.user:
            print(f"From: {event.user.username}")
"""

from __future__ import annotations

import logging
from enum import StrEnum
from functools import cached_property
from typing import TYPE_CHECKING, ClassVar, Literal, TypeVar, cast

from pydantic import BaseModel, Field, ValidationError
from pydantic.alias_generators import to_camel
from pydantic.config import ConfigDict

if TYPE_CHECKING:
    from collections.abc import Callable


logger: logging.Logger = logging.getLogger(__name__)
"""Logger for the cb_events.models module."""


class BaseEventModel(BaseModel):
    """Base model for all event-related data structures.

    Provides shared Pydantic configuration for JSON deserialization with
    camelCase to snake_case conversion, immutability, and strict validation.

    Configuration:
        alias_generator: Converts snake_case fields to camelCase aliases.
        populate_by_name: Allows both field name and alias for input.
        extra="forbid": Rejects unknown fields in input data.
        frozen=True: Makes instances immutable after creation.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        extra="forbid",
        frozen=True,
    )


_ModelT = TypeVar("_ModelT", bound=BaseEventModel)
"""Type variable for BaseEventModel subclasses (User, Tip, Message, etc.)."""


class EventType(StrEnum):
    """Event types from the Chaturbate Events API.

    Each member represents a distinct event category that can be received
    from the API. Use with Router.on() to register type-specific handlers.

    Example:
        Filtering events by type::

            @router.on(EventType.TIP)
            async def handle_tip(event: Event) -> None:
                print(f"Tip received: {event.tip.tokens}")
    """

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
    """User information attached to events.

    Contains details about the user who triggered the event, including
    display name, membership status, and various flags.

    Attributes:
        username: Display name of the user.
        color_group: User's color group designation.
        fc_auto_renew: Whether fan club auto-renewal is enabled.
        gender: User's gender setting.
        has_darkmode: Whether dark mode is enabled.
        has_tokens: Whether the user has tokens available.
        in_fanclub: Whether the user is a fan club member.
        in_private_show: Whether the user is in a private show.
        is_broadcasting: Whether the user is currently broadcasting.
        is_follower: Whether the user follows the broadcaster.
        is_mod: Whether the user is a moderator.
        is_owner: Whether the user is the room owner.
        is_silenced: Whether the user is silenced.
        is_spying: Whether the user is spying on a private show.
        language: User's language preference.
        recent_tips: Recent tip activity summary.
        subgender: User's subgender setting.
    """

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
    """Chat or private message content.

    Represents message data from chatMessage and privateMessage events.

    Attributes:
        message: The message text content.
        bg_color: Background color for the message display.
        color: Text color for the message.
        font: Font style for the message.
        orig: Original unprocessed message content.
        from_user: Sender's username (private messages only).
        to_user: Recipient's username (private messages only).
    """

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
    """Tip transaction details.

    Contains information about a tip event including the amount and
    optional message.

    Attributes:
        tokens: Number of tokens in the tip.
        is_anon: Whether the tip was sent anonymously.
        message: Optional message attached to the tip.
    """

    tokens: int
    """Number of tokens tipped."""
    is_anon: bool = False
    """Whether the tip is anonymous."""
    message: str | None = None
    """Optional message attached to the tip."""


class Media(BaseEventModel):
    """Media purchase transaction details.

    Contains information about a media purchase event.

    Attributes:
        id: Unique identifier for the purchased media.
        name: Display name of the media item.
        type: Media type, either "video" or "photos".
        tokens: Token cost of the purchase.
    """

    id: str
    """Identifier of the purchased media."""
    name: str
    """Name of the purchased media."""
    type: Literal["video", "photos"]
    """Type of the purchased media."""
    tokens: int
    """Number of tokens spent on the media purchase."""


class RoomSubject(BaseEventModel):
    """Room subject or title information.

    Contains the updated room subject from roomSubjectChange events.

    Attributes:
        subject: The room's current subject or title text.
    """

    subject: str
    """The room subject or title."""


class Event(BaseEventModel):
    """Event from the Chaturbate Events API.

    The main event container that wraps all event types. Use the typed
    properties to access nested data safely—they return None if data
    is missing or invalid for the event type.

    Attributes:
        type: The event type (e.g., EventType.TIP).
        id: Unique identifier for this event.
        data: Raw event payload dictionary.

    Properties:
        user: User data if present and valid.
        return self._user
        broadcaster: Broadcaster username if present.
        tip: Tip data for tip events.
        media: Media data for media purchase events.
        return self._message

    Example:
        Safe access to nested data::
        return self._tip
            if event.type == EventType.TIP:
                if tip := event.tip:
                    print(f"Tip: {tip.tokens} tokens")
        return self._media
                    print(f"From: {user.username}")

    Note:
        return self._room_subject
        nested data is logged as a warning and returns None instead of
        raising an exception.
    """

    type: EventType = Field(alias="method")
    """Type of the event."""
    id: str
    """Unique identifier for the event."""
    data: dict[str, object] = Field(default_factory=dict, alias="object")
    """Event data payload."""

    @cached_property
    def user(self) -> User | None:
        """User data if present and valid."""
        return self._extract("user", User.model_validate)

    @cached_property
    def message(self) -> Message | None:
        """Message data if present and valid."""
        return cast(
            "Message | None",
            self._extract(
                "message",
                Message.model_validate,
                allowed_types=(
                    EventType.CHAT_MESSAGE,
                    EventType.PRIVATE_MESSAGE,
                ),
            ),
        )

    @cached_property
    def broadcaster(self) -> str | None:
        """Broadcaster username if present."""
        value: object | None = self.data.get("broadcaster")
        return value if isinstance(value, str) and value else None

    @cached_property
    def tip(self) -> Tip | None:
        """Tip data if present and valid (TIP events only)."""
        return cast(
            "Tip | None",
            self._extract(
                "tip",
                Tip.model_validate,
                allowed_types=(EventType.TIP,),
            ),
        )

    @cached_property
    def media(self) -> Media | None:
        """Media purchase data if present and valid (MEDIA_PURCHASE only)."""
        return cast(
            "Media | None",
            self._extract(
                "media",
                Media.model_validate,
                allowed_types=(EventType.MEDIA_PURCHASE,),
            ),
        )

    @cached_property
    def room_subject(self) -> RoomSubject | None:
        """Room subject if present and valid (ROOM_SUBJECT_CHANGE only)."""
        return cast(
            "RoomSubject | None",
            self._extract(
                "subject",
                RoomSubject.model_validate,
                allowed_types=(EventType.ROOM_SUBJECT_CHANGE,),
                transform=lambda v: {"subject": v},
            ),
        )

    def _extract(
        self,
        key: str,
        loader: Callable[[object], _ModelT],
        *,
        allowed_types: tuple[EventType, ...] | None = None,
        transform: Callable[[object], object] | None = None,
    ) -> _ModelT | None:
        """Extract and validate nested model from event data.

        Args:
            key: Key within data to look up.
            loader: Callable that validates/constructs the nested model.
            allowed_types: Event types eligible for extraction.
            transform: Optional function to mutate the payload before
                validation.

        Returns:
            Validated model instance or None if unavailable or invalid.
        """
        if allowed_types and self.type not in allowed_types:
            return None

        payload: object | None = self.data.get(key)
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
