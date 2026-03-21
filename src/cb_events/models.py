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

import logging
from collections.abc import Callable
from enum import StrEnum
from functools import cached_property
from typing import ClassVar, Literal

from pydantic import BaseModel, Field, ValidationError
from pydantic.alias_generators import to_camel
from pydantic.config import ConfigDict

logger: logging.Logger = logging.getLogger(__name__)
"""Logger for the cb_events.models module."""


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


class BaseEventModel(BaseModel):
    """Base model for all event-related data structures.

    Provides shared Pydantic configuration for JSON deserialization with
    camelCase to snake_case conversion and immutability. All event data models
    should inherit from this base class to ensure consistent behavior when
    parsing API responses.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(
        alias_generator=to_camel,
        extra="ignore",
        frozen=True,
    )


class User(BaseEventModel):
    """User information attached to events.

    Contains details about the user who triggered the event, including
    display name, membership status, and various flags.
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
    """

    subject: str
    """The room subject or title."""


class Event(BaseEventModel):
    """Event from the Chaturbate Events API.

    The main event container that wraps all event types. Use the typed
    properties to access nested data safely—they return None if data is missing
    or invalid for the event type.

    Example:
        Safe access to nested data::

            if event.type == EventType.TIP:
                if tip := event.tip:
                    print(f"Tip: {tip.tokens} tokens")
                if user := event.user:
                    print(f"From: {user.username}")

    Note:
        Failures to parse nested data are logged as a warning and return None.

    Warning:
        All string fields in event data (e.g. ``message.message``,
        ``user.username``, ``tip.message``) originate from untrusted
        user input and are not sanitized by this library. Escape or
        validate them before use in HTML, SQL, or shell contexts.
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
        return self._extract(
            "message",
            Message.model_validate,
            allowed_types=(
                EventType.CHAT_MESSAGE,
                EventType.PRIVATE_MESSAGE,
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
        return self._extract(
            "tip",
            Tip.model_validate,
            allowed_types=(EventType.TIP,),
        )

    @cached_property
    def media(self) -> Media | None:
        """Media purchase data if present and valid (MEDIA_PURCHASE only)."""
        return self._extract(
            "media",
            Media.model_validate,
            allowed_types=(EventType.MEDIA_PURCHASE,),
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

    def _extract[T: BaseEventModel](
        self,
        key: str,
        loader: Callable[[object], T],
        *,
        allowed_types: tuple[EventType, ...] | None = None,
        transform: Callable[[object], object] | None = None,
    ) -> T | None:
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
