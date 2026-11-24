"""Pydantic event models used by cb_events.

Models are immutable and accept camelCase API payloads while exposing
snake_case attributes.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator, Mapping
from copy import deepcopy
from dataclasses import dataclass
from enum import StrEnum
from functools import partial
from types import MappingProxyType
from typing import ClassVar, Generic, TypeVar, cast

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    ValidationError,
    field_serializer,
    field_validator,
    model_validator,
)
from pydantic.alias_generators import to_camel
from typing_extensions import override

_logger = logging.getLogger(__name__)
"""Logger for the cb_events.models module."""


class EventType(StrEnum):
    """Event type values emitted by the API."""

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
    UNKNOWN = "unknown"
    """Event type is unrecognized by this client version."""


class BaseEventModel(BaseModel):
    """Shared base model for event payload objects."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        alias_generator=to_camel,
        extra="ignore",
        frozen=True,
        hide_input_in_errors=True,
        populate_by_name=True,
        validate_default=True,
    )


_T = TypeVar("_T")


class User(BaseEventModel):
    """User metadata attached to an event."""

    username: str
    """Display name of the user."""
    color_group: str | None = None
    """User name-color group.

    Known values: ``"o"`` (owner), ``"m"`` (moderator), ``"f"`` (fanclub),
    ``"l"`` (dark purple), ``"p"`` (light purple), ``"tr"`` (dark blue),
    ``"t"`` (light blue), ``"g"`` (grey).
    """
    fc_auto_renew: bool = False
    """Whether the user's fanclub membership is a recurring subscription."""
    gender: str | None = None
    """User gender code.

    Known values: ``"m"`` (male), ``"f"`` (female), ``"c"`` (couple),
    ``"t"`` (trans).
    """
    has_darkmode: bool = False
    """Whether the user has dark mode enabled."""
    has_tokens: bool = False
    """Whether the user has at least 1 token."""
    in_fanclub: bool = False
    """Whether the user is in the fan club."""
    in_private_show: bool = False
    """Whether the user is in the broadcaster's private show."""
    is_broadcasting: bool = False
    """Whether the user is currently broadcasting."""
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
    """User's preferred language.

    Known values: ``"de"`` (German), ``"en"`` (English), ``"es"`` (Spanish),
    ``"fr"`` (French), ``"it"`` (Italian), ``"ja"`` (Japanese),
    ``"ko"`` (Korean), ``"pl"`` (Polish), ``"pt"`` (Portuguese),
    ``"ru"`` (Russian), ``"zh"`` (Chinese).
    """
    recent_tips: str | None = None
    """Recent tipping activity bucket.

    Possible values: "none", "few", "some", "lots", "tons".

    Note:
        The string value "none" is truthy. Compare explicitly with
        recent_tips is None versus recent_tips == "none".
    """
    subgender: str | None = None
    """Subgender code when gender is "t".

    Possible values: "tf", "tm", "tn". None when not provided.
    """

    @field_validator("subgender", mode="before")
    @classmethod
    def _empty_subgender_to_none(cls, v: object) -> object:
        """Convert an empty subgender string to None.

        Returns:
            None for an empty string, otherwise the input value unchanged.
        """
        if isinstance(v, str) and not v:
            return None
        return v


class Message(BaseEventModel):
    """Payload for chatMessage and privateMessage events."""

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
    """Payload for tip events."""

    tokens: int
    """Number of tokens tipped."""
    is_anon: bool = False
    """Whether the tip is anonymous."""
    message: str | None = None
    """Optional message attached to the tip."""


class Media(BaseEventModel):
    """Payload for mediaPurchase events."""

    id: str
    """Identifier of the purchased media."""
    name: str
    """Name of the purchased media."""
    type: str
    """Type of the purchased media.

    Possible values: "photos", "video".
    """
    tokens: int
    """Number of tokens spent on the media purchase."""


class RoomSubject(BaseEventModel):
    """Payload for roomSubjectChange events."""

    subject: str
    """The room subject or title."""


_MAX_EVENT_DATA_DEPTH = 1000
_MappingValue = TypeVar("_MappingValue")


class _ImmutableMapping(Mapping[str, _MappingValue], Generic[_MappingValue]):
    """Read-only mapping with copy and pickle support.

    Nested mappings and sequences are recursively frozen: mappings become
    immutable mappings and sequences become tuples. Cycles and nesting beyond
    1000 levels are rejected, and thawing recreates ordinary JSON-compatible
    containers for serialization.
    """

    __slots__: tuple[str, ...] = ("_data",)

    _data: Mapping[str, _MappingValue]

    def __init__(self, values: Mapping[str, _MappingValue] | None = None) -> None:
        self._data = MappingProxyType(dict(values or {}))

    @override
    def __getitem__(self, key: str) -> _MappingValue:
        return self._data[key]

    @override
    def __iter__(self) -> Iterator[str]:
        return iter(self._data)

    @override
    def __len__(self) -> int:
        return len(self._data)

    @override
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Mapping):
            return NotImplemented
        return self._data == other

    @override
    def __hash__(self) -> int:
        """Reject hashing because mapping contents may themselves be unhashable."""
        msg = "unhashable type: '_ImmutableMapping'"
        raise TypeError(msg)

    def __deepcopy__(self, memo: dict[int, object]) -> _ImmutableMapping[_MappingValue]:
        return _ImmutableMapping({key: deepcopy(value, memo) for key, value in self.items()})

    def __copy__(self) -> _ImmutableMapping[_MappingValue]:
        return _ImmutableMapping(self)

    @override
    def __reduce__(
        self,
    ) -> tuple[type[_ImmutableMapping[_MappingValue]], tuple[dict[str, _MappingValue]]]:
        return (self.__class__, (dict(self),))


_AssignValue = Callable[[object], None]


def _assign_mapping(target: dict[str, object], key: str, value: object) -> None:
    """Assign one transformed value into a temporary mapping."""
    target[key] = value


def _assign_sequence(target: list[object], key: int, value: object) -> None:
    """Assign one transformed value into a temporary sequence."""
    target[key] = value


def _freeze_event_data(value: object) -> object:
    """Return a depth-bounded immutable copy of event data."""
    root: list[object] = []
    active_containers: set[int] = set()
    stack: list[tuple[str, object, _AssignValue, int, int | None]] = [
        ("visit", value, root.append, 0, None)
    ]

    while stack:
        operation, current, assign, depth, container_id = stack.pop()
        if operation == "finish_map":
            if container_id is not None:
                active_containers.discard(container_id)
            assign(_ImmutableMapping(cast("dict[str, object]", current)))
            continue
        if operation == "finish_sequence":
            if container_id is not None:
                active_containers.discard(container_id)
            assign(tuple(cast("list[object]", current)))
            continue
        if depth >= _MAX_EVENT_DATA_DEPTH:
            msg = f"Event payload nesting exceeds {_MAX_EVENT_DATA_DEPTH}."
            raise ValueError(msg)
        if isinstance(current, Mapping):
            mapping = cast("Mapping[str, object]", current)
            container_id = id(mapping)
            if container_id in active_containers:
                msg = "Event payload contains a reference cycle."
                raise ValueError(msg)
            active_containers.add(container_id)
            frozen: dict[str, object] = {}
            stack.append(("finish_map", frozen, assign, depth, container_id))
            stack.extend(
                (
                    "visit",
                    item,
                    partial(_assign_mapping, frozen, key),
                    depth + 1,
                    None,
                )
                for key, item in reversed(tuple(mapping.items()))
            )
            continue
        if isinstance(current, (list, tuple)):
            sequence = cast("list[object] | tuple[object, ...]", current)
            container_id = id(sequence)
            if container_id in active_containers:
                msg = "Event payload contains a reference cycle."
                raise ValueError(msg)
            active_containers.add(container_id)
            frozen_items: list[object] = [None] * len(sequence)
            stack.append(("finish_sequence", frozen_items, assign, depth, container_id))
            stack.extend(
                (
                    "visit",
                    item,
                    partial(_assign_sequence, frozen_items, index),
                    depth + 1,
                    None,
                )
                for index, item in reversed(tuple(enumerate(sequence)))
            )
            continue
        assign(current)

    return root[0]


def _thaw_event_data(value: object) -> object:
    """Return mutable JSON-compatible containers for serialization."""
    # Recursive traversal would exhaust Python's recursion limit near the
    # accepted payload-depth boundary, so thawing uses an explicit work stack.
    root: list[object] = []
    stack: list[tuple[str, object, _AssignValue]] = [("visit", value, root.append)]

    while stack:
        operation, current, assign = stack.pop()
        if operation == "finish_map":
            assign(cast("dict[str, object]", current))
            continue
        if operation == "finish_sequence":
            assign(cast("list[object]", current))
            continue
        if isinstance(current, Mapping):
            mapping = cast("Mapping[str, object]", current)
            thawed: dict[str, object] = {}
            stack.append(("finish_map", thawed, assign))
            stack.extend(
                (
                    "visit",
                    item,
                    partial(_assign_mapping, thawed, key),
                )
                for key, item in reversed(tuple(mapping.items()))
            )
            continue
        if isinstance(current, (list, tuple)):
            sequence = cast("list[object] | tuple[object, ...]", current)
            thawed_items: list[object] = [None] * len(sequence)
            stack.append(("finish_sequence", thawed_items, assign))
            stack.extend(
                (
                    "visit",
                    item,
                    partial(_assign_sequence, thawed_items, index),
                )
                for index, item in reversed(tuple(enumerate(sequence)))
            )
            continue
        assign(current)

    return root[0]


@dataclass(frozen=True)
class _PayloadSpec:
    """One nested event payload accessor and its validation rule."""

    private_name: str
    key: str
    loader: Callable[[object], object]
    allowed_types: tuple[EventType, ...] | None = None


class Event(BaseEventModel):
    """Top-level event container.

    Typed convenience accessors cache validated nested payload fields when
    the event is created and return None for missing or invalid values.

    Warning:
        String fields in payload data are untrusted user input.
    """

    type: EventType = Field(alias="method")
    """Type of the event."""
    raw_method: str | None = None
    """Original API method name when it is not recognized by this client."""
    id: str
    """Unique identifier for the event."""
    data: Mapping[str, object] = Field(default_factory=dict, alias="object")
    """Immutable event data payload."""

    # Private attributes hold the results of one-time sub-model parsing.
    _user: User | None = PrivateAttr(default=None)
    _message: Message | None = PrivateAttr(default=None)
    _broadcaster: str | None = PrivateAttr(default=None)
    _tip: Tip | None = PrivateAttr(default=None)
    _media: Media | None = PrivateAttr(default=None)
    _room_subject: RoomSubject | None = PrivateAttr(default=None)

    @field_validator("data", mode="after")
    @classmethod
    def _freeze_data(cls, value: Mapping[str, object]) -> Mapping[str, object]:
        """Freeze mappings and convert payload arrays to tuples."""
        frozen = _freeze_event_data(value)
        if not isinstance(frozen, _ImmutableMapping):
            msg = "Event payload must be a mapping."
            raise TypeError(msg)
        return cast("_ImmutableMapping[object]", frozen)

    @field_validator("type", mode="before")
    @classmethod
    def _coerce_unknown_type(cls, value: object) -> object:
        """Map unrecognized method strings to EventType.UNKNOWN."""
        if isinstance(value, str):
            try:
                return EventType(value)
            except ValueError:
                return EventType.UNKNOWN
        return value

    @model_validator(mode="before")
    @classmethod
    def _preserve_unknown_method(cls, value: object) -> object:
        """Retain the original name of an unrecognized upstream method."""
        if not isinstance(value, Mapping):
            return value

        mapping = cast("Mapping[str, object]", value)
        raw_method = mapping.get("method", mapping.get("type"))
        if not isinstance(raw_method, str):
            return mapping
        try:
            _ = EventType(raw_method)
        except ValueError:
            preserved = dict(mapping)
            if "raw_method" not in preserved and "rawMethod" not in preserved:
                preserved["raw_method"] = raw_method
            return preserved
        return mapping

    @field_serializer("data")
    @classmethod
    def _serialize_data(
        cls,
        value: Mapping[str, object],
    ) -> dict[str, object]:
        """Serialize the immutable payload as ordinary JSON containers."""
        del cls
        return cast("dict[str, object]", _thaw_event_data(value))

    @override
    def model_post_init(self, context: object, /) -> None:
        """Cache the validated sub-models using one payload registry."""
        strict_context = (
            cast("Mapping[str, object]", context) if isinstance(context, Mapping) else None
        )
        strict = strict_context is not None and strict_context.get("strict_validation") is True
        for spec in _PAYLOAD_SPECS:
            result = self._extract(
                spec.key,
                spec.loader,
                allowed_types=spec.allowed_types,
                strict=strict,
            )
            setattr(self, spec.private_name, result)

    @property
    def user(self) -> User | None:
        """User data if present and valid."""
        return self._user

    @property
    def message(self) -> Message | None:
        """Message data if present and valid."""
        return self._message

    @property
    def broadcaster(self) -> str | None:
        """Broadcaster username, or ``None`` if missing or invalid."""
        return self._broadcaster

    @property
    def tip(self) -> Tip | None:
        """Tip data if present and valid (TIP events only)."""
        return self._tip

    @property
    def media(self) -> Media | None:
        """Media purchase data if present and valid (MEDIA_PURCHASE only)."""
        return self._media

    @property
    def room_subject(self) -> RoomSubject | None:
        """Room subject if present and valid (ROOM_SUBJECT_CHANGE only)."""
        return self._room_subject

    def _extract(
        self,
        key: str,
        loader: Callable[[object], _T],
        *,
        allowed_types: tuple[EventType, ...] | None = None,
        strict: bool = False,
    ) -> _T | None:
        """Extract and validate nested model from event data.

        Args:
            key: Key within data to look up.
            loader: Callable that validates/constructs the nested model.
            allowed_types: Event types eligible for extraction.
            strict: Whether validation errors should propagate.

        Returns:
            Validated model instance or None if unavailable or invalid.

        Raises:
            ValidationError: If strict validation is enabled and loading fails.
        """
        if allowed_types is not None and self.type not in allowed_types:
            return None

        if key not in self.data:
            return None
        payload = self.data[key]
        if payload is None and not strict:
            return None

        try:
            result = loader(payload)
        except ValidationError as exc:
            if strict:
                raise
            fields: set[str] = {
                ".".join(str(p) for p in e.get("loc", ())) or key for e in exc.errors()
            }
            _logger.warning(
                "Invalid %s in event %s (invalid fields: %s)",
                key,
                self.id,
                ", ".join(sorted(fields)),
            )
            return None

        return result


def _load_room_subject(value: object) -> RoomSubject:
    """Load the scalar room subject into its nested model."""
    return RoomSubject.model_validate({"subject": value})


def _load_non_empty_string(value: object) -> str | None:
    """Return a non-empty string payload value, else None."""
    if isinstance(value, str) and value:
        return value
    return None


_PAYLOAD_SPECS = (
    _PayloadSpec("_user", "user", User.model_validate),
    _PayloadSpec(
        "_message",
        "message",
        Message.model_validate,
        (EventType.CHAT_MESSAGE, EventType.PRIVATE_MESSAGE),
    ),
    _PayloadSpec("_tip", "tip", Tip.model_validate, (EventType.TIP,)),
    _PayloadSpec("_media", "media", Media.model_validate, (EventType.MEDIA_PURCHASE,)),
    _PayloadSpec(
        "_room_subject",
        "subject",
        _load_room_subject,
        (EventType.ROOM_SUBJECT_CHANGE,),
    ),
    _PayloadSpec("_broadcaster", "broadcaster", _load_non_empty_string),
)
