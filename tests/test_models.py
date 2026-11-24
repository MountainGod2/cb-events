"""Model validation tests for :mod:`cb_events.models`."""

import json
import logging
import pickle
from collections import UserDict
from collections.abc import Mapping
from copy import copy, deepcopy
from typing import Any, cast

import pytest
from pydantic import ValidationError

from cb_events import Event, EventType, Message, RoomSubject, Tip, User
from cb_events._models import _ImmutableMapping


@pytest.mark.parametrize("event_type", EventType)
def test_event_type_mapping(event_type: EventType) -> None:
    """Every EventType value should round-trip through model validation."""
    event = Event.model_validate({
        "method": event_type.value,
        "id": "test_id",
        "object": {},
    })

    assert event.type == event_type


def test_event_properties_parsed() -> None:
    """Events should provide easy access to nested data."""
    event_data = {
        "method": "tip",
        "id": "event_123",
        "object": {
            "tip": {"tokens": 100},
            "user": {"username": "tipper"},
        },
    }

    event = Event.model_validate(event_data)

    assert event.id == "event_123"
    assert event.type == EventType.TIP
    assert event.tip is not None
    assert event.tip.tokens == 100
    assert event.user is not None
    assert event.user.username == "tipper"


def test_models_accept_python_field_names_and_api_aliases() -> None:
    """Models should accept both documented snake_case names and API camelCase aliases."""
    event = Event(type=EventType.TIP, id="event_python", data={"tip": {"tokens": 25}})
    user = User.model_validate({
        "username": "tipper",
        "fc_auto_renew": True,
        "isFollower": True,
    })
    tip = Tip.model_validate({"tokens": 25, "is_anon": True})
    message = Message.model_validate({"message": "hello", "from_user": "sender"})

    assert event.type is EventType.TIP
    assert event.data["tip"] is not None
    assert user.fc_auto_renew is True
    assert user.is_follower is True
    assert tip.is_anon is True
    assert message.from_user == "sender"


def test_unknown_event_type_maps_to_unknown() -> None:
    """Unrecognized event methods should map to EventType.UNKNOWN."""
    event = Event.model_validate({
        "method": "futureEventTypeFromApi",
        "id": "event_unknown",
        "object": {},
    })

    assert event.type is EventType.UNKNOWN


def test_event_data_is_json_serializable_and_deep_copy_safe() -> None:
    """Event payloads should remain JSON-compatible and copy-safe."""
    event = Event.model_validate({
        "method": "tip",
        "id": "event_456",
        "object": {
            "tip": {"tokens": 100},
            "nested": {"items": [1, 2, {"flag": True}]},
        },
    })

    assert isinstance(event.data, Mapping)
    assert event.model_dump(mode="json")["data"] == {
        "tip": {"tokens": 100},
        "nested": {"items": [1, 2, {"flag": True}]},
    }
    copied = event.model_copy(deep=True)
    assert copied.data == {
        "tip": {"tokens": 100},
        "nested": {"items": (1, 2, {"flag": True})},
    }
    with pytest.raises(TypeError):
        cast(dict[str, object], copied.data)["tip"] = {"tokens": 999}


def test_event_data_rejects_excessive_nesting() -> None:
    """Excessively deep payloads should fail validation without RecursionError."""
    nested: object = {"value": 1}
    for _ in range(5000):
        nested = {"value": nested}

    with pytest.raises(ValidationError, match="nesting exceeds"):
        Event.model_validate({
            "method": "chatMessage",
            "id": "event_deep",
            "object": {"message": {"message": "hello", "extra": nested}},
        })


def test_event_data_accepts_depth_below_guard_limit() -> None:
    """The iterative freezer should not fail at Python's recursion limit."""
    nested: object = {"value": 1}
    for _ in range(600):
        nested = {"value": nested}

    event = Event.model_validate({
        "method": "chatMessage",
        "id": "event_deep_valid",
        "object": {"nested": nested},
    })

    assert event.data["nested"] is not None
    serialized = event.model_dump(mode="python")
    assert serialized["data"]["nested"] is not None
    assert json.dumps(serialized["data"])


def test_event_data_freezes_user_dict_payloads() -> None:
    """Non-dict mappings should be frozen recursively like plain dicts."""
    payload = UserDict({"nested": UserDict({"items": [1, 2, 3]})})
    event = Event.model_validate({
        "method": "chatMessage",
        "id": "event_user_dict",
        "object": payload,
    })

    nested = cast(Mapping[str, object], event.data["nested"])
    assert isinstance(event.data, Mapping)
    assert isinstance(nested, Mapping)
    assert nested["items"] == (1, 2, 3)
    with pytest.raises(TypeError):
        cast(dict[str, object], nested)["items"] = []


def test_event_data_rejects_reference_cycles() -> None:
    """Programmatically supplied cyclic payloads should fail clearly."""
    cyclic: dict[str, object] = {}
    cyclic["self"] = cyclic

    with pytest.raises(ValidationError, match="reference cycle"):
        Event.model_validate({
            "method": "chatMessage",
            "id": "event_cycle",
            "object": cyclic,
        })


def test_event_data_rejects_sequence_reference_cycles() -> None:
    """Cyclic list payloads should fail clearly."""
    cyclic_list: list[object] = []
    cyclic_list.append(cyclic_list)

    with pytest.raises(ValidationError, match="reference cycle"):
        Event.model_validate({
            "method": "chatMessage",
            "id": "event_list_cycle",
            "object": {"nested": cyclic_list},
        })


def test_event_data_validator_rejects_non_mapping_root() -> None:
    """Validator should reject non-mapping roots when called directly."""
    with pytest.raises(TypeError, match="must be a mapping"):
        Event._freeze_data([])  # pyright: ignore[reportArgumentType]


def test_event_is_pickle_round_trippable() -> None:
    """Event objects should survive pickle round-trips for multiprocessing and caches."""
    event = Event.model_validate({
        "method": "tip",
        "id": "event_pickle",
        "object": {"tip": {"tokens": 42}, "user": {"username": "alice"}},
    })

    restored = pickle.loads(pickle.dumps(event))

    assert restored == event
    assert restored.data == event.data


def test_event_mapping_has_no_mutator_api() -> None:
    """Immutable payloads expose only the read-only Mapping API."""
    event = Event.model_validate({
        "method": "tip",
        "id": "evt-mapping",
        "object": {"nested": {"items": [1]}},
    })

    assert not hasattr(event.data, "update")
    assert not hasattr(event.data, "__setitem__")
    assert isinstance(event.data["nested"], Mapping)
    assert isinstance(cast(Mapping[str, object], event.data["nested"])["items"], tuple)


def test_immutable_mapping_copy_and_equality_behaviors() -> None:
    """_ImmutableMapping should support value-based equality and copy operations."""
    mapping = _ImmutableMapping({"nested": {"count": 1}})

    assert mapping == {"nested": {"count": 1}}
    assert mapping != {"nested": {"count": 2}}

    mapping_copy = copy(mapping)
    assert isinstance(mapping_copy, _ImmutableMapping)
    assert mapping_copy == mapping
    assert mapping_copy is not mapping

    mapping_deepcopy = deepcopy(mapping)
    assert isinstance(mapping_deepcopy, _ImmutableMapping)
    assert mapping_deepcopy == mapping
    assert mapping_deepcopy is not mapping


def test_immutable_mapping_is_unhashable() -> None:
    """_ImmutableMapping hash should raise TypeError."""
    mapping = _ImmutableMapping({"a": 1})
    with pytest.raises(TypeError, match="unhashable"):
        hash(mapping)


@pytest.mark.parametrize(
    ("raw_subgender", "expected"),
    [
        ("", None),  # empty string → None
        ("tf", "tf"),  # valid value passes through
        ("tm", "tm"),
        ("tn", "tn"),
        (None, None),  # None passes through unchanged
    ],
)
def test_user_subgender_validator(raw_subgender: str | None, expected: str | None) -> None:
    """Empty subgender should coerce to None while valid values pass through."""
    user = User.model_validate({"username": "u", "subgender": raw_subgender})
    assert user.subgender == expected


def test_user_field_mapping() -> None:
    """The User model should map camelCase fields to snake_case attributes."""
    user_data = {
        "username": "testuser",
        "colorGroup": "p",
        "gender": "f",
        "inFanclub": True,
        "isMod": True,
        "isFollower": True,
    }

    user = User.model_validate(user_data)

    assert user.username == "testuser"
    assert user.color_group == "p"
    assert user.gender == "f"
    assert user.in_fanclub is True
    assert user.is_mod is True
    assert user.is_follower is True


@pytest.mark.parametrize(
    ("field_name", "attr_name", "value"),
    [
        ("colorGroup", "color_group", "p"),
        ("colorGroup", "color_group", "owner"),  # not a documented value
        ("gender", "gender", "f"),
        ("gender", "gender", "x"),  # not a documented value
        ("language", "language", "en"),
        ("language", "language", "sv"),  # not a documented value
        ("recentTips", "recent_tips", "some"),
        ("recentTips", "recent_tips", "many"),  # not a documented value
        ("subgender", "subgender", "tf"),
        ("subgender", "subgender", "xx"),  # not a documented value
    ],
)
def test_user_open_string_fields_accept_arbitrary_values(
    field_name: str,
    attr_name: str,
    value: str,
) -> None:
    """User fields documented with "known values" are plain strings.

    The API should be able to send new values without breaking parsing.
    """
    user = User.model_validate({"username": "u", field_name: value})
    assert getattr(user, attr_name) == value


@pytest.mark.parametrize(
    ("message_data", "expected_is_private", "expected_from", "expected_to"),
    [
        ({"message": "Hello everyone!"}, False, None, None),
        (
            {
                "message": "Private hello",
                "fromUser": "sender",
                "toUser": "receiver",
            },
            True,
            "sender",
            "receiver",
        ),
    ],
)
def test_message_privacy(
    message_data: dict[str, str],
    expected_is_private: bool,
    expected_from: str | None,
    expected_to: str | None,
) -> None:
    """Message privacy depends on sender and recipient fields."""
    message = Message.model_validate(message_data)

    assert message.message == message_data["message"]
    assert message.is_private is expected_is_private
    assert message.from_user == expected_from
    assert message.to_user == expected_to


def test_tip_fields() -> None:
    """Tip model should expose its attributes cleanly."""
    tip_data = {"tokens": 100, "isAnon": False, "message": "Great show!"}

    tip = Tip.model_validate(tip_data)

    assert tip.tokens == 100
    assert tip.is_anon is False
    assert tip.message == "Great show!"


def test_room_subject_field() -> None:
    """RoomSubject should parse the ``subject`` field."""
    subject_data = {"subject": "Welcome to my room!"}

    room_subject = RoomSubject.model_validate(subject_data)

    assert room_subject.subject == "Welcome to my room!"


def test_media_parsed() -> None:
    """MEDIA_PURCHASE events should validate and return a Media model."""
    event_data = {
        "method": "mediaPurchase",
        "id": "evt-media",
        "object": {
            "media": {
                "id": "m1",
                "name": "clip",
                "type": "video",
                "tokens": 50,
            }
        },
    }

    event = Event.model_validate(event_data)
    assert event.media is not None
    assert event.media.id == "m1"
    assert event.media.name == "clip"
    assert event.media.type == "video"
    assert event.media.tokens == 50


def test_media_missing_payload_returns_none() -> None:
    """Missing media key should return None for MEDIA_PURCHASE events."""
    event = Event.model_validate(
        {"method": "mediaPurchase", "id": "evt-media-2", "object": {}},
    )
    assert event.media is None


@pytest.mark.parametrize(
    ("method", "key"),
    [
        ("tip", "tip"),
        ("mediaPurchase", "media"),
    ],
)
def test_present_null_payload_is_lenient(method: str, key: str) -> None:
    """A present null payload should remain optional in lenient mode."""
    event = Event.model_validate({
        "method": method,
        "id": "evt-null",
        "object": {key: None},
    })

    assert getattr(event, "tip" if key == "tip" else "media") is None


@pytest.mark.parametrize(
    ("method", "key"),
    [
        ("tip", "tip"),
        ("mediaPurchase", "media"),
    ],
)
def test_present_null_payload_is_strict_error(method: str, key: str) -> None:
    """A present null payload should reach the registered loader in strict mode."""
    with pytest.raises(ValidationError):
        Event.model_validate(
            {
                "method": method,
                "id": "evt-null-strict",
                "object": {key: None},
            },
            context={"strict_validation": True},
        )


@pytest.mark.parametrize(
    ("method", "event_id", "invalid_object", "attr_name", "log_msg"),
    [
        (
            "tip",
            "evt-user",
            {"user": {"username": None}},
            "user",
            "Invalid user",
        ),
        (
            "tip",
            "evt-tip",
            {"tip": {"message": "missing tokens"}},
            "tip",
            "Invalid tip",
        ),
        (
            "chatMessage",
            "evt-msg",
            {"message": {}},
            "message",
            "Invalid message",
        ),
        (
            "roomSubjectChange",
            "evt-subject",
            {"subject": 123},
            "room_subject",
            "Invalid subject",
        ),
        (
            "mediaPurchase",
            "evt-media-3",
            {
                "media": {
                    "id": "m1",
                    "name": "clip",
                    "type": "video",
                    "tokens": "abc",
                }
            },
            "media",
            "Invalid media",
        ),
    ],
)
def test_event_property_validation_errors_logged(
    caplog: pytest.LogCaptureFixture,
    method: str,
    event_id: str,
    invalid_object: dict[str, Any],
    attr_name: str,
    log_msg: str,
) -> None:
    """When event properties fail validation, they should return None."""
    caplog.set_level(logging.WARNING, logger="cb_events._models")
    event = Event.model_validate({
        "method": method,
        "id": event_id,
        "object": invalid_object,
    })

    assert getattr(event, attr_name) is None
    # Access again. Only one error should be logged.
    assert getattr(event, attr_name) is None
    warning_records = [
        r
        for r in caplog.records
        if r.levelname == "WARNING" and f"{log_msg} in event {event_id}" in r.getMessage()
    ]
    assert len(warning_records) == 1


def test_event_broadcaster_property() -> None:
    """Broadcaster property should return the configured username."""
    event = Event.model_validate({
        "method": "broadcastStart",
        "id": "evt-bcaster",
        "object": {"broadcaster": "streamer"},
    })

    assert event.broadcaster == "streamer"


def test_event_broadcaster_missing_returns_none() -> None:
    """Missing broadcaster should return None."""
    event = Event.model_validate({
        "method": "broadcastStart",
        "id": "evt-bcaster-missing",
        "object": {},
    })

    assert event.broadcaster is None


def test_event_data_is_immutable() -> None:
    """Mutating the raw payload should not silently corrupt the parsed model."""
    event = Event.model_validate({
        "method": "tip",
        "id": "evt-immutable",
        "object": {"tip": {"tokens": 5}},
    })

    assert event.tip is not None
    assert event.tip.tokens == 5

    mutable_tip = cast(dict[str, object], event.data["tip"])
    with pytest.raises(TypeError):
        mutable_tip["tokens"] = 100

    assert event.tip.tokens == 5


def test_message_not_parsed_on_tip_event() -> None:
    """Message objects should not be parsed for TIP events."""
    event = Event.model_validate({
        "method": "tip",
        "id": "evt-mismatch",
        "object": {"message": {"message": "hi"}},
    })

    assert event.message is None


def test_room_subject_string_parsed() -> None:
    """Room subject may be provided as a string and should parse correctly."""
    event = Event.model_validate({
        "method": "roomSubjectChange",
        "id": "evt-room-sub",
        "object": {"subject": "New title"},
    })

    assert event.room_subject is not None
    assert event.room_subject.subject == "New title"


def test_room_subject_not_parsed_when_other_event_type() -> None:
    """Subject present on unrelated event types should be ignored."""
    event = Event.model_validate({
        "method": "tip",
        "id": "evt-room-sub-tipping",
        "object": {"subject": "something"},
    })

    assert event.room_subject is None
