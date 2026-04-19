"""Model validation tests for :mod:`cb_events.models`."""

import logging
from typing import Any

import pytest

from cb_events import Event, EventType
from cb_events.models import Message, RoomSubject, Tip, User


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
    caplog.set_level(logging.WARNING, logger="cb_events.models")
    event = Event.model_validate({
        "method": method,
        "id": event_id,
        "object": invalid_object,
    })

    assert getattr(event, attr_name) is None
    # Access again — result is cached, so no additional warning is expected
    assert getattr(event, attr_name) is None
    warning_records = [
        r
        for r in caplog.records
        if r.levelname == "WARNING"
        and f"{log_msg} in event {event_id}" in r.getMessage()
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


def test_event_broadcaster_property_cached() -> None:
    """Broadcaster property should return the same value on repeated access (cache hit path)."""
    event = Event.model_validate({
        "method": "broadcastStart",
        "id": "evt-bcaster-cache",
        "object": {"broadcaster": "streamer"},
    })

    first = event.broadcaster
    second = event.broadcaster
    assert first == second == "streamer"


def test_event_broadcaster_missing_returns_none(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Missing broadcaster should return None and emit a warning."""
    caplog.set_level(logging.WARNING, logger="cb_events.models")
    event = Event.model_validate({
        "method": "broadcastStart",
        "id": "evt-bcaster-missing",
        "object": {},
    })

    assert event.broadcaster is None
    assert any(
        "Missing or invalid broadcaster in event evt-bcaster-missing"
        in r.getMessage()
        for r in caplog.records
        if r.levelname == "WARNING"
    )


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
