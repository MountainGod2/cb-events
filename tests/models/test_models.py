"""Model validation tests for :mod:`cb_events.models`."""

import logging

import pytest

from cb_events import Event, EventType
from cb_events.models import Message, RoomSubject, Tip, User


@pytest.mark.parametrize(
    ("method", "expected_type"),
    [
        ("tip", EventType.TIP),
        ("chatMessage", EventType.CHAT_MESSAGE),
        ("broadcastStart", EventType.BROADCAST_START),
        ("userEnter", EventType.USER_ENTER),
        ("follow", EventType.FOLLOW),
        ("roomSubjectChange", EventType.ROOM_SUBJECT_CHANGE),
        ("privateMessage", EventType.PRIVATE_MESSAGE),
        ("fanclubJoin", EventType.FANCLUB_JOIN),
    ],
)
def test_event_type_mapping(method: str, expected_type: EventType) -> None:
    """Event method strings should map to the correct enum member."""
    event_data = {"method": method, "id": "test_id", "object": {}}
    event = Event.model_validate(event_data)

    assert event.type is expected_type


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
    assert event.type is EventType.TIP
    assert event.tip is not None
    assert event.tip.tokens == 100
    assert event.user is not None
    assert event.user.username == "tipper"


def test_user_field_mapping() -> None:
    """The User model should map camelCase fields to snake_case attributes."""
    user_data = {
        "username": "testuser",
        "colorGroup": "purple",
        "gender": "f",
        "inFanclub": True,
        "isMod": True,
        "isFollower": True,
    }

    user = User.model_validate(user_data)

    assert user.username == "testuser"
    assert user.color_group == "purple"
    assert user.gender == "f"
    assert user.in_fanclub is True
    assert user.is_mod is True
    assert user.is_follower is True


def test_message_public() -> None:
    """Messages without sender/recipient should not be private."""
    message_data = {"message": "Hello everyone!"}

    message = Message.model_validate(message_data)

    assert message.message == "Hello everyone!"
    assert not message.is_private


def test_message_private() -> None:
    """Messages with sender and recipient should read as private."""
    message_data = {
        "message": "Private hello",
        "fromUser": "sender",
        "toUser": "receiver",
    }

    message = Message.model_validate(message_data)

    assert message.message == "Private hello"
    assert message.from_user == "sender"
    assert message.to_user == "receiver"
    assert message.is_private


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


def test_event_user_validation_error(caplog: pytest.LogCaptureFixture) -> None:
    """Invalid user payloads should be skipped with logged details."""
    caplog.set_level(logging.WARNING, logger="cb_events.models")
    event = Event.model_validate({
        "method": "tip",
        "id": "evt-user",
        "object": {"user": {"username": None}},
    })

    assert event.user is None
    assert event.user is None  # cached value should remain None
    assert "Invalid user in event evt-user" in caplog.text


def test_event_tip_validation_error(caplog: pytest.LogCaptureFixture) -> None:
    """Tip events with invalid tip data should log and return None."""
    caplog.set_level(logging.WARNING, logger="cb_events.models")
    event = Event.model_validate({
        "method": "tip",
        "id": "evt-tip",
        "object": {"tip": {"message": "missing tokens"}},
    })

    assert event.tip is None
    assert "Invalid tip in event evt-tip" in caplog.text


def test_event_message_validation_error(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Message events with invalid payloads should be ignored."""
    caplog.set_level(logging.WARNING, logger="cb_events.models")
    event = Event.model_validate({
        "method": "chatMessage",
        "id": "evt-msg",
        "object": {"message": {}},
    })

    assert event.message is None
    assert "Invalid message in event evt-msg" in caplog.text


def test_event_room_subject_validation_error(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Room subject events should handle invalid payloads gracefully."""
    caplog.set_level(logging.WARNING, logger="cb_events.models")
    event = Event.model_validate({
        "method": "roomSubjectChange",
        "id": "evt-subject",
        "object": {"subject": 123},  # Invalid type
    })

    assert event.room_subject is None
    assert "Invalid subject in event evt-subject" in caplog.text


def test_event_broadcaster_property() -> None:
    """Broadcaster property should return the configured username."""
    event = Event.model_validate({
        "method": "broadcastStart",
        "id": "evt-bcaster",
        "object": {"broadcaster": "streamer"},
    })

    assert event.broadcaster == "streamer"


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
