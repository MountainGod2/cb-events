"""Tests for Event, User, Message, Tip models."""

from typing import Any

import pytest

from chaturbate_events import Event, EventType
from chaturbate_events.models import Message, Tip, User


@pytest.mark.parametrize(
    ("event_data", "expected_type"),
    [
        ({"method": "tip", "id": "1", "object": {}}, EventType.TIP),
        ({"method": "chatMessage", "id": "2", "object": {}}, EventType.CHAT_MESSAGE),
    ],
)
def test_event_model_validation(
    event_data: dict[str, Any], expected_type: EventType
) -> None:
    """Test Event model validation and type mapping functionality."""
    event = Event.model_validate(event_data)
    assert event.type == expected_type
    assert event.id == event_data["id"]
    assert isinstance(event.data, dict)


def test_event_validation_with_invalid_data() -> None:
    """Test Event model validation with invalid input data."""
    with pytest.raises(ValueError, match="Input should be"):
        Event.model_validate({"method": "invalid", "id": "x"})


@pytest.mark.parametrize(
    ("model_class", "test_data", "expected_assertions"),
    [
        (
            User,
            {
                "username": "testuser",
                "colorGroup": "purple",
                "fcAutoRenew": True,
                "gender": "f",
                "hasDarkmode": True,
                "hasTokens": True,
                "inFanclub": True,
                "inPrivateShow": False,
                "isBroadcasting": False,
                "isFollower": True,
                "isMod": True,
                "isOwner": False,
                "isSilenced": False,
                "isSpying": True,
                "language": "es",
                "recentTips": "recent tip data",
                "subgender": "trans",
            },
            [
                ("username", "testuser"),
                ("color_group", "purple"),
                ("fc_auto_renew", True),
                ("has_darkmode", True),
                ("in_fanclub", True),
                ("is_mod", True),
                ("is_spying", True),
            ],
        ),
        (
            Message,
            {
                "message": "Hello everyone!",
                "bgColor": "#FF0000",
                "color": "#FFFFFF",
                "font": "arial",
            },
            [
                ("message", "Hello everyone!"),
                ("bg_color", "#FF0000"),
                ("from_user", None),
                ("to_user", None),
            ],
        ),
        (
            Message,
            {
                "message": "Private hello",
                "fromUser": "sender",
                "toUser": "receiver",
                "orig": "original text",
            },
            [
                ("message", "Private hello"),
                ("from_user", "sender"),
                ("to_user", "receiver"),
                ("orig", "original text"),
            ],
        ),
        (
            Tip,
            {"tokens": 100, "isAnon": True, "message": "Anonymous tip message"},
            [("tokens", 100), ("is_anon", True), ("message", "Anonymous tip message")],
        ),
        (Tip, {"tokens": 50, "isAnon": False}, [("tokens", 50), ("is_anon", False)]),
    ],
)
def test_model_validation_comprehensive(
    model_class: Any,
    test_data: dict[str, Any],
    expected_assertions: list[tuple[str, Any]],
) -> None:
    """Test comprehensive model validation for User, Message, and Tip models."""
    model_instance = model_class.model_validate(test_data)
    for attr_name, expected_value in expected_assertions:
        actual_value = getattr(model_instance, attr_name)
        assert actual_value == expected_value


def test_model_validation_errors() -> None:
    """Test model validation with malformed data."""
    with pytest.raises(ValueError, match="Field required"):
        Event.model_validate({"method": "tip"})

    with pytest.raises(ValueError, match="Input should be"):
        Event.model_validate({"method": "invalidMethod", "id": "test"})

    with pytest.raises(ValueError, match="Input should be a valid string"):
        User.model_validate({"username": 123})


def test_event_properties_edge_cases() -> None:
    """Test Event model properties with missing or incorrect data."""
    event_no_user = Event.model_validate({
        "method": EventType.TIP.value,
        "id": "test",
        "object": {"tip": {"tokens": 50}},
    })
    assert event_no_user.user is None
    assert event_no_user.tip is not None
    assert event_no_user.message is None

    chat_event = Event.model_validate({
        "method": EventType.CHAT_MESSAGE.value,
        "id": "test",
        "object": {"message": {"message": "hello"}},
    })
    assert chat_event.tip is None
    assert chat_event.message is not None

    broadcast_event = Event.model_validate({
        "method": EventType.BROADCAST_START.value,
        "id": "test",
        "object": {"broadcaster": "streamer123"},
    })
    assert broadcast_event.broadcaster == "streamer123"

    event_with_user = Event.model_validate({
        "method": EventType.TIP.value,
        "id": "test",
        "object": {
            "tip": {"tokens": 100},
            "user": {
                "username": "tipper123",
                "colorGroup": "purple",
                "hasTokens": True,
                "inFanclub": False,
            },
        },
    })

    user = event_with_user.user
    assert user is not None
    assert user.username == "tipper123"
    assert user.color_group == "purple"
    assert user.has_tokens is True
    assert user.in_fanclub is False

    room_subject_event = Event.model_validate({
        "method": "roomSubjectChange",
        "id": "s",
        "object": {"broadcaster": "u", "subject": "topic"},
    })
    assert room_subject_event.room_subject is not None
    assert room_subject_event.room_subject.subject == "topic"
    assert room_subject_event.broadcaster == "u"
