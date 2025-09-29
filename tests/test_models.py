"""Tests for Event, User, Message, Tip models."""

from typing import Any

import pytest

from cb_events import Event, EventType
from cb_events.models import Message, RoomSubject, Tip, User


@pytest.mark.parametrize(
    ("event_data", "expected_type"),
    [
        ({"method": "tip", "id": "1", "object": {}}, EventType.TIP),
        ({"method": "chatMessage", "id": "2", "object": {}}, EventType.CHAT_MESSAGE),
        ({"method": "broadcastStart", "id": "3", "object": {}}, EventType.BROADCAST_START),
        ({"method": "broadcastStop", "id": "4", "object": {}}, EventType.BROADCAST_STOP),
        ({"method": "userEnter", "id": "5", "object": {}}, EventType.USER_ENTER),
        ({"method": "userLeave", "id": "6", "object": {}}, EventType.USER_LEAVE),
        ({"method": "follow", "id": "7", "object": {}}, EventType.FOLLOW),
        ({"method": "unfollow", "id": "8", "object": {}}, EventType.UNFOLLOW),
        ({"method": "roomSubjectChange", "id": "9", "object": {}}, EventType.ROOM_SUBJECT_CHANGE),
    ],
)
def test_event_model_validation(event_data: dict[str, Any], expected_type: EventType) -> None:
    """Test Event model validation and type mapping functionality."""
    event = Event.model_validate(event_data)
    assert event.type == expected_type
    assert event.id == event_data["id"]
    assert isinstance(event.data, dict)


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
                ("language", "es"),
                ("subgender", "trans"),
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
                ("color", "#FFFFFF"),
                ("font", "arial"),
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
        (
            Tip,
            {"tokens": 50, "isAnon": False},
            [("tokens", 50), ("is_anon", False), ("message", "")],
        ),
        (
            RoomSubject,
            {"subject": "New room topic"},
            [("subject", "New room topic")],
        ),
    ],
)
def test_model_validation_comprehensive(
    model_class: Any,
    test_data: dict[str, Any],
    expected_assertions: list[tuple[str, Any]],
) -> None:
    """Test comprehensive model validation for User, Message, Tip, and RoomSubject models."""
    model_instance = model_class.model_validate(test_data)
    for attr_name, expected_value in expected_assertions:
        actual_value = getattr(model_instance, attr_name)
        assert actual_value == expected_value


@pytest.mark.parametrize(
    ("message_data", "expected_is_private"),
    [
        # Public chat message (no from_user/to_user)
        (
            {"message": "Hello everyone!"},
            False,
        ),
        # Public chat message with color
        (
            {"message": "Hello!", "color": "#FF0000", "font": "arial"},
            False,
        ),
        # Private message (has both from_user and to_user)
        (
            {
                "message": "Private hello",
                "fromUser": "sender",
                "toUser": "receiver",
            },
            True,
        ),
        # Incomplete private message (only from_user)
        (
            {
                "message": "Not private",
                "fromUser": "sender",
            },
            False,
        ),
        # Incomplete private message (only to_user)
        (
            {
                "message": "Not private",
                "toUser": "receiver",
            },
            False,
        ),
    ],
)
def test_message_is_private_property(
    message_data: dict[str, Any],
    expected_is_private: bool,
) -> None:
    """Test Message.is_private property correctly identifies private vs public messages."""
    message = Message.model_validate(message_data)
    assert message.is_private == expected_is_private


@pytest.mark.parametrize(
    ("invalid_data", "expected_error_pattern"),
    [
        ({"method": "tip"}, "Field required"),
        ({"method": "invalidMethod", "id": "test"}, "Input should be"),
        ({"username": 123}, "Input should be a valid string"),
        ({}, "Field required"),
        ({"tokens": "not_a_number"}, "Input should be a valid integer"),
        ({"isAnon": "not_boolean"}, "Input should be a valid boolean"),
    ],
)
def test_model_validation_errors(invalid_data: dict[str, Any], expected_error_pattern: str) -> None:
    """Test model validation with malformed data."""
    if "method" in invalid_data:
        with pytest.raises(ValueError, match=expected_error_pattern):
            Event.model_validate(invalid_data)
    elif "username" in invalid_data or not invalid_data:
        with pytest.raises(ValueError, match=expected_error_pattern):
            User.model_validate(invalid_data)
    elif "tokens" in invalid_data or "isAnon" in invalid_data:
        with pytest.raises(ValueError, match=expected_error_pattern):
            Tip.model_validate(invalid_data)


@pytest.mark.parametrize(
    ("event_data", "property_checks"),
    [
        (
            {
                "method": EventType.TIP.value,
                "id": "tip_test",
                "object": {
                    "tip": {"tokens": 100, "isAnon": False},
                    "user": {"username": "tipper123", "hasTokens": True},
                },
            },
            [
                ("tip.tokens", 100),
                ("tip.is_anon", False),
                ("user.username", "tipper123"),
                ("user.has_tokens", True),
                ("message", None),
            ],
        ),
        (
            {
                "method": EventType.CHAT_MESSAGE.value,
                "id": "chat_test",
                "object": {
                    "message": {"message": "Hello chat!", "color": "#FF0000"},
                    "user": {"username": "chatter", "isMod": True},
                },
            },
            [
                ("message.message", "Hello chat!"),
                ("message.color", "#FF0000"),
                ("user.username", "chatter"),
                ("user.is_mod", True),
                ("tip", None),
            ],
        ),
        (
            {
                "method": EventType.ROOM_SUBJECT_CHANGE.value,
                "id": "subject_test",
                "object": {
                    "broadcaster": "streamer123",
                    "subject": "New topic here",
                },
            },
            [
                ("broadcaster", "streamer123"),
                ("room_subject.subject", "New topic here"),
                ("tip", None),
                ("user", None),
            ],
        ),
        (
            {
                "method": EventType.BROADCAST_START.value,
                "id": "broadcast_test",
                "object": {"broadcaster": "streamer456"},
            },
            [
                ("broadcaster", "streamer456"),
                ("user", None),
                ("tip", None),
                ("message", None),
                ("room_subject", None),
            ],
        ),
    ],
)
def test_event_properties_comprehensive(
    event_data: dict[str, Any],
    property_checks: list[tuple[str, Any]],
) -> None:
    """Test Event model properties with various data combinations."""
    event = Event.model_validate(event_data)

    for property_path, expected_value in property_checks:
        obj = event
        for prop in property_path.split("."):
            obj = getattr(obj, prop, None)
            if obj is None:
                break

        assert obj == expected_value, (
            f"Property {property_path} should be {expected_value}, got {obj}"
        )


def test_event_validation_with_invalid_data() -> None:
    """Test Event model validation with completely invalid input data."""
    with pytest.raises(ValueError, match="Input should be"):
        Event.model_validate({"method": "invalid", "id": "x"})
