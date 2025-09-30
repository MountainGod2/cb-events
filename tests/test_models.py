"""Tests for Event, User, Message, Tip, and related models."""

import pytest
from pydantic import ValidationError

from cb_events import Event, EventType
from cb_events.models import Message, RoomSubject, Tip, User


class TestEvent:
    @pytest.mark.parametrize(
        ("method", "expected_type"),
        [
            ("tip", EventType.TIP),
            ("chatMessage", EventType.CHAT_MESSAGE),
            ("broadcastStart", EventType.BROADCAST_START),
            ("broadcastStop", EventType.BROADCAST_STOP),
            ("userEnter", EventType.USER_ENTER),
            ("userLeave", EventType.USER_LEAVE),
            ("follow", EventType.FOLLOW),
            ("unfollow", EventType.UNFOLLOW),
            ("roomSubjectChange", EventType.ROOM_SUBJECT_CHANGE),
            ("privateMessage", EventType.PRIVATE_MESSAGE),
            ("fanclubJoin", EventType.FANCLUB_JOIN),
            ("mediaPurchase", EventType.MEDIA_PURCHASE),
        ],
    )
    def test_event_type_mapping(self, method, expected_type):
        event_data = {"method": method, "id": "test_id", "object": {}}
        event = Event.model_validate(event_data)
        assert event.type == expected_type

    def test_event_properties(self):
        event_data = {
            "method": "tip",
            "id": "event_123",
            "object": {
                "tip": {"tokens": 100},
                "user": {"username": "tipper"},
                "message": {"message": "Great show!", "fromUser": "sender", "toUser": "receiver"},
                "roomSubject": {"subject": "New show topic"},
            },
        }

        event = Event.model_validate(event_data)

        assert event.id == "event_123"
        assert event.type == EventType.TIP
        assert event.tip
        assert event.tip.tokens == 100
        assert event.user
        assert event.user.username == "tipper"
        assert event.message is None
        assert event.room_subject is None

    def test_missing_properties(self):
        event_data = {"method": "tip", "id": "test_id", "object": {}}
        event = Event.model_validate(event_data)

        assert event.tip is None
        assert event.user is None
        assert event.message is None
        assert event.room_subject is None

    def test_invalid_event_data(self):
        with pytest.raises(ValidationError):
            Event.model_validate({"method": "invalid_method"})


class TestUser:
    def test_user_creation(self):
        user_data = {
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
        }

        user = User.model_validate(user_data)

        assert user.username == "testuser"
        assert user.color_group == "purple"
        assert user.fc_auto_renew is True
        assert user.gender == "f"
        assert user.has_darkmode is True
        assert user.has_tokens is True
        assert user.in_fanclub is True
        assert user.is_mod is True
        assert user.language == "es"
        assert user.subgender == "trans"

    def test_user_minimal_data(self):
        user_data = {"username": "simple_user"}
        user = User.model_validate(user_data)
        assert user.username == "simple_user"
        assert not user.color_group
        assert not user.gender


class TestMessage:
    def test_public_message(self):
        message_data = {
            "message": "Hello everyone!",
            "bgColor": "#FF0000",
            "color": "#FFFFFF",
            "font": "arial",
        }

        message = Message.model_validate(message_data)

        assert message.message == "Hello everyone!"
        assert message.bg_color == "#FF0000"
        assert message.color == "#FFFFFF"
        assert message.font == "arial"
        assert message.from_user is None
        assert message.to_user is None
        assert not message.is_private

    def test_private_message(self):
        message_data = {
            "message": "Private hello",
            "fromUser": "sender",
            "toUser": "receiver",
            "orig": "original text",
        }

        message = Message.model_validate(message_data)

        assert message.message == "Private hello"
        assert message.from_user == "sender"
        assert message.to_user == "receiver"
        assert message.orig == "original text"
        assert message.is_private

    def test_message_without_users(self):
        message_data = {"message": "Public message"}
        message = Message.model_validate(message_data)
        assert not message.is_private


class TestTip:
    def test_tip_creation(self):
        tip_data = {
            "tokens": 100,
            "isAnon": False,
            "message": "Great show!",
        }

        tip = Tip.model_validate(tip_data)

        assert tip.tokens == 100
        assert tip.is_anon is False
        assert tip.message == "Great show!"

    def test_anonymous_tip(self):
        tip_data = {"tokens": 50, "isAnon": True}
        tip = Tip.model_validate(tip_data)
        assert tip.is_anon is True


class TestRoomSubject:
    def test_room_subject_creation(self):
        subject_data = {"subject": "Welcome to my room!"}
        room_subject = RoomSubject.model_validate(subject_data)
        assert room_subject.subject == "Welcome to my room!"


class TestModelValidation:
    @pytest.mark.parametrize(
        ("invalid_data", "model_class"),
        [
            ({"tokens": "invalid"}, Tip),
            ({}, Message),
        ],
    )
    def test_validation_errors(self, invalid_data, model_class):
        with pytest.raises(ValidationError):
            model_class.model_validate(invalid_data)

    def test_model_immutability(self):
        user = User.model_validate({"username": "test"})

        # Test that model_copy works correctly for updating fields
        updated_user = user.model_copy(update={"username": "changed"})
        assert updated_user.username == "changed"
        assert user.username == "test"  # Original unchanged

    def test_model_serialization(self):
        user_data = {"username": "test", "colorGroup": "blue"}
        user = User.model_validate(user_data)

        serialized = user.model_dump()
        assert serialized["username"] == "test"
        assert serialized["color_group"] == "blue"

        serialized_alias = user.model_dump(by_alias=True)
        assert serialized_alias["colorGroup"] == "blue"
