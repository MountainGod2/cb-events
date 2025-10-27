"""Tests for Event, User, Message, Tip, and related models."""

import pytest

from cb_events import Event, EventType
from cb_events.models import Message, RoomSubject, Tip, User


class TestEvent:
    """Test Event model and type handling."""

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
    def test_event_type_mapping(self, method, expected_type):
        """Event method strings should map to correct EventType enum."""
        event_data = {"method": method, "id": "test_id", "object": {}}
        event = Event.model_validate(event_data)

        assert event.type == expected_type

    def test_event_properties_parsed(self):
        """Event should parse and provide access to nested data via properties."""
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
        assert event.tip
        assert event.tip.tokens == 100
        assert event.user
        assert event.user.username == "tipper"


class TestUser:
    """Test User model parsing and field mapping."""

    def test_user_field_mapping(self):
        """User should correctly map camelCase API fields to snake_case."""
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


class TestMessage:
    """Test Message model and is_private property."""

    def test_public_message(self):
        """Message without from/to users should not be private."""
        message_data = {"message": "Hello everyone!"}
        message = Message.model_validate(message_data)

        assert message.message == "Hello everyone!"
        assert not message.is_private

    def test_private_message(self):
        """Message with from/to users should be identified as private."""
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


class TestTip:
    """Test Tip model parsing."""

    def test_tip_fields(self):
        """Tip should parse all fields correctly."""
        tip_data = {"tokens": 100, "isAnon": False, "message": "Great show!"}
        tip = Tip.model_validate(tip_data)

        assert tip.tokens == 100
        assert tip.is_anon is False
        assert tip.message == "Great show!"


class TestRoomSubject:
    """Test RoomSubject model parsing."""

    def test_room_subject_field(self):
        """RoomSubject should parse subject field."""
        subject_data = {"subject": "Welcome to my room!"}
        room_subject = RoomSubject.model_validate(subject_data)

        assert room_subject.subject == "Welcome to my room!"
