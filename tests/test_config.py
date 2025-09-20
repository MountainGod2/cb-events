"""Test configuration and shared constants."""

# Test credentials
TEST_CREDENTIALS = {
    "username": "test_user",
    "token": "test_token",
    "use_testbed": True,
}

# Common test URLs and patterns
TESTBED_BASE_URL = "https://events.testbed.cb.dev/events"

# Sample data for testing
SAMPLE_EVENT_DATA = {
    "tip": {
        "method": "tip",
        "id": "event_123",
        "object": {
            "tip": {"tokens": 100},
            "user": {"username": "test_tipper"},
            "message": {"message": "Great show!"},
        },
    },
    "chat_message": {
        "method": "chatMessage",
        "id": "event_456",
        "object": {
            "message": {"message": "Hello everyone!"},
            "user": {"username": "test_chatter"},
        },
    },
    "follow": {
        "method": "follow",
        "id": "event_789",
        "object": {
            "user": {"username": "test_follower"},
        },
    },
}
