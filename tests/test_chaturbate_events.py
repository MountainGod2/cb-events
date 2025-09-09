"""Unit tests for the Chaturbate Events API wrapper."""

import json
from typing import Any
from unittest.mock import AsyncMock, patch

import aiohttp
import pytest
from pytest_mock import MockerFixture

from chaturbate_events import (
    AuthError,
    Event,
    EventClient,
    EventRouter,
    EventsError,
    EventType,
)
from chaturbate_events.models import Message, Tip, User


@pytest.mark.parametrize(
    ("event_data", "expected_type"),
    [
        ({"method": "tip", "id": "1", "object": {}}, EventType.TIP),
        ({"method": "chatMessage", "id": "2", "object": {}}, EventType.CHAT_MESSAGE),
    ],
)
def test_event_model(event_data: dict[str, Any], expected_type: EventType) -> None:
    """Test Event model validation and type mapping functionality."""
    event = Event.model_validate(event_data)
    assert event.type == expected_type
    assert event.id == event_data["id"]
    assert isinstance(event.data, dict)


@pytest.mark.asyncio
async def test_client_poll_and_auth(
    credentials: dict[str, Any], mock_http_get: AsyncMock, mocker: MockerFixture
) -> None:
    """Test event polling and authentication error handling."""
    async with EventClient(
        username=credentials["username"],
        token=credentials["token"],
        use_testbed=credentials["use_testbed"],
    ) as client:
        events = await client.poll()
        assert events
        assert isinstance(events[0], Event)
        mock_http_get.assert_called_once()

    # Simulate auth error
    response_mock = AsyncMock(status=401)
    response_mock.text = AsyncMock(return_value="")
    context_mock = AsyncMock(
        __aenter__=AsyncMock(return_value=response_mock),
        __aexit__=AsyncMock(return_value=None),
    )
    mocker.patch("aiohttp.ClientSession.get", return_value=context_mock)
    async with EventClient(
        username=credentials["username"],
        token=credentials["token"],
        use_testbed=credentials["use_testbed"],
    ) as client:
        with pytest.raises(AuthError, match="Authentication failed for"):
            await client.poll()


@pytest.mark.asyncio
async def test_client_multiple_events(
    credentials: dict[str, Any],
    multiple_events: list[dict[str, Any]],
    mocker: MockerFixture,
) -> None:
    """Test client processing of multiple events in a single API response."""
    api_response = {"events": multiple_events, "nextUrl": "url"}
    response_mock = AsyncMock(status=200)
    response_mock.json = AsyncMock(return_value=api_response)
    context_mock = AsyncMock(
        __aenter__=AsyncMock(return_value=response_mock),
        __aexit__=AsyncMock(return_value=None),
    )
    mocker.patch("aiohttp.ClientSession.get", return_value=context_mock)
    async with EventClient(
        username=credentials["username"],
        token=credentials["token"],
        use_testbed=credentials["use_testbed"],
    ) as client:
        events = await client.poll()
        types = [e.type for e in events]
        assert types == [EventType.TIP, EventType.FOLLOW, EventType.CHAT_MESSAGE]


@pytest.mark.asyncio
async def test_client_cleanup(credentials: dict[str, Any]) -> None:
    """Test proper cleanup of client resources and session management."""
    client = EventClient(
        username=credentials["username"],
        token=credentials["token"],
        use_testbed=credentials["use_testbed"],
    )
    async with client:
        pass
    await client.close()


@pytest.mark.parametrize(
    ("username", "token", "err"),
    [
        ("", "t", "Username cannot be empty"),
        (" ", "t", "Username cannot be empty"),
        ("u", "", "Token cannot be empty"),
        ("u", " ", "Token cannot be empty"),
    ],
)
def test_client_validation(username: str, token: str, err: str) -> None:
    """Test input validation for EventClient initialization."""
    with pytest.raises(ValueError, match=err):
        EventClient(username=username, token=token)


def test_event_validation() -> None:
    """Test Event model validation with invalid input data."""
    with pytest.raises(ValueError, match="Input should be"):
        Event.model_validate({"method": "invalid", "id": "x"})


def test_model_properties() -> None:
    """Test data model properties and type conversion functionality."""
    user = User.model_validate({
        "username": "u",
        "colorGroup": "tr",
        "fcAutoRenew": True,
        "gender": "m",
        "hasDarkmode": False,
        "hasTokens": True,
        "inFanclub": False,
        "inPrivateShow": False,
        "isBroadcasting": True,
        "isFollower": True,
        "isMod": False,
        "isOwner": False,
        "isSilenced": False,
        "isSpying": False,
        "language": "en",
        "recentTips": "x",
        "subgender": "",
    })
    assert user.username == "u"
    assert user.color_group == "tr"
    assert user.fc_auto_renew

    message = Message.model_validate({
        "message": "hi",
        "bgColor": "#F00",
        "color": "#FFF",
        "font": "arial",
        "orig": None,
        "fromUser": "a",
        "toUser": "b",
    })
    assert message.message == "hi"
    assert message.bg_color == "#F00"
    assert message.from_user == "a"

    event = Event.model_validate({
        "method": "roomSubjectChange",
        "id": "s",
        "object": {"broadcaster": "u", "subject": "topic"},
    })
    assert event.room_subject is not None
    assert event.room_subject.subject == "topic"
    assert event.broadcaster == "u"

    chat_event = Event.model_validate({
        "method": "chatMessage",
        "id": "c",
        "object": {"message": {"message": "hi"}},
    })
    tip_event = Event.model_validate({
        "method": "tip",
        "id": "t",
        "object": {"tip": {"tokens": 50}},
    })
    assert chat_event.tip is None
    assert tip_event.message is None
    assert tip_event.room_subject is None


@pytest.mark.parametrize(
    "event_type",
    [EventType.TIP, EventType.CHAT_MESSAGE, EventType.BROADCAST_START],
)
@pytest.mark.asyncio
async def test_router_dispatch(event_type: EventType) -> None:
    """Test EventRouter event dispatching to registered handlers."""
    router = EventRouter()
    handler = AsyncMock()
    router.on(event_type)(handler)
    event = Event.model_validate({
        "method": event_type.value,
        "id": "x",
        "object": {},
    })
    await router.dispatch(event)
    handler.assert_called_once_with(event)
    any_handler = AsyncMock()
    router.on_any()(any_handler)
    await router.dispatch(event)
    any_handler.assert_called_once_with(event)


# Additional EventClient tests
def test_client_token_masking() -> None:
    """Test token masking in client representation and URL masking."""
    client = EventClient(username="testuser", token="abcdef12345")

    # Test __repr__ masks token
    repr_str = repr(client)
    assert "abcdef12345" not in repr_str
    assert "*******2345" in repr_str  # Shows last 4 chars with asterisks

    # Test short token masking
    short_client = EventClient(username="user", token="abc")
    short_repr = repr(short_client)
    assert "abc" not in short_repr
    assert "***" in short_repr

    # Test URL masking
    test_url = "https://example.com?token=abcdef12345"
    masked_url = client._mask_url(test_url)
    assert "abcdef12345" not in masked_url
    assert "2345" in masked_url  # Should show last 4 chars


@pytest.mark.asyncio
async def test_client_http_errors(
    credentials: dict[str, Any], mocker: MockerFixture
) -> None:
    """Test handling of various HTTP error status codes."""
    # Test 400 Bad Request without nextUrl
    response_mock = AsyncMock(status=400)
    response_mock.text = AsyncMock(return_value='{"error": "Bad request"}')
    context_mock = AsyncMock(
        __aenter__=AsyncMock(return_value=response_mock),
        __aexit__=AsyncMock(return_value=None),
    )
    mocker.patch("aiohttp.ClientSession.get", return_value=context_mock)

    async with EventClient(
        username=str(credentials["username"]),
        token=str(credentials["token"]),
        use_testbed=bool(credentials["use_testbed"]),
    ) as client:
        with pytest.raises(EventsError, match="HTTP 400"):
            await client.poll()

    # Test 500 Internal Server Error
    response_mock = AsyncMock(status=500)
    response_mock.text = AsyncMock(return_value="Internal Server Error")
    context_mock = AsyncMock(
        __aenter__=AsyncMock(return_value=response_mock),
        __aexit__=AsyncMock(return_value=None),
    )
    mocker.patch("aiohttp.ClientSession.get", return_value=context_mock)

    async with EventClient(
        username=str(credentials["username"]),
        token=str(credentials["token"]),
        use_testbed=bool(credentials["use_testbed"]),
    ) as client:
        with pytest.raises(EventsError, match="HTTP 500"):
            await client.poll()


@pytest.mark.asyncio
async def test_client_timeout_with_next_url(
    credentials: dict[str, Any], mocker: MockerFixture
) -> None:
    """Test handling of timeout responses with nextUrl extraction."""
    timeout_response = {
        "status": "waited too long",
        "nextUrl": "https://events.testbed.cb.dev/events/next",
    }
    response_mock = AsyncMock(status=400)
    response_mock.text = AsyncMock(return_value=json.dumps(timeout_response))
    context_mock = AsyncMock(
        __aenter__=AsyncMock(return_value=response_mock),
        __aexit__=AsyncMock(return_value=None),
    )
    mocker.patch("aiohttp.ClientSession.get", return_value=context_mock)

    async with EventClient(
        username=str(credentials["username"]),
        token=str(credentials["token"]),
        use_testbed=bool(credentials["use_testbed"]),
    ) as client:
        events = await client.poll()
        assert events == []
        assert client._next_url == timeout_response["nextUrl"]


@pytest.mark.asyncio
async def test_client_json_decode_error(
    credentials: dict[str, Any], mocker: MockerFixture
) -> None:
    """Test handling of invalid JSON responses."""
    response_mock = AsyncMock(status=200)
    response_mock.text = AsyncMock(return_value="Invalid JSON content")
    response_mock.json = AsyncMock(side_effect=json.JSONDecodeError("msg", "doc", 0))
    context_mock = AsyncMock(
        __aenter__=AsyncMock(return_value=response_mock),
        __aexit__=AsyncMock(return_value=None),
    )
    mocker.patch("aiohttp.ClientSession.get", return_value=context_mock)

    async with EventClient(
        username=str(credentials["username"]),
        token=str(credentials["token"]),
        use_testbed=bool(credentials["use_testbed"]),
    ) as client:
        with pytest.raises(EventsError, match="Invalid JSON response"):
            await client.poll()


@pytest.mark.asyncio
async def test_client_network_errors(
    credentials: dict[str, Any], mocker: MockerFixture
) -> None:
    """Test handling of network-related errors."""
    # Test TimeoutError
    mocker.patch(
        "aiohttp.ClientSession.get", side_effect=TimeoutError("Connection timeout")
    )

    async with EventClient(
        username=str(credentials["username"]),
        token=str(credentials["token"]),
        use_testbed=bool(credentials["use_testbed"]),
    ) as client:
        with pytest.raises(EventsError, match="Request timeout"):
            await client.poll()

    # Test aiohttp.ClientError
    mocker.patch(
        "aiohttp.ClientSession.get",
        side_effect=aiohttp.ClientConnectionError("Connection failed"),
    )

    async with EventClient(
        username=str(credentials["username"]),
        token=str(credentials["token"]),
        use_testbed=bool(credentials["use_testbed"]),
    ) as client:
        with pytest.raises(EventsError, match="Network error"):
            await client.poll()


@pytest.mark.asyncio
async def test_client_session_not_initialized(credentials: dict[str, Any]) -> None:
    """Test polling without initializing session raises error."""
    client = EventClient(
        username=str(credentials["username"]),
        token=str(credentials["token"]),
        use_testbed=bool(credentials["use_testbed"]),
    )
    with pytest.raises(EventsError, match="Session not initialized"):
        await client.poll()


@pytest.mark.asyncio
async def test_client_continuous_polling(
    credentials: dict[str, Any], mocker: MockerFixture
) -> None:
    """Test continuous polling with async iteration."""
    # Create multiple response batches
    responses = [
        {"events": [{"method": "tip", "id": "1", "object": {}}], "nextUrl": "url1"},
        {"events": [{"method": "follow", "id": "2", "object": {}}], "nextUrl": "url2"},
        {"events": [], "nextUrl": "url3"},  # Empty response
    ]

    call_count = 0

    def mock_response(*_args: Any, **_kwargs: Any) -> AsyncMock:
        nonlocal call_count
        response_mock = AsyncMock(status=200)
        response_mock.json = AsyncMock(
            return_value=responses[call_count % len(responses)]
        )
        response_mock.text = AsyncMock(return_value="")
        context_mock = AsyncMock(
            __aenter__=AsyncMock(return_value=response_mock),
            __aexit__=AsyncMock(return_value=None),
        )
        call_count += 1
        return context_mock

    mocker.patch("aiohttp.ClientSession.get", side_effect=mock_response)

    async with EventClient(
        username=str(credentials["username"]),
        token=str(credentials["token"]),
        use_testbed=bool(credentials["use_testbed"]),
    ) as client:
        event_count = 0
        async for event in client:
            assert isinstance(event, Event)
            event_count += 1
            if event_count >= 2:  # Stop after receiving 2 events
                break


def test_extract_next_url_edge_cases() -> None:
    """Test _extract_next_url with various response formats."""
    # Valid timeout response
    timeout_json = '{"status": "waited too long", "nextUrl": "http://example.com"}'
    assert EventClient._extract_next_url(timeout_json) == "http://example.com"

    # Case insensitive matching
    timeout_json_caps = '{"status": "WAITED TOO LONG", "nextUrl": "http://example.com"}'
    assert EventClient._extract_next_url(timeout_json_caps) == "http://example.com"

    # Missing nextUrl
    no_next_url = '{"status": "waited too long"}'
    assert EventClient._extract_next_url(no_next_url) is None

    # Invalid JSON
    assert EventClient._extract_next_url("invalid json") is None

    # Different status message
    different_status = '{"status": "different error", "nextUrl": "http://example.com"}'
    assert EventClient._extract_next_url(different_status) is None

    # Empty response
    assert EventClient._extract_next_url("") is None


# Additional EventRouter tests
@pytest.mark.asyncio
async def test_router_multiple_handlers() -> None:
    """Test multiple handlers for the same event type."""
    router = EventRouter()
    handler1 = AsyncMock()
    handler2 = AsyncMock()

    router.on(EventType.TIP)(handler1)
    router.on(EventType.TIP)(handler2)

    event = Event.model_validate({
        "method": EventType.TIP.value,
        "id": "test",
        "object": {},
    })

    await router.dispatch(event)

    handler1.assert_called_once_with(event)
    handler2.assert_called_once_with(event)


def test_router_string_event_types() -> None:
    """Test router with string-based event type registration."""
    router = EventRouter()
    handler = AsyncMock()

    # Register with string instead of EventType enum
    router.on("customEvent")(handler)

    # Create event with custom method
    event_data = {"method": "customEvent", "id": "test", "object": {}}

    # This will fail validation since customEvent is not in EventType enum
    with pytest.raises(ValueError, match="Input should be"):
        Event.model_validate(event_data)


@pytest.mark.asyncio
async def test_router_no_handlers() -> None:
    """Test dispatching events with no registered handlers."""
    router = EventRouter()
    event = Event.model_validate({
        "method": EventType.TIP.value,
        "id": "test",
        "object": {},
    })

    # Should not raise any errors
    await router.dispatch(event)


@pytest.mark.asyncio
async def test_router_global_and_specific_handlers() -> None:
    """Test combination of global and event-specific handlers."""
    router = EventRouter()
    global_handler = AsyncMock()
    tip_handler = AsyncMock()
    follow_handler = AsyncMock()

    router.on_any()(global_handler)
    router.on(EventType.TIP)(tip_handler)
    router.on(EventType.FOLLOW)(follow_handler)

    tip_event = Event.model_validate({
        "method": EventType.TIP.value,
        "id": "tip",
        "object": {},
    })

    await router.dispatch(tip_event)

    # Global handler should be called for all events
    global_handler.assert_called_once_with(tip_event)
    # Only tip handler should be called for tip events
    tip_handler.assert_called_once_with(tip_event)
    follow_handler.assert_not_called()


# Additional Model tests
def test_user_model_comprehensive() -> None:
    """Test User model with comprehensive field combinations."""
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
    assert user.has_darkmode is True
    assert user.in_fanclub is True
    assert user.is_mod is True
    assert user.is_spying is True


def test_message_model_variations() -> None:
    """Test Message model with various field combinations."""
    # Public chat message
    public_msg = Message.model_validate({
        "message": "Hello everyone!",
        "bgColor": "#FF0000",
        "color": "#FFFFFF",
        "font": "arial",
    })
    assert public_msg.message == "Hello everyone!"
    assert public_msg.bg_color == "#FF0000"
    assert public_msg.from_user is None
    assert public_msg.to_user is None

    # Private message
    private_msg = Message.model_validate({
        "message": "Private hello",
        "fromUser": "sender",
        "toUser": "receiver",
        "orig": "original text",
    })
    assert private_msg.message == "Private hello"
    assert private_msg.from_user == "sender"
    assert private_msg.to_user == "receiver"
    assert private_msg.orig == "original text"


def test_tip_model_anonymous() -> None:
    """Test Tip model with anonymous tip functionality."""
    # Anonymous tip
    anon_tip = Tip.model_validate({
        "tokens": 100,
        "isAnon": True,
        "message": "Anonymous tip message",
    })
    assert anon_tip.tokens == 100
    assert anon_tip.is_anon is True
    assert anon_tip.message == "Anonymous tip message"

    # Regular tip
    regular_tip = Tip.model_validate({
        "tokens": 50,
        "isAnon": False,
    })
    assert regular_tip.tokens == 50
    assert regular_tip.is_anon is False
    assert not regular_tip.message  # Default empty message


def test_event_properties_edge_cases() -> None:
    """Test Event model properties with missing or incorrect data."""
    # Event without user data
    event_no_user = Event.model_validate({
        "method": EventType.TIP.value,
        "id": "test",
        "object": {"tip": {"tokens": 50}},
    })
    assert event_no_user.user is None
    assert event_no_user.tip is not None
    assert event_no_user.message is None

    # Non-tip event trying to access tip property
    chat_event = Event.model_validate({
        "method": EventType.CHAT_MESSAGE.value,
        "id": "test",
        "object": {"message": {"message": "hello"}},
    })
    assert chat_event.tip is None  # Should be None for non-tip events
    assert chat_event.message is not None

    # Event with broadcaster
    broadcast_event = Event.model_validate({
        "method": EventType.BROADCAST_START.value,
        "id": "test",
        "object": {"broadcaster": "streamer123"},
    })
    assert broadcast_event.broadcaster == "streamer123"


# Exception handling tests
def test_events_error_comprehensive() -> None:
    """Test EventsError with various parameter combinations."""
    # Basic error
    basic_error = EventsError("Basic error message")
    assert basic_error.message == "Basic error message"
    assert basic_error.status_code is None
    assert basic_error.response_text is None

    # Error with all parameters
    full_error = EventsError(
        "Full error",
        status_code=500,
        response_text="Server error response",
        request_id="12345",
        timeout=30.0,
    )
    assert full_error.status_code == 500
    assert full_error.response_text == "Server error response"
    assert full_error.extra_info["request_id"] == "12345"
    assert full_error.extra_info["timeout"] == 30.0

    # Test __repr__ method
    repr_str = repr(full_error)
    assert "Full error" in repr_str
    assert "status_code=500" in repr_str
    assert "Server error response" in repr_str


def test_auth_error_inheritance() -> None:
    """Test AuthError as subclass of EventsError."""
    auth_error = AuthError(
        "Authentication failed", status_code=401, response_text="Unauthorized"
    )
    assert isinstance(auth_error, EventsError)
    assert auth_error.message == "Authentication failed"
    assert auth_error.status_code == 401


# Additional validation tests
def test_model_validation_errors() -> None:
    """Test model validation with malformed data."""
    # Event with missing required fields
    with pytest.raises(ValueError, match="Field required"):
        Event.model_validate({"method": "tip"})  # Missing id

    # Event with invalid method
    with pytest.raises(ValueError, match="Input should be"):
        Event.model_validate({"method": "invalidMethod", "id": "test"})

    # User with invalid data types
    with pytest.raises(ValueError, match="Input should be a valid string"):
        User.model_validate({"username": 123})  # Should be string


@pytest.mark.asyncio
async def test_integration_client_router() -> None:
    """Test integration between EventClient and EventRouter."""
    credentials = {"username": "test", "token": "test", "use_testbed": True}

    # Mock successful API response

    api_response = {
        "events": [
            {"method": "tip", "id": "1", "object": {"tip": {"tokens": 100}}},
            {
                "method": "chatMessage",
                "id": "2",
                "object": {"message": {"message": "hi"}},
            },
        ],
        "nextUrl": "next_url",
    }

    response_mock = AsyncMock(status=200)
    response_mock.json = AsyncMock(return_value=api_response)
    response_mock.text = AsyncMock(return_value="")
    context_mock = AsyncMock(
        __aenter__=AsyncMock(return_value=response_mock),
        __aexit__=AsyncMock(return_value=None),
    )

    # Set up router with handlers
    router = EventRouter()
    tip_handler = AsyncMock()
    chat_handler = AsyncMock()
    global_handler = AsyncMock()

    router.on(EventType.TIP)(tip_handler)
    router.on(EventType.CHAT_MESSAGE)(chat_handler)
    router.on_any()(global_handler)

    # Test integration
    with patch("aiohttp.ClientSession.get", return_value=context_mock):
        async with EventClient(
            username=str(credentials["username"]),
            token=str(credentials["token"]),
            use_testbed=bool(credentials["use_testbed"]),
        ) as client:
            events = await client.poll()

            # Dispatch all events through router
            for event in events:
                await router.dispatch(event)

    # Verify handlers were called appropriately
    assert tip_handler.call_count == 1
    assert chat_handler.call_count == 1
    assert global_handler.call_count == 2  # Called for both events
