"""Unit tests for the Chaturbate Events API wrapper."""

import re
from typing import Any
from unittest.mock import AsyncMock

import aiohttp
import pytest
from aioresponses import aioresponses
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
from tests.conftest import create_url_pattern


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
    credentials: dict[str, Any],
    api_response: dict[str, Any],
    mock_aioresponse: aioresponses,
) -> None:
    """Test event polling and authentication error handling."""
    # Mock successful response
    url_pattern = create_url_pattern(credentials["username"], credentials["token"])
    mock_aioresponse.get(url_pattern, payload=api_response)

    async with EventClient(
        username=credentials["username"],
        token=credentials["token"],
        use_testbed=credentials["use_testbed"],
    ) as client:
        events = await client.poll()
        assert events
        assert isinstance(events[0], Event)

    # Test auth error
    mock_aioresponse.clear()
    mock_aioresponse.get(url_pattern, status=401, payload={})

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
    mock_aioresponse: aioresponses,
) -> None:
    """Test client processing of multiple events in a single API response."""
    api_response = {"events": multiple_events, "nextUrl": "url"}
    url_pattern = create_url_pattern(credentials["username"], credentials["token"])
    mock_aioresponse.get(url_pattern, payload=api_response)

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


@pytest.mark.parametrize(
    ("mock_response", "expected_error", "error_match"),
    [
        # HTTP error statuses
        ({"status": 400, "payload": {"error": "Bad request"}}, EventsError, "HTTP 400"),
        ({"status": 500, "body": "Internal Server Error"}, EventsError, "HTTP 500"),
        # JSON decode error
        (
            {"status": 200, "body": "Invalid JSON content"},
            EventsError,
            "Invalid JSON response",
        ),
        # Network errors
        (
            {"exception": TimeoutError("Connection timeout")},
            EventsError,
            "Request timeout",
        ),
        (
            {"exception": aiohttp.ClientConnectionError("Connection failed")},
            EventsError,
            "Network error",
        ),
        # Timeout with nextUrl (returns empty list instead of error)
        (
            {
                "status": 400,
                "payload": {
                    "status": "waited too long",
                    "nextUrl": "https://example.com/next",
                },
            },
            None,
            None,
        ),
    ],
)
@pytest.mark.asyncio
async def test_client_error_handling(
    credentials: dict[str, Any],
    mock_aioresponse: aioresponses,
    mock_response: dict[str, Any],
    expected_error: type[Exception] | None,
    error_match: str | None,
) -> None:
    """Test handling of various error conditions in client polling."""
    url_pattern = create_url_pattern(credentials["username"], credentials["token"])

    # Set up mock response
    if "exception" in mock_response:
        mock_aioresponse.get(url_pattern, exception=mock_response["exception"])
    else:
        mock_kwargs = {"url": url_pattern, "status": mock_response.get("status", 200)}
        if "payload" in mock_response:
            mock_kwargs["payload"] = mock_response["payload"]
        if "body" in mock_response:
            mock_kwargs["body"] = mock_response["body"]
        mock_aioresponse.get(**mock_kwargs)

    async with EventClient(
        username=str(credentials["username"]),
        token=str(credentials["token"]),
        use_testbed=bool(credentials["use_testbed"]),
    ) as client:
        if expected_error:
            with pytest.raises(expected_error, match=error_match):
                await client.poll()
        else:
            # Special case for timeout with nextUrl - should return empty list
            events = await client.poll()
            assert events == []
            if "nextUrl" in mock_response.get("payload", {}):
                assert client._next_url == mock_response["payload"]["nextUrl"]


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
@pytest.mark.parametrize(
    ("setup_func", "event_type", "expected_calls"),
    [
        ("setup_multiple_handlers", EventType.TIP, {"handler1": 1, "handler2": 1}),
        ("setup_no_handlers", EventType.TIP, {}),
        (
            "setup_global_and_specific",
            EventType.TIP,
            {"global_handler": 1, "tip_handler": 1, "follow_handler": 0},
        ),
    ],
)
@pytest.mark.asyncio
async def test_router_scenarios(
    setup_func: str,
    event_type: EventType,
    expected_calls: dict[str, int],
) -> None:
    """Test various EventRouter dispatching scenarios."""
    router = EventRouter()
    handlers = {}

    # Setup handlers based on scenario
    if setup_func == "setup_multiple_handlers":
        handlers["handler1"] = AsyncMock()
        handlers["handler2"] = AsyncMock()
        router.on(event_type)(handlers["handler1"])
        router.on(event_type)(handlers["handler2"])
    elif setup_func == "setup_no_handlers":
        pass  # No handlers registered
    elif setup_func == "setup_global_and_specific":
        handlers["global_handler"] = AsyncMock()
        handlers["tip_handler"] = AsyncMock()
        handlers["follow_handler"] = AsyncMock()
        router.on_any()(handlers["global_handler"])
        router.on(EventType.TIP)(handlers["tip_handler"])
        router.on(EventType.FOLLOW)(handlers["follow_handler"])

    # Create and dispatch event
    event = Event.model_validate({
        "method": event_type.value,
        "id": "test",
        "object": {},
    })

    # Should not raise any errors regardless of scenario
    await router.dispatch(event)

    # Verify expected calls
    for handler_name, expected_count in expected_calls.items():
        if handler_name in handlers:
            assert handlers[handler_name].call_count == expected_count


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


# Model validation tests
@pytest.mark.parametrize(
    ("model_class", "test_data", "expected_assertions"),
    [
        # User model tests
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
        # Message model - public message
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
        # Message model - private message
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
        # Tip model - anonymous tip
        (
            Tip,
            {
                "tokens": 100,
                "isAnon": True,
                "message": "Anonymous tip message",
            },
            [
                ("tokens", 100),
                ("is_anon", True),
                ("message", "Anonymous tip message"),
            ],
        ),
        # Tip model - regular tip
        (
            Tip,
            {
                "tokens": 50,
                "isAnon": False,
            },
            [
                ("tokens", 50),
                ("is_anon", False),
            ],
        ),
    ],
)
def test_model_validation_comprehensive(
    model_class: type[User | Message | Tip],
    test_data: dict[str, Any],
    expected_assertions: list[tuple[str, Any]],
) -> None:
    """Test comprehensive model validation for User, Message, and Tip models."""
    model_instance = model_class.model_validate(test_data)

    for attr_name, expected_value in expected_assertions:
        actual_value = getattr(model_instance, attr_name)
        assert actual_value == expected_value, (
            f"{attr_name}: expected {expected_value}, got {actual_value}"
        )


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
@pytest.mark.parametrize(
    ("error_class", "args", "kwargs", "expected_checks"),
    [
        # Basic EventsError
        (
            EventsError,
            ("Basic error message",),
            {},
            [
                ("message", "Basic error message"),
                ("status_code", None),
                ("response_text", None),
            ],
        ),
        # EventsError with all parameters
        (
            EventsError,
            ("Full error",),
            {
                "status_code": 500,
                "response_text": "Server error response",
                "request_id": "12345",
                "timeout": 30.0,
            },
            [
                ("message", "Full error"),
                ("status_code", 500),
                ("response_text", "Server error response"),
                ("extra_info", {"request_id": "12345", "timeout": 30.0}),
            ],
        ),
        # AuthError inheritance test
        (
            AuthError,
            ("Authentication failed",),
            {"status_code": 401, "response_text": "Unauthorized"},
            [
                ("message", "Authentication failed"),
                ("status_code", 401),
                ("response_text", "Unauthorized"),
                ("isinstance_EventsError", True),
            ],
        ),
    ],
)
def test_exception_handling_comprehensive(
    error_class: type[EventsError],
    args: tuple[str, ...],
    kwargs: dict[str, Any],
    expected_checks: list[tuple[str, Any]],
) -> None:
    """Test comprehensive exception handling for EventsError and AuthError."""
    error_instance = error_class(*args, **kwargs)

    for check_name, expected_value in expected_checks:
        if check_name == "isinstance_EventsError":
            assert isinstance(error_instance, EventsError)
        elif check_name == "extra_info":
            assert error_instance.extra_info == expected_value
        else:
            actual_value = getattr(error_instance, check_name)
            assert actual_value == expected_value

    # Test __repr__ method for EventsError with parameters
    if error_class == EventsError and kwargs:
        repr_str = repr(error_instance)
        assert error_instance.message in repr_str
        if error_instance.status_code:
            assert f"status_code={error_instance.status_code}" in repr_str


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
async def test_integration_client_router(mock_aioresponse: aioresponses) -> None:
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

    url_pattern = re.compile(r"https://events\.testbed\.cb\.dev/events/test/test/.*")
    mock_aioresponse.get(url_pattern, payload=api_response)

    # Set up router with handlers
    router = EventRouter()
    tip_handler = AsyncMock()
    chat_handler = AsyncMock()
    global_handler = AsyncMock()

    router.on(EventType.TIP)(tip_handler)
    router.on(EventType.CHAT_MESSAGE)(chat_handler)
    router.on_any()(global_handler)

    # Test integration
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
