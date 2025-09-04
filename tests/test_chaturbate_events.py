"""Unit tests for the Chaturbate Events API wrapper."""

from typing import Any
from unittest.mock import AsyncMock

import pytest

from chaturbate_events import (
    AuthError,
    Event,
    EventClient,
    EventRouter,
    EventType,
)
from chaturbate_events.models import Message, User


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
async def test_client_poll_and_auth(credentials, mock_http_get, mocker):
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
async def test_client_multiple_events(credentials, multiple_events, mocker):
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
async def test_client_cleanup(credentials):
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
async def test_router_dispatch(event_type):
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
