"""Shared helper utilities for test modules."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from cb_events import EventType

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

ALL_EVENT_TYPES: tuple[EventType, ...] = tuple(EventType)

CORE_EVENT_TYPES: tuple[EventType, ...] = (
    EventType.TIP,
    EventType.FOLLOW,
    EventType.CHAT_MESSAGE,
)

ITERATION_EVENT_TYPES: tuple[EventType, ...] = (
    EventType.TIP,
    EventType.FOLLOW,
    EventType.CHAT_MESSAGE,
    EventType.BROADCAST_START,
    EventType.PRIVATE_MESSAGE,
)

TESTBED_BASE_URL = (
    "https://events.testbed.cb.dev/events/test_user/test_token/?timeout=10"
)


def make_event(
    method: EventType = EventType.TIP,
    *,
    event_id: str = "evt-1",
    object: dict[str, Any] | None = None,  # noqa: A002
    **overrides: Any,
) -> dict[str, Any]:
    """Return a baseline event payload for the provided method."""
    payload: dict[str, Any] = {
        "method": method.value,
        "id": event_id,
        "object": object or {},
    }
    payload.update(overrides)
    return payload


def make_response(
    events: Iterable[dict[str, Any]],
    *,
    next_url: str | None = None,
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Construct an API response payload from the provided events.

    Returns:
        A dictionary representing the API response payload.
    """
    payload: dict[str, Any] = {"events": list(events), "nextUrl": next_url}
    if extra:
        payload.update(extra)
    return payload


def make_timeout_payload(
    next_url: str,
    *,
    events: Iterable[dict[str, Any]] | None = None,
    status: str = "waited too long for events",
) -> dict[str, Any]:
    """Build a timeout payload returned by the upstream API.

    Returns:
        A dictionary representing the timeout payload.
    """
    return {
        "status": status,
        "nextUrl": next_url,
        "events": list(events or []),
    }
