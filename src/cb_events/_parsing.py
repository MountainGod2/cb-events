"""Parse raw API responses into typed event batches."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, Field, ValidationError
from pydantic.config import ConfigDict

from ._utils import format_validation_error_locations
from .exceptions import EventsError
from .models import Event

logger = logging.getLogger(__name__)


class _RawEventBatch(BaseModel):
    """Raw payload shape from the Events API."""

    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    next_url: str | None = Field(alias="nextUrl")
    events: list[dict[str, Any]] = Field(default_factory=list)


@dataclass(slots=True)
class EventBatch:
    """Validated events and next polling URL."""

    next_url: str | None
    events: list[Event]


def build_event_batch(
    payload: dict[str, Any],
    *,
    strict_validation: bool,
    raw_text: str | None = None,
) -> EventBatch:
    """Validate API payload and build an EventBatch.

    Args:
        payload: Decoded HTTP response body.
        strict_validation: If True, raise on any invalid event. If False, log and skip.
        raw_text: Original response text for error messages.

    Returns:
        EventBatch with parsed events and next_url.

    Raises:
        EventsError: If payload structure is invalid.
    """
    try:
        raw_batch = _RawEventBatch.model_validate(payload)
    except ValidationError as exc:
        msg = "Invalid API response"
        raise EventsError(msg, response_text=raw_text or str(payload)) from exc

    events = _validate_events(raw_batch.events, strict_validation=strict_validation)
    return EventBatch(next_url=raw_batch.next_url, events=events)


def _validate_events(
    raw_events: list[dict[str, Any]],
    *,
    strict_validation: bool,
) -> list[Event]:
    """Parse raw event dictionaries into Event models.

    Args:
        raw_events: Raw event payloads.
        strict_validation: If True, raise on invalid events. If False, skip them.

    Returns:
        List of validated Event models.

    Raises:
        ValidationError: If strict_validation=True and an event fails validation.
    """
    events: list[Event] = []
    for item in raw_events:
        try:
            events.append(Event.model_validate(item))
        except ValidationError as exc:
            if strict_validation:
                raise
            event_id = str(item.get("id", "<unknown>"))
            locations = format_validation_error_locations(exc)
            logger.warning("event_id=%s locations=%s", event_id, locations)
    return events
