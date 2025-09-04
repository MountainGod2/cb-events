"""Asynchronous client for the Chaturbate Events API."""

import json
import logging
from collections.abc import AsyncIterator
from http import HTTPStatus
from types import TracebackType
from typing import Self

import aiohttp

from .exceptions import AuthError, EventsError
from .models import Event

DEFAULT_TIMEOUT = 10
TOKEN_MASK_LENGTH = 4

logger = logging.getLogger(__name__)


class EventClient:
    """HTTP client for polling Chaturbate Events API."""

    BASE_URL = "https://eventsapi.chaturbate.com/events"
    TESTBED_URL = "https://events.testbed.cb.dev/events"

    def __init__(
        self,
        username: str,
        token: str,
        *,
        timeout: int = DEFAULT_TIMEOUT,
        use_testbed: bool = False,
    ) -> None:
        """Initialize the client with credentials and connection options."""
        if not username.strip():
            msg = "Username cannot be empty"
            raise ValueError(msg)
        if not token.strip():
            msg = "Token cannot be empty"
            raise ValueError(msg)

        self.username = username.strip()
        self.token = token.strip()
        self.timeout = timeout
        self.base_url = self.TESTBED_URL if use_testbed else self.BASE_URL
        self.session: aiohttp.ClientSession | None = None
        self._next_url: str | None = None

    def __repr__(self) -> str:
        """Return a string representation with masked token."""
        masked_token = self._mask_token(self.token)
        return f"EventClient(username='{self.username}', token='{masked_token}')"

    @staticmethod
    def _mask_token(token: str) -> str:
        """Mask token showing only last 4 characters."""
        if len(token) <= TOKEN_MASK_LENGTH:
            return "*" * len(token)
        return "*" * (len(token) - TOKEN_MASK_LENGTH) + token[-TOKEN_MASK_LENGTH:]

    def _mask_url(self, url: str) -> str:
        """Mask token in URL for logging."""
        return url.replace(self.token, self._mask_token(self.token))

    async def __aenter__(self) -> Self:
        """Create HTTP session."""
        if self.session is None or self.session.closed:
            timeout_cfg = aiohttp.ClientTimeout(total=self.timeout + 5)
            self.session = aiohttp.ClientSession(timeout=timeout_cfg)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Clean up resources."""
        await self.close()

    async def poll(self) -> list[Event]:
        """Perform a single poll and return parsed events."""
        if self.session is None:
            msg = "Session not initialized - use async context manager"
            raise EventsError(msg)

        url = (
            self._next_url
            or f"{self.base_url}/{self.username}/{self.token}/?timeout={self.timeout}"
        )

        logger.debug("Polling events from %s", self._mask_url(url))

        try:
            async with self.session.get(url) as resp:
                text = await resp.text()

                if resp.status in {HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN}:
                    logger.warning("Authentication failed for user %s", self.username)
                    msg = f"Authentication failed for {self.username}"
                    raise AuthError(msg)

                if resp.status == HTTPStatus.BAD_REQUEST and (
                    next_url := self._extract_next_url(text)
                ):
                    logger.debug("Received nextUrl from timeout response")
                    self._next_url = next_url
                    return []

                if resp.status != HTTPStatus.OK:
                    logger.error("HTTP error %d: %s", resp.status, text[:200])
                    msg = f"HTTP {resp.status}: {text[:200]}"
                    raise EventsError(msg)

                data = await resp.json()
                self._next_url = data["nextUrl"]
                events = [Event.model_validate(item) for item in data.get("events", [])]
                logger.debug("Received %d events", len(events))
                return events

        except TimeoutError as err:
            logger.warning("Request timeout after %ds", self.timeout)
            msg = f"Request timeout after {self.timeout}s"
            raise EventsError(msg) from err
        except aiohttp.ClientError as err:
            logger.exception("Network error occurred")
            msg = f"Network error: {err}"
            raise EventsError(msg) from err
        except json.JSONDecodeError as err:
            logger.exception("Invalid JSON response received")
            msg = f"Invalid JSON response: {err}"
            raise EventsError(msg) from err

    def _extract_next_url(self, text: str) -> str | None:
        """Extract nextUrl from timeout error response."""
        try:
            error_data = json.loads(text)
            if "waited too long" in error_data.get("status", "").lower():
                next_url = error_data.get("nextUrl")
                return str(next_url) if next_url else None
        except (json.JSONDecodeError, KeyError):
            pass
        return None

    async def poll_continuously(self) -> AsyncIterator[Event]:
        """Continuously yield events from the API."""
        while True:
            events = await self.poll()
            for event in events:
                yield event

    def __aiter__(self) -> AsyncIterator[Event]:
        """Allow async iteration over the client."""
        return self.poll_continuously()

    async def close(self) -> None:
        """Close the HTTP session."""
        if self.session:
            await self.session.close()
            self.session = None
        self._next_url = None
