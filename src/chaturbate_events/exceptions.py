"""Exception classes for the Chaturbate Events client."""


class EventsError(Exception):
    """Base exception for all Events API failures."""


class AuthError(EventsError):
    """Authentication failure exception."""
