"""Exception classes for the Chaturbate Events client."""


class EventsError(Exception):
    """Base exception for all Chaturbate Events API failures.

    This is the parent class for all exceptions that can be raised
    when interacting with the Events API.
    """


class AuthError(EventsError):
    """Authentication failure with the Events API.

    Raised when credentials are invalid or insufficient permissions
    are granted for the requested operation.
    """
