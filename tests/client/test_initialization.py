# pyright: reportMissingParameterType=false
# pyright: reportUnknownParameterType=false
# pyright: reportUnknownArgumentType=false
# pyright: reportUnknownMemberType=false

"""Initialization tests for :class:`cb_events.EventClient`."""

import pytest

from cb_events import EventClient
from cb_events.exceptions import AuthError


def test_token_masking_in_repr() -> None:
    """Token should be masked while preserving the final characters."""
    client = EventClient("user", "secret_token_1234")
    repr_str = str(client)

    assert repr_str.count("1234") == 1
    assert "secret_token" not in repr_str


@pytest.mark.parametrize(
    ("username", "token", "message"),
    [
        ("", "token", "Username cannot be empty or contain"),
        (" user ", "token", "Username cannot be empty or contain"),
        ("user", "", "Token cannot be empty or contain"),
        ("user", " token ", "Token cannot be empty or contain"),
    ],
)
def test_reject_invalid_credentials(username: str, token: str, message: str) -> None:
    """Invalid credentials should raise an ``AuthError`` with guidance."""
    with pytest.raises(AuthError, match=message):
        EventClient(username, token)
