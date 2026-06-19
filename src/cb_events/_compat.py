"""Compatibility shims for standard-library symbols added in recent Python versions.

Each symbol is gated to the Python version in which it was promoted to
``typing``, using an explicit ``sys.version_info`` check
"""

from __future__ import annotations

import sys

if sys.version_info >= (3, 12):
    # pyright targets 3.10, so it sees this branch as unreachable
    from typing import override  # pyright: ignore[reportUnreachable]
else:
    from typing_extensions import override

__all__ = ["override"]
