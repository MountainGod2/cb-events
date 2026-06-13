"""Compatibility shims for standard-library symbols added in recent Python versions.

Each symbol is gated to the Python version in which it was promoted to
``typing``, using an explicit ``sys.version_info`` check
"""

from __future__ import annotations

import sys

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override

if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self

__all__ = ["Self", "override"]
