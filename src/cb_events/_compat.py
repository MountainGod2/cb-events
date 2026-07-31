"""Compatibility shims for standard-library symbols added in newer Python versions."""

from __future__ import annotations

import sys
from enum import StrEnum

if sys.version_info >= (3, 12):
    from typing import override  # pyright: ignore[reportUnreachable]
else:
    from typing_extensions import override


__all__ = ["StrEnum", "override"]
