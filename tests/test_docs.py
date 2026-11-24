"""Executable smoke tests for documentation examples."""

from __future__ import annotations

from pathlib import Path
from typing import Self

import pytest

import cb_events

_ROOT = Path(__file__).parents[1]


class _DocumentationClient:
    """In-memory stream used to execute quickstart examples."""

    def __init__(self, _events_url: str) -> None:
        self._events = iter([
            cb_events.Event.model_validate({
                "method": "userEnter",
                "id": "docs-enter",
                "object": {"user": {"username": "example"}},
            }),
            cb_events.Event.model_validate({
                "method": "tip",
                "id": "docs-tip",
                "object": {
                    "user": {"username": "example"},
                    "tip": {"tokens": 100},
                },
            }),
        ])

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    def __aiter__(self) -> _DocumentationClient:
        return self

    async def __anext__(self) -> cb_events.Event:
        try:
            return next(self._events)
        except StopIteration:
            raise StopAsyncIteration from None


@pytest.mark.parametrize(
    "example_path",
    [_ROOT / "README.md", _ROOT / "docs/snippets/quickstart.py"],
)
def test_quickstart_example_executes(
    example_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Quickstart sources should remain importable and runnable without network access."""
    monkeypatch.setattr(cb_events, "EventClient", _DocumentationClient)
    if example_path.suffix == ".md":
        text = example_path.read_text(encoding="utf-8")
        source = text.split("```python", 1)[1].split("```", 1)[0]
    else:
        source = example_path.read_text(encoding="utf-8")

    exec(  # ruff: ignore[exec-builtin]
        compile(source, str(example_path), "exec"),
        {"__name__": "__main__"},
    )
