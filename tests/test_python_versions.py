"""Tests for the project Python-version policy."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "python_versions.py"


def _run(*args: str) -> str:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        check=True,
        cwd=ROOT,
        capture_output=True,
        text=True,
    ).stdout.strip()


def test_python_policy_outputs_supported_versions() -> None:
    """The shell and GitHub outputs should expose the same matrix."""
    supported = _run("--shell").split()
    assert supported == json.loads(_run("--github-matrix"))
    assert supported


def test_python_policy_is_consistent() -> None:
    """All operational Python versions and classifiers should agree."""
    _run("--validate")
