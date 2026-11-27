"""Read project Python-version policy from pyproject.toml."""

from __future__ import annotations

import argparse
import json
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"


def _policy() -> dict[str, object]:
    with PYPROJECT.open("rb") as file:
        project = tomllib.load(file)
    return project["tool"]["cb-events"]


def _supported_versions(policy: dict[str, object]) -> list[str]:
    versions = policy["supported-python-versions"]
    if not isinstance(versions, list) or not all(isinstance(item, str) for item in versions):
        msg = "supported-python-versions must be a list of strings"
        raise SystemExit(msg)
    return versions


def _string_policy(policy: dict[str, object], key: str) -> str:
    value = policy[key]
    if not isinstance(value, str):
        msg = f"{key} must be a string"
        raise SystemExit(msg)
    return value


def main(argv: list[str] | None = None) -> int:
    """Print or validate the configured Python version policy."""
    parser = argparse.ArgumentParser()
    output = parser.add_mutually_exclusive_group(required=True)
    output.add_argument("--shell", action="store_true")
    output.add_argument("--github-matrix", action="store_true")
    output.add_argument("--lint-python", action="store_true")
    output.add_argument("--lowest-direct-python", action="store_true")
    output.add_argument("--cross-platform-python", action="store_true")
    output.add_argument("--validate", action="store_true")
    args = parser.parse_args(argv)

    policy = _policy()
    supported = _supported_versions(policy)

    if args.shell:
        sys.stdout.write(" ".join(supported) + "\n")
    elif args.github_matrix:
        sys.stdout.write(json.dumps(supported) + "\n")
    elif args.lint_python:
        sys.stdout.write(_string_policy(policy, "lint-python-version") + "\n")
    elif args.lowest_direct_python:
        sys.stdout.write(_string_policy(policy, "lowest-direct-python-version") + "\n")
    elif args.cross_platform_python:
        sys.stdout.write(_string_policy(policy, "cross-platform-python-version") + "\n")
    elif args.validate:
        with PYPROJECT.open("rb") as file:
            project = tomllib.load(file)
        classifier_versions = {
            classifier.removeprefix("Programming Language :: Python :: ")
            for classifier in project["project"]["classifiers"]
            if classifier.startswith("Programming Language :: Python :: 3.")
        }
        if set(supported) != classifier_versions:
            msg = (
                "Python support policy does not match project classifiers: "
                f"policy={supported}, classifiers={sorted(classifier_versions)}"
            )
            raise SystemExit(msg)
        operational_versions = {
            _string_policy(policy, "lint-python-version"),
            _string_policy(policy, "lowest-direct-python-version"),
            _string_policy(policy, "cross-platform-python-version"),
        }
        unsupported = operational_versions - set(supported)
        if unsupported:
            msg = (
                "Operational Python versions must belong to supported-python-versions: "
                f"{sorted(unsupported)}"
            )
            raise SystemExit(msg)
        minimum = supported[0]
        ruff_target = project["tool"]["ruff"]["target-version"]
        basedpyright_version = project["tool"]["basedpyright"]["pythonVersion"]
        if ruff_target != f"py{minimum.replace('.', '')}":
            msg = (
                "Ruff target-version does not match the minimum supported Python: "
                f"{ruff_target} != py{minimum.replace('.', '')}"
            )
            raise SystemExit(msg)
        if basedpyright_version != minimum:
            msg = (
                "basedpyright pythonVersion does not match the minimum supported Python: "
                f"{basedpyright_version} != {minimum}"
            )
            raise SystemExit(msg)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
