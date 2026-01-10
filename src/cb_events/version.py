"""Version information for the package."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__: str = version("cb-events")
except PackageNotFoundError:  # pragma: no cover
    __version__ = "0.0.0"
