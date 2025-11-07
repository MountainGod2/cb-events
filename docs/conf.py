"""Documentation configuration file for Sphinx."""  # noqa: INP001

import importlib.metadata
import sys
from pathlib import Path

# Path setup
DOCS_DIR: Path = Path(__file__).resolve().parent
PROJECT_ROOT: Path = DOCS_DIR.parent
SRC_DIR: Path = PROJECT_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

# Project information
project = "cb_events"
author = "MountainGod2"
project_copyright = "2025, MountainGod2"
language = "en"

# Version
try:
    version: str = importlib.metadata.version("cb-events")
except importlib.metadata.PackageNotFoundError:
    from cb_events import __version__

    version = __version__

release: str = version

# Extensions
extensions: list[str] = [
    "sphinx.ext.napoleon",
    "sphinx.ext.intersphinx",
    "sphinx.ext.viewcode",
    "autoapi.extension",
    "sphinx_autodoc_typehints",
    "sphinxcontrib.autodoc_pydantic",
    "myst_nb",
]

# Build exclusions
exclude_patterns: list[str] = [
    "_build",
    "Thumbs.db",
    ".DS_Store",
    "**/.pytest_cache",
    "**/__pycache__",
]

# HTML theme configuration
html_theme = "sphinx_rtd_theme"
html_title = "cb_events API Client Library"
html_show_sourcelink = False
html_copy_source = False
html_last_updated_fmt = "%b %d, %Y"

html_theme_options: dict[str, bool | int] = {
    "navigation_depth": 4,
    "collapse_navigation": False,
    "sticky_navigation": True,
    "titles_only": False,
}

html_context: dict[str, bool | str] = {
    "display_github": True,
    "github_user": "MountainGod2",
    "github_repo": "cb-events",
    "github_version": "main",
    "conf_py_path": "/docs/",
}

# Napoleon docstring configuration
napoleon_google_docstring = True
napoleon_numpy_docstring = False
napoleon_include_special_with_doc = True
napoleon_use_param = True
napoleon_use_rtype = True
napoleon_attr_annotations = True

# AutoAPI configuration
autoapi_dirs: list[str] = [str(SRC_DIR / "cb_events")]
autoapi_type = "python"
autoapi_root = "api"
autoapi_member_order = "bysource"
autoapi_python_class_content = "class"
autoapi_keep_files = False

autoapi_options: list[str] = [
    "members",
    "show-inheritance",
    "show-module-summary",
]

autoapi_ignore: list[str] = [
    "*/tests/*",
    "*/test_*",
    "*/__pycache__/*",
    "*/conftest.py",
]

# Intersphinx mapping
intersphinx_mapping: dict[str, tuple[str, None]] = {
    "python": ("https://docs.python.org/3", None),
    "pydantic": ("https://docs.pydantic.dev/latest/", None),
    "aiohttp": ("https://docs.aiohttp.org/en/stable/", None),
}

# Type hints configuration
typehints_fully_qualified = False
typehints_document_rtype = True
always_document_param_types = True

# MyST-NB configuration
nb_execution_mode = "off"
myst_enable_extensions: list[str] = [
    "colon_fence",
    "deflist",
]

# Suppress warnings
suppress_warnings: list[str] = [
    "autoapi",
    "ref.python",
]
