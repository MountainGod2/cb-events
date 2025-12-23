"""Sphinx documentation configuration for cb-events."""  # noqa: INP001

from __future__ import annotations

import importlib.metadata
import sys
from pathlib import Path

# -- Path setup --------------------------------------------------------------
DOCS_DIR: Path = Path(__file__).resolve().parent
PROJECT_ROOT: Path = DOCS_DIR.parent
SRC_DIR: Path = PROJECT_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

# -- Project information -----------------------------------------------------
project = "cb-events"
author = "MountainGod2"
project_copyright = "2025, MountainGod2"
language = "en"

try:
    version: str = importlib.metadata.version("cb-events")
except importlib.metadata.PackageNotFoundError:
    from cb_events import __version__

    version = __version__
release: str = version

# -- General configuration ---------------------------------------------------
extensions: list[str] = [
    "sphinx.ext.napoleon",
    "sphinx.ext.intersphinx",
    "sphinx.ext.viewcode",
    "autoapi.extension",
    "sphinx_autodoc_typehints",
    "sphinx_copybutton",
]

exclude_patterns: list[str] = [
    "_build",
    "Thumbs.db",
    ".DS_Store",
    "**/.pytest_cache",
    "**/__pycache__",
]

# -- HTML output -------------------------------------------------------------
html_theme = "furo"
html_title = "cb-events"
html_show_sourcelink = True
html_copy_source = False
html_last_updated_fmt = "%b %d, %Y"

html_theme_options: dict[str, str | dict[str, str]] = {
    "source_repository": "https://github.com/MountainGod2/cb-events",
    "source_branch": "main",
    "source_directory": "docs/",
    "light_css_variables": {
        "color-brand-primary": "#7C4DFF",
        "color-brand-content": "#7C4DFF",
    },
    "dark_css_variables": {
        "color-brand-primary": "#B388FF",
        "color-brand-content": "#B388FF",
    },
    "sidebar_hide_name": False,
    "navigation_with_keys": True,
}

html_static_path: list[str] = ["_static"]
html_css_files: list[str] = ["custom.css"]

# -- Napoleon configuration --------------------------------------------------
napoleon_google_docstring = True
napoleon_numpy_docstring = False
napoleon_include_special_with_doc = False
napoleon_use_param = True
napoleon_use_rtype = True
napoleon_attr_annotations = True
napoleon_preprocess_types = True

# -- AutoAPI configuration ---------------------------------------------------
autoapi_dirs: list[str] = [str(SRC_DIR / "cb_events")]
autoapi_type = "python"
autoapi_root = "api"
autoapi_member_order = "groupwise"
autoapi_python_class_content = "class"
autoapi_add_toctree_entry = False
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

# -- Intersphinx configuration -----------------------------------------------
intersphinx_mapping: dict[str, tuple[str, None]] = {
    "python": ("https://docs.python.org/3", None),
    "pydantic": ("https://docs.pydantic.dev/latest/", None),
    "aiohttp": ("https://docs.aiohttp.org/en/stable/", None),
}

# -- Type hints configuration ------------------------------------------------
typehints_fully_qualified = False
typehints_document_rtype = True
always_document_param_types = True
typehints_use_signature = True
typehints_use_signature_return = True

# -- Copy button configuration -----------------------------------------------
copybutton_prompt_text = r">>> |\.\.\. |\$ "
copybutton_prompt_is_regexp = True
copybutton_only_copy_prompt_lines = False

# -- Nitpicky mode -----------------------------------------------------------
nitpicky = True
nitpick_ignore: list[tuple[str, str]] = [
    ("py:class", "aiolimiter.AsyncLimiter"),
    ("py:class", "Event"),
    ("py:class", "HandlerFunc"),
    ("py:class", "Ellipsis"),
    ("py:obj", "BaseEventModel"),
]

suppress_warnings: list[str] = [
    "autoapi.duplicate_object",
    "ref.python",
    "ref.obj",
]
