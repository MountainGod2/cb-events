"""Documentation configuration file for Sphinx."""  # noqa: INP001

from cb_events import __version__

# Project configuration
project = "cb_events"
project_copyright = "2025, MountainGod2"
author = "MountainGod2"
version: str = __version__
release: str = __version__

# Sphinx extensions
extensions: list[str] = [
    "myst_nb",
    "autoapi.extension",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinx.ext.intersphinx",
    "sphinx.ext.coverage",
    "sphinx.ext.doctest",
    "sphinx.ext.todo",
    "sphinx.ext.githubpages",
    "sphinx_autodoc_typehints",
]

# Build exclusions
exclude_patterns: list[str] = [
    "_build",
    "Thumbs.db",
    ".DS_Store",
    "examples/",
    "tutorials/",
    "**/.pytest_cache",
    "**/__pycache__",
]

# HTML output configuration
html_theme = "furo"
html_title = "CB Events API Client Library"
html_show_sourcelink = False
html_copy_source = False

html_theme_options = {
    "source_repository": "https://github.com/MountainGod2/chaturbate-events/",
    "source_branch": "main",
    "source_directory": "docs/",
    "navigation_with_keys": True,
    "top_of_page_button": "edit",
    "announcement": None,
}

# Napoleon extension configuration
napoleon_google_docstring = True
napoleon_numpy_docstring = False
napoleon_include_init_with_doc = False
napoleon_include_private_with_doc = False
napoleon_include_special_with_doc = True
napoleon_use_admonition_for_examples = False
napoleon_use_admonition_for_notes = False
napoleon_use_admonition_for_references = False
napoleon_use_ivar = False
napoleon_use_param = True
napoleon_use_rtype = True
napoleon_preprocess_types = False
napoleon_type_aliases = None
napoleon_attr_annotations = True

# AutoAPI configuration
autoapi_dirs: list[str] = ["../src"]
autoapi_type = "python"
autoapi_template_dir = "_templates/autoapi"
autoapi_options = [
    "members",
    "undoc-members",
    "show-inheritance",
    "show-module-summary",
    "special-members",
]
autoapi_python_class_content = "both"
autoapi_member_order = "groupwise"
autoapi_root = "api"
autoapi_keep_files = True
autoapi_ignore = ["*/tests/*", "*/test_*"]
autoapi_generate_api_docs = True

# Intersphinx configuration
intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "pydantic": ("https://docs.pydantic.dev/latest/", None),
    "aiohttp": ("https://docs.aiohttp.org/en/stable/", None),
}

# MyST-NB configuration
nb_execution_timeout = 60
nb_execution_allow_errors = False

# Type hints configuration
typehints_fully_qualified = False
always_document_param_types = True

# Suppress warnings
suppress_warnings = [
    "autoapi.python_import_resolution",
    "ref.python",
    "autoapi.not_readable",
    "app.add_node",
    "app.add_directive",
    "app.add_role",
]

typehints_document_rtype = True
typehints_use_rtype = True

# Coverage extension configuration
coverage_show_missing_items = True

# sphinx.ext.todo configuration
todo_include_todos = True

# Link check configuration
linkcheck_ignore: list[str] = [
    "https://chaturbate.com/statsapi/authtoken/",
    r"https://github\.com/.*",
    r"http://localhost:\d+",
    r"file://.*",
]
