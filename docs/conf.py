"""Sphinx configuration for the python-netgear-switch-library documentation.

Built on Read the Docs from ``.readthedocs.yaml``; buildable locally with::

    make -C docs html

The build is warning-free by policy and Read the Docs runs it with
``fail_on_warning``. A broken cross-reference, a missing document or a
documented file path that no longer exists therefore breaks the build instead
of shipping a page that quietly misleads.
"""

from __future__ import annotations

import os
import sys
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as pkg_version
from pathlib import Path

DOCS_DIR = Path(__file__).parent
REPO_ROOT = DOCS_DIR.parent

# Local extensions (docs/_ext/) and, for a bare checkout with no install, the
# package itself. Read the Docs installs the project properly (see
# .readthedocs.yaml), so the src/ entry is only a convenience for local builds.
sys.path.insert(0, str(DOCS_DIR / "_ext"))
sys.path.insert(0, str(REPO_ROOT / "src"))

# -- Project ------------------------------------------------------------------

project = "python-netgear-switch-library"
author = "Tim Ansell"
copyright = f"{datetime.now(tz=UTC):%Y}, {author}"

try:
    release = pkg_version("python-netgear-switch-library")
except PackageNotFoundError:  # pragma: no cover - uninstalled source checkout
    release = "0.0.dev0+unknown"
version = release

# -- General ------------------------------------------------------------------

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinx.ext.intersphinx",
    "sphinx.ext.extlinks",
    "sphinx_copybutton",
    "sphinxarg.ext",
    # Local: see docs/_ext/.
    "filelinks",
    "support_tables",
]

templates_path = ["_templates"]
exclude_patterns = [
    "_build",
    # Design specs and implementation plans live under docs/ but are working
    # documents, not published pages. They are still linked from the docs by
    # path, which docs/_ext/filelinks.py turns into links to the files.
    "superpowers/**",
    "README.md",
]

# Single backticks mean "a Python object", which is what most inline references
# in this project are.
default_role = "py:obj"
nitpicky = False
maximum_signature_line_length = 88

# -- Autodoc ------------------------------------------------------------------

autodoc_default_options = {
    "members": True,
    "undoc-members": True,
    "show-inheritance": True,
    "member-order": "bysource",
}
autodoc_typehints = "description"
autodoc_typehints_description_target = "documented_params"
autodoc_class_signature = "mixed"
autodoc_preserve_defaults = True
autosummary_generate = True
napoleon_google_docstring = True
napoleon_numpy_docstring = False
# Render a docstring's ``Attributes:`` section as :ivar: fields inside the class
# body. Without this, napoleon emits a separate attribute directive for each
# entry, which collides with the one autodoc already emits for the dataclass
# field of the same name (a "duplicate object description" warning, and two
# entries in the index for one attribute).
napoleon_use_ivar = True

# Mock nothing: the docs extra installs every optional dependency precisely so
# that autodoc imports the real modules. A mocked import produces a page that
# looks complete while documenting a stub.
autodoc_mock_imports: list[str] = []

# -- Cross-project links ------------------------------------------------------

# Fetching inventories needs network access. Local builds in an offline sandbox
# set NGSW_DOCS_OFFLINE=1 to skip them; Read the Docs always has network, so the
# published build gets the full links.
if os.environ.get("NGSW_DOCS_OFFLINE"):
    intersphinx_mapping: dict[str, tuple[str, None]] = {}
else:
    intersphinx_mapping = {"python": ("https://docs.python.org/3", None)}

GITHUB_REPO = "https://github.com/mithro/python-netgear-switch-library"

extlinks = {
    "issue": (f"{GITHUB_REPO}/issues/%s", "issue #%s"),
    "pypi": ("https://pypi.org/project/%s/", "%s"),
}

# docs/_ext/filelinks.py: any inline literal naming a file in this repository
# becomes a link to that file.
filelinks_repo_url = GITHUB_REPO
filelinks_ref = os.environ.get("NGSW_DOCS_GIT_REF", "main")

# -- HTML ---------------------------------------------------------------------

html_theme = "furo"
html_title = f"{project} {release}"
html_static_path = ["_static"]
html_css_files = ["ngsw.css"]
html_theme_options = {
    "source_repository": f"{GITHUB_REPO}/",
    "source_branch": filelinks_ref,
    "source_directory": "docs/",
}

copybutton_prompt_text = r"\$ |>>> |\.\.\. "
copybutton_prompt_is_regexp = True
