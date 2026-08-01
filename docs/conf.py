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
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sphinx.application import Sphinx

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
    # Synchronised tab sets: every API example is shown in both synchronous and
    # asynchronous form, and picking one switches every example on the page.
    "sphinx_design",
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
# Single backticks mean "literal", not "cross-reference". The library's
# docstrings use them loosely for prose and shell fragments (`snmpget`,
# `apt-get install -y snmp`, `type: ignore`), which a py:obj default role turns
# into a flood of unresolvable references under nitpicky mode. Cross-references
# in this documentation are always written with an explicit role, so nothing is
# lost -- and filelinks still turns any literal naming a repository file into a
# link to that file.
default_role = "literal"

# Every cross-reference must resolve, or the build fails. This is what keeps the
# documentation actually hyperlinked: an unresolved `py:obj` renders as plain
# text, so without this a whole page of API names can silently stop being links
# -- which is exactly what happened when references were written as
# `netgear_switch.SyncSwitch` (autodoc documents the class under its DEFINING
# module, netgear_switch.sync_api, so the short path never resolved).
nitpicky = True
nitpick_ignore = [
    # Base classes autodoc emits for our enums. They resolve through
    # intersphinx, so these only matter for an offline build.
    ("py:class", "enum.Enum"),
    ("py:class", "enum.IntEnum"),
]

# Napoleon splits a docstring "Returns:"/"Attributes:" type on its first comma,
# so a generic like ``tuple[NsdpPortStatus, ...]`` arrives as the fragment
# ``'tuple[NsdpPortStatus``. These are mis-parses of a real annotation, not
# broken links; the signatures autodoc renders from the actual type hints are
# correct. Ignored by shape so a genuinely missing class still fails the build.
nitpick_ignore_regex = [
    ("py:class", r"^'?(?:tuple|list|dict|Mapping|Sequence|frozenset)\[.*"),
    # A prose Attributes: entry whose type slot holds a sentence.
    ("py:class", r"^The [A-Z].*"),
]

if os.environ.get("NGSW_DOCS_OFFLINE"):
    # Standard-library targets that only resolve when intersphinx can fetch its
    # inventory. Online (CI and Read the Docs) they link properly and stay
    # strict; offline they would be noise.
    nitpick_ignore += [
        ("py:class", "argparse.ArgumentParser"),
        ("py:func", "asyncio.to_thread"),
        ("py:func", "importlib.import_module"),
    ]
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
    # Shown at the top of EVERY page. This library and this documentation were
    # written by an AI; a reader deserves to know that before they trust a
    # sentence of it, not only if they happen to land on the front page.
    "announcement": (
        "This library and its documentation were written by an AI. "
        '<a href="/en/latest/#ai-generated">What that means, and what was '
        "actually verified against hardware</a>."
    ),
}

copybutton_prompt_text = r"\$ |>>> |\.\.\. "
copybutton_prompt_is_regexp = True


# -- Build tweaks -------------------------------------------------------------


def _force_serial_build(app: Sphinx) -> None:
    """Read and write documents serially, whatever ``-j`` was passed.

    Read the Docs always invokes Sphinx with ``-j auto``, and a parallel READ
    requires every registered domain to implement ``merge_domaindata`` so the
    workers' results can be combined. ``sphinx-argparse`` registers an
    ``ArgParseDomain`` that does not, so a parallel build dies with::

        NotImplementedError: merge_domaindata must be implemented in
        <class 'sphinxarg.ext.ArgParseDomain'> to be able to do parallel builds!

    Forcing ``parallel`` back to 1 here is a deliberate trade of build time for
    a working build; it is the only knob available, since Read the Docs does not
    expose the ``-j`` flag in ``.readthedocs.yaml``. Serial is ~5 minutes for
    this project, well inside any build timeout. Remove this once
    sphinx-argparse implements ``merge_domaindata``.

    This is why the CI documentation job passes ``-j auto`` too (see
    ``.github/workflows/ci.yml``): the gate must run the command Read the Docs
    runs, or a failure like this one reaches production with CI still green.
    """
    app.parallel = 1


def setup(app: Sphinx) -> None:
    app.connect("builder-inited", _force_serial_build)
