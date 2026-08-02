# tests/test_docs_coverage.py
"""The documentation must cover the whole package, and keep covering it.

These gates are deliberately cheap: they read the reST sources rather than a
built HTML tree, so they run in the normal suite and catch the realistic
regression -- a module added to the package and never added to the docs.

The stronger check (every public class, function and method actually rendered)
is enforced by the docs build itself: ``autodoc_default_options`` in
``docs/conf.py`` sets ``members`` and ``undoc-members``, so once a module is
autodoc'd, everything public in it is documented whether or not it has a
docstring. That only holds where members are not suppressed, which is why
``:no-members:`` is checked here too.
"""

from __future__ import annotations

import importlib
import inspect
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
PACKAGE = REPO / "src" / "netgear_switch"
DOCS = REPO / "docs"

#: Generated at build time by hatch-vcs; it holds only the version string and
#: does not exist in a fresh checkout, so there is nothing to document.
EXCLUDED = {"netgear_switch._version"}


def _package_modules() -> set[str]:
    modules = set()
    for path in PACKAGE.rglob("*.py"):
        parts = list(path.relative_to(PACKAGE.parent).with_suffix("").parts)
        if parts[-1] == "__init__":
            parts.pop()
        modules.add(".".join(parts))
    return modules - EXCLUDED


def _automodule_directives() -> dict[str, str]:
    """Module name -> the options block of its ``automodule`` directive."""
    found: dict[str, str] = {}
    for rst in DOCS.rglob("*.rst"):
        text = rst.read_text()
        for match in re.finditer(
            r"^\.\. automodule:: (\S+)\n((?:   :.*\n)*)", text, re.MULTILINE
        ):
            found[match.group(1)] = match.group(2)
    return found


def test_every_module_is_documented():
    undocumented = _package_modules() - set(_automodule_directives())
    assert not undocumented, (
        "these modules exist in the package but no documentation page "
        f"autodocs them: {sorted(undocumented)}"
    )


def test_no_documentation_page_names_a_module_that_is_gone():
    stale = {
        name for name in _automodule_directives() if name.startswith("netgear_switch")
    } - _package_modules()
    assert not stale, f"documentation autodocs modules that no longer exist: {stale}"


@pytest.mark.parametrize(
    "module",
    sorted(
        name
        for name, options in _automodule_directives().items()
        if ":no-members:" in options
    ),
)
def test_no_members_only_hides_re_exports(module: str):
    """``:no-members:`` must only ever be used on a pure re-export module.

    Suppressing members is correct for a package ``__init__`` whose names are
    documented where they are defined, and silently lossy anywhere else: the
    objects simply never appear in the documentation, and nothing warns.
    """
    imported = importlib.import_module(module)
    own = [
        attr
        for attr, obj in vars(imported).items()
        if not attr.startswith("_")
        and not inspect.ismodule(obj)
        and getattr(obj, "__module__", None) == module
    ]
    assert not own, (
        f"{module} is documented with :no-members:, which hides the objects it "
        f"defines itself: {sorted(own)}"
    )
