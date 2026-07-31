"""Sphinx extension: every reference to a repository file becomes a link to it.

Two mechanisms, one guarantee.

**Automatic.** A post-transform walks every inline literal in the built
doctree -- prose written here *and* docstrings pulled in by autodoc -- and, when
the text resolves to a file that exists in this repository, wraps it in a link
to that file on the code host. Writing ``` ``src/netgear_switch/registry.py`` ```
is therefore enough; there is no separate markup to remember and no way for a
docstring's file mention to stay unlinked.

Paths are resolved repository-root-first, then relative to
``src/netgear_switch/`` and ``src/``. That second lookup matters: docstrings
throughout the library refer to their neighbours the way a reader of the package
would (``protocols/http/endpoints.py``), and those references link correctly
without touching a single docstring.

**Checked.** A literal that *looks* like a repository path -- it starts with a
top-level directory of this project, or names a file at the root -- but does not
exist is reported as a warning. With ``-W`` (and ``fail_on_warning`` on Read the
Docs, see ``.readthedocs.yaml``) that fails the build, so documentation cannot
keep pointing at a file that has been renamed or deleted.

Text that merely resembles a path is deliberately left alone rather than
warned about: the switch web-UI endpoints these docs quote
(``/iss/specific/port_settings.html``, ``vlan_port_cfg.html``) are URLs on a
device, not files here. They are linked if a file happens to match and are
silent otherwise. Use the explicit ``:repofile:`` role where you want the
stricter behaviour: it always warns when its target is missing.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from docutils import nodes
from sphinx.transforms.post_transforms import SphinxPostTransform
from sphinx.util import logging

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

    from docutils.parsers.rst.states import Inliner
    from sphinx.application import Sphinx

logger = logging.getLogger(__name__)

#: Top-level directories that unambiguously identify a path in THIS repository.
#: A literal starting with one of these is expected to exist; anything else is
#: linked opportunistically and never warned about.
_REPO_PREFIXES = (
    "src/",
    "tests/",
    "docs/",
    "debian/",
    "packaging/",
    ".github/",
)

#: Root-level files referred to by bare name.
_ROOT_FILES = frozenset(
    {
        "pyproject.toml",
        "README.md",
        "CLAUDE.md",
        "LICENSE",
        "RELEASING.md",
        "uv.lock",
        ".readthedocs.yaml",
        ".gitignore",
    }
)

#: A path-shaped literal: no whitespace, and at most a trailing ``:123`` line
#: number. Glob metacharacters are allowed because docstrings routinely name a
#: *set* of fixtures (``tests/fixtures/http/{a,b}_*.html``); those resolve to
#: the directory holding them.
_PATH_RE = re.compile(r"^(?P<path>[A-Za-z0-9_.\-/*?\[\]{},]+)(?::(?P<line>\d+))?$")

#: Characters that make a reference a pattern rather than one file.
_GLOB_CHARS = frozenset("*?[]{},")


class FileRef:
    """A resolved reference to a file or directory in the repository."""

    def __init__(self, relpath: str, *, is_dir: bool, line: int | None) -> None:
        self.relpath = relpath
        self.is_dir = is_dir
        self.line = line

    def url(self, repo_url: str, ref: str) -> str:
        kind = "tree" if self.is_dir else "blob"
        url = f"{repo_url.rstrip('/')}/{kind}/{ref}/{self.relpath}"
        return f"{url}#L{self.line}" if self.line and not self.is_dir else url


def _candidates(path: str) -> Iterator[str]:
    """Repository-relative paths ``path`` might mean, most specific first."""
    yield path
    # Docstrings inside the package name their neighbours package-relatively.
    yield f"src/netgear_switch/{path}"
    yield f"src/{path}"


def _looks_like_repo_path(path: str) -> bool:
    return path.startswith(_REPO_PREFIXES) or path in _ROOT_FILES


def normalise(text: str) -> str:
    """Undo the line wrapping a docstring may have applied inside a literal.

    A path long enough to wrap arrives with an embedded newline and the next
    line's indentation. Both belong to the source layout, not to the path.
    """
    return re.sub(r"\s*\n\s*", "", text)


def _deepest_existing_dir(pattern: str, root: Path) -> str | None:
    """The deepest existing directory along ``pattern``'s path.

    A glob names a *set* of files, and the closest thing a link can point at is
    the directory holding them. Walking up rather than taking the immediate
    parent means a pattern with a brace expansion in a middle component still
    resolves to something useful.
    """
    for candidate in _candidates(pattern):
        parts = Path(candidate).parts
        for depth in range(len(parts) - 1, 0, -1):
            prefix = "/".join(parts[:depth])
            if not _GLOB_CHARS.isdisjoint(prefix):
                continue
            if (root / prefix).is_dir():
                return prefix
    return None


def resolve(text: str, root: Path) -> FileRef | None:
    """Resolve literal ``text`` to a repository file or directory, or ``None``.

    Handles an optional trailing ``:LINE``, pytest node ids
    (``tests/test_x.py::test_case``), directory references with or without a
    trailing slash, and glob or brace patterns naming a set of fixtures, which
    resolve to the directory holding them.
    """
    text = normalise(text)
    # A pytest node id names a file plus a test within it; link the file.
    text = text.split("::", 1)[0]
    match = _PATH_RE.match(text)
    if match is None:
        return None
    raw = match["path"]
    line = int(match["line"]) if match["line"] else None
    if raw in {".", "..", "/"} or raw.startswith("/"):
        return None
    # A bare word with no separator and no extension is not a path.
    if "/" not in raw and "." not in raw:
        return None

    trailing_slash = raw.endswith("/")
    candidate_text = raw.rstrip("/")
    if not _GLOB_CHARS.isdisjoint(candidate_text):
        directory = _deepest_existing_dir(candidate_text, root)
        return None if directory is None else FileRef(directory, is_dir=True, line=None)

    for candidate in _candidates(candidate_text):
        target = root / candidate
        if target.is_dir():
            return FileRef(candidate, is_dir=True, line=None)
        if target.is_file() and not trailing_slash:
            return FileRef(candidate, is_dir=False, line=line)
    return None


def _repo_root(srcdir: str | Path) -> Path:
    """The repository root: the parent of the ``docs/`` source directory."""
    return Path(srcdir).parent


def _make_link(text: str, ref: FileRef, repo_url: str, git_ref: str) -> nodes.reference:
    link = nodes.reference("", "", internal=False, refuri=ref.url(repo_url, git_ref))
    link["classes"].append("repofile")
    link += nodes.literal(text, text)
    return link


class FileLinkPostTransform(SphinxPostTransform):
    """Link inline literals that name a file in this repository."""

    # After reference resolution (priority 10-100 there), so an already-resolved
    # cross-reference is a `reference` node by now and is skipped rather than
    # double-linked.
    default_priority = 400

    def run(self, **kwargs: Any) -> None:
        config = self.env.config
        if not config.filelinks_repo_url:
            return
        root = _repo_root(self.env.srcdir)
        counts = self.env.domaindata.setdefault("filelinks", {"linked": 0})

        for node in list(self.document.findall(nodes.literal)):
            if isinstance(node.parent, nodes.reference):
                continue  # already inside a link (a resolved xref, or ours)
            if "xref" in node["classes"]:
                continue  # an unresolved cross-reference, not a file mention
            text = node.astext()
            ref = resolve(text, root)
            if ref is None:
                candidate = normalise(text).split("::", 1)[0].split(":")[0].rstrip("/")
                # Warn only for an unambiguous, non-pattern reference into this
                # repository: those are the ones a rename or deletion breaks,
                # and the ones the build should refuse to ship stale.
                if _looks_like_repo_path(candidate) and _GLOB_CHARS.isdisjoint(
                    candidate
                ):
                    logger.warning(
                        "documentation references %r, which does not exist in "
                        "the repository",
                        candidate,
                        location=node,
                        type="filelinks",
                        subtype="missing",
                    )
                continue
            node.replace_self(
                _make_link(text, ref, config.filelinks_repo_url, config.filelinks_ref)
            )
            counts["linked"] += 1


def repofile_role(
    name: str,
    rawtext: str,
    text: str,
    lineno: int,
    inliner: Inliner,
    options: dict[str, Any] | None = None,
    content: Sequence[str] = (),
) -> tuple[list[nodes.Node], list[nodes.system_message]]:
    """``:repofile:`path``` -- link a repository file, erroring if it is absent.

    The strict counterpart to the automatic literal linking: use it when a
    reference must be guaranteed to resolve, whatever the text looks like.
    """
    env = inliner.document.settings.env
    root = _repo_root(env.srcdir)
    ref = resolve(text, root)
    if ref is None:
        msg = inliner.reporter.error(
            f"repofile: {text!r} does not exist in the repository", line=lineno
        )
        return [nodes.literal(rawtext, text)], [msg]
    env.domaindata.setdefault("filelinks", {"linked": 0})["linked"] += 1
    return [
        _make_link(text, ref, env.config.filelinks_repo_url, env.config.filelinks_ref)
    ], []


def _report(app: Sphinx, exception: Exception | None) -> None:
    if exception is not None:
        return
    linked = app.env.domaindata.get("filelinks", {}).get("linked", 0)
    logger.info("filelinks: linked %d file reference(s) to the repository", linked)


def setup(app: Sphinx) -> dict[str, Any]:
    app.add_config_value("filelinks_repo_url", "", "env", types=frozenset({str}))
    app.add_config_value("filelinks_ref", "main", "env", types=frozenset({str}))
    app.add_post_transform(FileLinkPostTransform)
    app.add_role("repofile", repofile_role)
    app.connect("build-finished", _report)
    return {"version": "1.0", "parallel_read_safe": True, "parallel_write_safe": True}
