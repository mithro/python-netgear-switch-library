# tests/test_deb_version.py
"""``packaging/deb-version.py`` derives a Debian version from git.

This is a standalone stdlib+git script (it must run in a bare Debian build
container with no third-party packages installed), so these tests drive it
via ``subprocess`` under plain ``python3`` rather than importing it -- that
also proves it truly needs nothing beyond the standard library.

The version changes every time this repo gets a commit or a tag, so nothing
here hard-codes today's value; each assertion recomputes the expected value
from ``git`` at test time. The live-repo check deliberately uses DIFFERENT git
commands from the script (``describe --abbrev=0`` + ``rev-list --count
TAG..HEAD`` versus the script's ``describe --long`` regex) so the two can
disagree if either is wrong. The tagless fallback (``0.0.post<count>``) is
exercised in a throwaway repo: the live repo has been tagged since v0.0/v0.1
on 2026-08-22, so it no longer takes that path.
"""

from __future__ import annotations

import ast
import os
import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "packaging" / "deb-version.py"
CHANGELOG = REPO / "debian" / "changelog"

_DEBIAN_VERSION_RE = re.compile(r"^\d+(\.\d+)*(\.post\d+)?$")


def _run(*args: str) -> str:
    return subprocess.run(
        ["python3", str(SCRIPT), *args],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def _git(*args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(REPO), *args],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def _run_in_repo(
    repo: Path,
    *args: str,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Invoke the script with ``DEB_VERSION_REPO`` pointed at a temp repo.

    ``deb-version.py`` normally derives its own repo location from
    ``__file__``, but honours the ``DEB_VERSION_REPO`` env var override so it
    can be pointed at a throwaway git repo for these tests without touching
    the real project checkout.
    """
    env = os.environ.copy()
    env["DEB_VERSION_REPO"] = str(repo)
    return subprocess.run(
        ["python3", str(SCRIPT), *args],
        capture_output=True,
        text=True,
        check=check,
        env=env,
    )


def _init_repo(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    subprocess.run(
        ["git", "-C", str(path), "config", "user.email", "test@example.invalid"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(path), "config", "user.name", "Test User"],
        check=True,
    )


def _commit(path: Path, message: str) -> None:
    subprocess.run(
        ["git", "-C", str(path), "commit", "-q", "--allow-empty", "-m", message],
        check=True,
    )


def test_script_is_executable_and_has_correct_shebang():
    assert SCRIPT.stat().st_mode & 0o111, "packaging/deb-version.py must be executable"
    first_line = SCRIPT.read_text().splitlines()[0]
    assert first_line == "#!/usr/bin/env python3"


def test_only_stdlib_imports():
    """Must run in a bare Debian container before any deps are installed."""
    stdlib_allow = {
        "argparse",
        "os",
        "re",
        "subprocess",
        "sys",
        "pathlib",
        "__future__",
    }
    tree = ast.parse(SCRIPT.read_text())
    seen = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            seen.update(n.name.split(".")[0] for n in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            seen.add(node.module.split(".")[0])
    assert seen <= stdlib_allow, f"non-stdlib imports found: {seen - stdlib_allow}"


def test_live_repo_version_matches_git_describe():
    """The real checkout: X.Y at the nearest vX.Y tag, X.Y.postN N commits on.

    Expected value is derived independently of the script: the nearest tag via
    ``describe --abbrev=0`` and the distance via ``rev-list --count TAG..HEAD``
    (the script parses ``describe --long`` instead). This broke on 2026-08-22
    when v0.1 was pushed and the old assertion still expected the tagless
    ``0.0.post<count>`` fallback -- CI went red and, correctly, nothing was
    published for that commit.
    """
    tag = _git("describe", "--tags", "--abbrev=0", "--match", "v[0-9]*")
    assert tag.startswith("v"), tag
    base = tag[1:]
    distance = int(_git("rev-list", "--count", f"{tag}..HEAD"))
    expected = base if distance == 0 else f"{base}.post{distance}"
    assert _run() == expected


def test_commit_count_fallback_in_tagless_repo(tmp_path):
    """With no vX.Y tag at all the version is 0.0.post<commit count>.

    The live repo left this path when it was tagged, so exercise it in a
    throwaway repo: three commits, no tags -> 0.0.post3.
    """
    repo = tmp_path / "tagless-repo"
    _init_repo(repo)
    for i in range(3):
        _commit(repo, f"commit {i}")
    assert _run_in_repo(repo).stdout.strip() == "0.0.post3"


def test_version_is_a_valid_debian_version_string():
    printed = _run()
    assert _DEBIAN_VERSION_RE.match(printed), printed


def test_write_changelog_produces_parseable_debian_changelog(tmp_path):
    changelog_existed = CHANGELOG.exists()
    backup = None
    if changelog_existed:
        backup = tmp_path / "changelog.bak"
        backup.write_bytes(CHANGELOG.read_bytes())
    try:
        subprocess.run(
            ["python3", str(SCRIPT), "--write-changelog"],
            check=True,
        )
        assert CHANGELOG.exists()
        first_line = CHANGELOG.read_text().splitlines()[0]
        expected_version = _run()
        assert first_line == (
            f"python-netgear-switch-library ({expected_version}) "
            "unstable; urgency=medium"
        )
    finally:
        if changelog_existed:
            assert backup is not None
            CHANGELOG.write_bytes(backup.read_bytes())
        else:
            CHANGELOG.unlink(missing_ok=True)
            debian_dir = CHANGELOG.parent
            if debian_dir.exists() and not any(debian_dir.iterdir()):
                debian_dir.rmdir()


def test_version_tag_based_path(tmp_path):
    """vX.Y -> X.Y at the tag; X.Y.postN with N commits after it.

    This is the path the live upstream repo takes since v0.0 (root commit) and
    v0.1 (2026-08-22) were tagged; the live-repo test above checks it against
    the real checkout, this one pins the exact arithmetic on a throwaway
    repo whose tag and distance are fully controlled.
    """
    repo = tmp_path / "tag-repo"
    _init_repo(repo)
    _commit(repo, "initial commit")
    subprocess.run(["git", "-C", str(repo), "tag", "v1.2"], check=True)

    at_tag = _run_in_repo(repo)
    assert at_tag.stdout.strip() == "1.2"

    n = 3
    for i in range(n):
        _commit(repo, f"commit {i} after tag")

    after_tag = _run_in_repo(repo)
    assert after_tag.stdout.strip() == f"1.2.post{n}"


def test_shallow_clone_fails_loudly_instead_of_wrong_version(tmp_path):
    """A shallow clone must FAIL, not silently emit a truncated 0.0.post1.

    Regression test for the bug where ``git rev-list --count HEAD`` returns 1
    in a ``--depth 1`` clone, producing a badly wrong version that looks like
    a downgrade from previously published releases.
    """
    origin = tmp_path / "origin"
    _init_repo(origin)
    for i in range(5):
        _commit(origin, f"commit {i}")

    shallow = tmp_path / "shallow-clone"
    subprocess.run(
        # file:// forces a real shallow clone; git silently ignores --depth
        # for plain local-path clones ("--depth is ignored in local clones").
        ["git", "clone", "-q", "--depth", "1", f"file://{origin}", str(shallow)],
        check=True,
    )

    result = _run_in_repo(shallow, check=False)

    assert result.returncode != 0, (
        f"expected non-zero exit on a shallow clone, got stdout={result.stdout!r}"
    )
    assert "0.0.post1" not in result.stdout
    assert "shallow" in result.stderr.lower()
