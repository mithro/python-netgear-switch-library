# Slice 8: Packaging, CI & Rolling Release Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn `python-netgear-switch-library` into a rolling-release project where every mergeable push to `main` derives a fresh version from git and automatically publishes a PyPI wheel/sdist and Debian packages (trixie + sid) to a signed GitHub Pages apt repository, with CI enforcing the exact same ruff/mypy/coverage gates that run locally.

**Architecture:** Two parallel version-derivation paths that agree because both read git: (1) the Python build uses `hatch-vcs` (post-release scheme, no local version) so `uv build` produces a monotonic wheel version; (2) the Debian build uses a standalone `packaging/deb-version.py` script (git-describe → `X.Y.postN`, fallback `0.0.post<commit-count>`) that regenerates `debian/changelog` at build time, and `debian/rules` feeds that version back into the Python metadata via `SETUPTOOLS_SCM_PRETEND_VERSION`. GitHub Actions workflows (CI, PyPI publish, deb+apt) mirror the established mithro pattern from `sensors2mqtt` and `ten64-microcontroller-utility`. No git tags are ever created; the commit height is the version.

**Tech Stack:** Python ≥3.11, uv, hatchling + hatch-vcs, GitHub Actions, PyPI trusted publishing (OIDC), Debian dh-python/pybuild (`debhelper-compat 13`), `dpkg-buildpackage` inside `debian:trixie`/`debian:sid` docker containers, `dpkg-scanpackages` + `apt-ftparchive` + GPG for the apt repo, GitHub Pages.

## Global Constraints

- Python ≥3.11.
- Distribution name `python-netgear-switch-library`; import package `netgear_switch`; CLI `ngsw`.
- License Apache-2.0.
- uv-based workflow.
- DERIVED rolling version — no manual version bump, NO git tags, "mergeable ⇒ released".
- Strict ruff + `mypy --strict` + coverage ≥ 90 enforced identically LOCAL and in CI.
- CI installs the `snmp` (net-snmp CLI) system package.
- net-snmp CLI is a documented runtime system-dependency for the sync transport.
- Debian packages for trixie AND sid, published to a GitHub Pages apt repo like the other mithro repos.
- PyPI publish via trusted-publishing/OIDC, ready for final credential setup.
- Proper `--no-ff` merge commits.
- Every push to main produces new packages.
- Never `git add -A` (overlay char-device dotfiles must never be staged); stage explicit paths only.
- No flaky CI.
- Secrets/keys are a documented final human setup step, never committed.
- Everything must work on the local arm64 system AND in GitHub CI.

---

## File Structure

Files created or modified by this slice:

- `pyproject.toml` (modify) — switch from hard-coded `version = "0.1.0"` to `dynamic = ["version"]` via hatch-vcs; add version-file build hook; exclude the generated `_version.py` from ruff/mypy.
- `.gitignore` (modify) — ignore the hatch-vcs-generated `src/netgear_switch/_version.py` and Debian build byproducts.
- `packaging/deb-version.py` (create) — standalone git→Debian-version derivation + `debian/changelog` regeneration. Only depends on `git`.
- `packaging/ci-build.sh` (create) — builds the `.deb` inside a Debian container; invoked by CI and locally reproducible.
- `packaging/apt-index.html` (create) — landing page + `sources.list` snippet served at the apt repo root.
- `debian/control` (create) — source `python-netgear-switch-library`, binary `python3-netgear-switch-library` (ships the library + `ngsw`, Depends `snmp`).
- `debian/rules` (create) — dh-python/pybuild, tests skipped (they run in the CI test job), version pinned from the changelog.
- `debian/changelog` (create) — placeholder; regenerated at build time by `deb-version.py`.
- `debian/copyright` (create) — Apache-2.0 machine-readable copyright.
- `debian/source/format` (create) — `3.0 (native)`.
- `.github/workflows/ci.yml` (create) — push/PR test+lint+type matrix (3.11/3.12/3.13), installs `snmp`.
- `.github/workflows/publish-pypi.yml` (create) — build sdist+wheel, publish to PyPI via OIDC (gated on final setup).
- `.github/workflows/deb.yml` (create) — build `.deb` for trixie AND sid, publish a signed flat apt repo to GitHub Pages.
- `README.md` (modify) — add an Installation section (pip + apt).
- `RELEASING.md` (create) — the one-time human setup steps (PyPI trusted-publisher config, apt GPG signing key).

Task ordering: derived-version → Debian-version script → CI (test/lint/type) → PyPI publish → Debian packaging → deb build/apt-repo workflow → docs.

---

### Task 1: Rolling derived version via hatch-vcs

**Files:**
- Modify: `pyproject.toml:1-14,42-53`
- Modify: `.gitignore`

**Interfaces:**
- Produces: a `dynamic = ["version"]` project whose version is derived from git (`hatch-vcs`, `version_scheme = "post-release"`, `local_scheme = "no-local-version"`). `uv build` emits `python_netgear_switch_library-<git-derived>-py3-none-any.whl`. With no tags and 66 commits the derived version is `0.0.post66`-shaped (monotonic, increments every commit). A generated `src/netgear_switch/_version.py` appears after any build/editable-install and is git-ignored.
- Consumed by: Task 4 (PyPI publish `uv build`), Task 5 (`debian/rules` reuses the same monotonic scheme through `SETUPTOOLS_SCM_PRETEND_VERSION`).

- [ ] **Step 1: Write the failing check (assert the version is no longer hard-coded)**

Create a throwaway verification (do NOT commit this file — it is a manual gate):

```bash
python3 - <<'PY'
import tomllib, pathlib
cfg = tomllib.loads(pathlib.Path("pyproject.toml").read_text())
proj = cfg["project"]
assert "version" not in proj, "hard-coded version must be removed"
assert proj.get("dynamic") == ["version"], "version must be dynamic"
assert cfg["tool"]["hatch"]["version"]["source"] == "vcs"
print("OK")
PY
```

- [ ] **Step 2: Run it to verify it fails**

Run the snippet above against the current `pyproject.toml`.
Expected: `AssertionError: hard-coded version must be removed` (because `version = "0.1.0"` is still present).

- [ ] **Step 3: Rewrite `pyproject.toml`**

Replace the entire contents of `pyproject.toml` with:

```toml
[build-system]
requires = ["hatchling", "hatch-vcs"]
build-backend = "hatchling.build"

[project]
name = "python-netgear-switch-library"
dynamic = ["version"]
description = "Python library and CLI to query and control Netgear switches over SNMP, NSDP and HTTP."
readme = "README.md"
requires-python = ">=3.11"
license = "Apache-2.0"
license-files = ["LICENSE"]
authors = [{ name = "Tim Ansell", email = "me@mith.ro" }]
dependencies = []

[project.optional-dependencies]
# The sync SNMP transport shells out to the net-snmp CLI tools (snmpget/
# snmpbulkwalk/snmpset), which are a system package (apt install snmp), not a
# Python dependency; ezsnmp fails to build on arm64 and is intentionally not
# used.
sync = []
async = ["pysnmp>=7.0"]
http = ["httpx>=0.27"]
testing = ["pysnmp>=7.0"]

[project.scripts]
ngsw = "netgear_switch.cli.main:main"

[dependency-groups]
dev = ["pytest>=8.0", "ruff>=0.6", "mypy>=1.11", "pytest-cov>=5.0"]

# Rolling release: the version is derived from git, never hand-edited and never
# tagged. Every commit on main increments the commit height, so post-release
# versioning yields a real, monotonic version (0.0.postN with no tag; X.Y.postN
# once a vX.Y tag ever exists). "no-local-version" keeps the version PyPI-upload
# safe. These forms are also valid Debian versions verbatim.
[tool.hatch.version]
source = "vcs"

[tool.hatch.version.raw-options]
version_scheme = "post-release"
local_scheme = "no-local-version"

[tool.hatch.build.hooks.vcs]
version-file = "src/netgear_switch/_version.py"

[tool.hatch.build.targets.wheel]
packages = ["src/netgear_switch"]

[tool.hatch.build.targets.wheel.force-include]
"src/netgear_switch/py.typed" = "netgear_switch/py.typed"

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-ra --cov=netgear_switch --cov-report=term-missing --cov-fail-under=90"

[tool.ruff]
target-version = "py311"
src = ["src", "tests"]
extend-exclude = ["src/netgear_switch/_version.py"]

[tool.ruff.lint]
select = ["E", "F", "I", "UP", "B", "SIM", "RUF", "PT", "TC", "C4", "PIE", "RET", "N"]

[tool.mypy]
packages = ["netgear_switch"]
strict = true
python_version = "3.11"

[[tool.mypy.overrides]]
module = "netgear_switch._version"
ignore_errors = true
```

- [ ] **Step 4: Ignore the generated version file and Debian build byproducts**

Append to `.gitignore` (below the existing "Coverage artifacts" block, above the overlay-dotfile block is fine — order does not matter, just do not touch the overlay-dotfile lines):

```gitignore

# hatch-vcs writes this at build/editable-install time; it is derived from git.
/src/netgear_switch/_version.py

# Debian build byproducts (dpkg-buildpackage writes to the parent dir; local
# builds may drop these in-tree).
/built-debs/
*.deb
*.buildinfo
*.changes
/debian/.debhelper/
/debian/files
/debian/python3-netgear-switch-library/
/debian/debhelper-build-stamp
```

Add the edit with Edit (match the last existing gitignore line to anchor), never rewrite the overlay-dotfile section.

- [ ] **Step 5: Verify the version derives and the wheel builds**

Run:

```bash
uv build 2>&1 | tail -5
ls dist/
```

Expected: a wheel and sdist named like `python_netgear_switch_library-0.0.post66-py3-none-any.whl` and `python_netgear_switch_library-0.0.post66.tar.gz` (the number tracks `git rev-list --count HEAD`; it will differ once more commits land). The version MUST start with `0.0.post` and contain no `+g<hash>` local segment.

Then re-run the Step 1 snippet.
Expected: `OK`.

Then confirm the quality-gate tests still pass (they assert the ruff select list, mypy strict, and coverage floor are intact):

```bash
uv run pytest tests/test_quality_gates.py -v
```

Expected: PASS (5 tests).

- [ ] **Step 6: Commit**

```bash
rm -rf dist
git add pyproject.toml .gitignore
git commit -m "build: derive rolling version from git via hatch-vcs"
```

---

### Task 2: Debian version-derivation script

**Files:**
- Create: `packaging/deb-version.py`

**Interfaces:**
- Produces: `packaging/deb-version.py` — a standalone script (only needs `git`). `python3 packaging/deb-version.py` prints the derived Debian version; `python3 packaging/deb-version.py --write-changelog` (over)writes `debian/changelog` for that version. Version logic: `git describe --tags --long --match 'v[0-9]*'` → `vX.Y-N-g…` maps to `X.Y` (N=0) or `X.Y.postN`; with no matching tag it falls back to `0.0.post<git rev-list --count HEAD>`. All outputs are valid Debian versions verbatim and match the hatch-vcs post-release scheme from Task 1.
- Consumed by: Task 5/6 (`debian/rules` + `packaging/ci-build.sh` + `.github/workflows/deb.yml` call `--write-changelog` before `dpkg-buildpackage`).

- [ ] **Step 1: Write the verification (expected value is deterministic here)**

The repo has no tags and 66 commits, so the script must print `0.0.post66`. Write this check to run after creating the script:

```bash
test "$(python3 packaging/deb-version.py)" = "0.0.post$(git rev-list --count HEAD)" && echo "OK"
```

- [ ] **Step 2: Confirm it fails now**

Run: `python3 packaging/deb-version.py`
Expected: `python3: can't open file 'packaging/deb-version.py': No such file or directory`.

- [ ] **Step 3: Create `packaging/deb-version.py`**

```python
#!/usr/bin/env python3
"""Derive the Debian package version from ``git describe``.

At tag ``vX.Y`` the version is ``X.Y``; N commits later ``X.Y.postN``. With no
matching tag (the current upstream state) it falls back to ``0.0.post<commit
count>``. It increments on every commit, so each push publishes a new,
upgradeable package with no manual bump and no tag. All forms are valid Debian
versions verbatim, and match the hatch-vcs ``post-release`` scheme used for the
PyPI wheel, so the .deb and the wheel carry the same version.

Usage:
    python3 packaging/deb-version.py                   # print the version
    python3 packaging/deb-version.py --write-changelog # regenerate debian/changelog
"""
from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CHANGELOG = REPO / "debian" / "changelog"
SOURCE = "python-netgear-switch-library"
MAINTAINER = "Tim 'mithro' Ansell <me@mith.ro>"


def _git(*args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(REPO), *args],
        capture_output=True, text=True, check=True,
    ).stdout.strip()


def version() -> str:
    """git-describe derived version: vX.Y -> X.Y, N commits later -> X.Y.postN."""
    try:
        describe = _git("describe", "--tags", "--long", "--match", "v[0-9]*")
        m = re.match(r"^v(.+)-(\d+)-g[0-9a-f]+$", describe)
        if m:
            base, n = m.group(1), int(m.group(2))
            return base if n == 0 else f"{base}.post{n}"
    except subprocess.CalledProcessError:
        pass
    # No matching tag yet: fall back to a monotonic count-based version.
    try:
        return "0.0.post" + _git("rev-list", "--count", "HEAD")
    except Exception:  # noqa: BLE001
        return "0.0"


def write_changelog() -> None:
    try:
        describe = _git("describe", "--tags", "--always", "--long")
        date = _git("log", "-1", "--format=%cd", "--date=rfc2822")
    except Exception:  # noqa: BLE001
        describe, date = "unknown", "Thu, 01 Jan 1970 00:00:00 +0000"
    CHANGELOG.parent.mkdir(parents=True, exist_ok=True)
    CHANGELOG.write_text(
        f"{SOURCE} ({version()}) unstable; urgency=medium\n\n"
        f"  * Automated build from git ({describe}).\n\n"
        f" -- {MAINTAINER}  {date}\n"
    )


def main() -> None:
    ap = argparse.ArgumentParser(description="Derive the package version from git")
    ap.add_argument("--write-changelog", action="store_true",
                    help="regenerate debian/changelog for the git-derived version")
    args = ap.parse_args()
    if args.write_changelog:
        write_changelog()
    else:
        print(version())


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Make it executable and verify the printed value**

Run:

```bash
chmod +x packaging/deb-version.py
python3 packaging/deb-version.py
```

Expected: `0.0.post66` (equals `0.0.post` + `git rev-list --count HEAD`).

Then run the Step 1 check.
Expected: `OK`.

- [ ] **Step 5: Verify `--write-changelog` produces a parseable changelog**

Run:

```bash
python3 packaging/deb-version.py --write-changelog
head -1 debian/changelog
git checkout -- debian/changelog 2>/dev/null || rm -f debian/changelog
```

Expected first line: `python-netgear-switch-library (0.0.post66) unstable; urgency=medium`.
(The `debian/changelog` created here is discarded — Task 5 commits the placeholder.)

- [ ] **Step 6: Commit**

```bash
git add packaging/deb-version.py
git commit -m "packaging: add git-derived Debian version script"
```

---

### Task 3: CI workflow (test + lint + type, local == CI)

**Files:**
- Create: `.github/workflows/ci.yml`

**Interfaces:**
- Produces: a `CI` workflow that runs on push to `main` and on every PR. Matrix over Python 3.11/3.12/3.13. Installs the `snmp` net-snmp CLI, runs `uv sync --all-extras --dev`, then `uv run ruff check`, `uv run mypy`, and `uv run pytest` (coverage ≥ 90 enforced via the pytest addopts from Task 1). Timeout large enough for the ~10-minute suite.
- Consumed by: branch protection / merge policy (a green CI is the "mergeable" gate that the rolling release depends on).

- [ ] **Step 1: Create `.github/workflows/ci.yml`**

```yaml
name: CI

# Runs the SAME gates as local development (ruff, mypy --strict, pytest with
# coverage >= 90) on every push to main and every pull request. A green run here
# is what "mergeable" means; merging to main triggers the release workflows.
on:
  push:
    branches: [main]
  pull_request:

concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true

jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 25
    strategy:
      fail-fast: false
      matrix:
        python-version: ["3.11", "3.12", "3.13"]
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # full history so hatch-vcs can derive the version

      - name: Install net-snmp CLI (system dependency for the sync transport)
        run: |
          sudo apt-get update
          sudo apt-get install -y --no-install-recommends snmp

      - uses: astral-sh/setup-uv@v6

      - name: Install the matrix Python
        run: uv python install ${{ matrix.python-version }}

      - name: Sync all extras and the dev group
        run: uv sync --all-extras --dev --python ${{ matrix.python-version }}

      - name: Lint (ruff)
        run: uv run ruff check

      - name: Type-check (mypy --strict)
        run: uv run mypy

      - name: Tests + coverage gate (>= 90)
        run: uv run pytest
```

- [ ] **Step 2: Verify the workflow is valid YAML**

Run:

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml')); print('OK')"
```

Expected: `OK`.

- [ ] **Step 3: (Optional but recommended) Lint with actionlint if available**

Run:

```bash
command -v actionlint >/dev/null && actionlint .github/workflows/ci.yml || echo "actionlint not installed; skipping"
```

Expected: `OK`-style output from actionlint, or the skip message. No errors reported if actionlint runs.

- [ ] **Step 4: Sanity-check the gate commands locally (mirror of CI)**

Run the exact commands CI will run, locally on arm64:

```bash
sudo apt-get install -y --no-install-recommends snmp 2>/dev/null || dpkg -s snmp >/dev/null 2>&1 && echo "snmp present"
uv sync --all-extras --dev
uv run ruff check
uv run mypy
uv run pytest
```

Expected: ruff clean, mypy clean, pytest passes with coverage ≥ 90 (the suite takes ~6-10 min). This confirms local == CI.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add test/lint/type workflow (py3.11-3.13, snmp, coverage>=90)"
```

---

### Task 4: PyPI publish workflow (trusted publishing / OIDC)

**Files:**
- Create: `.github/workflows/publish-pypi.yml`

**Interfaces:**
- Consumes: the hatch-vcs dynamic version from Task 1 (each push to main → unique post-release version).
- Produces: a workflow that, on push to `main`, builds sdist+wheel with `uv build` and publishes to PyPI via `pypa/gh-action-pypi-publish` using OIDC trusted publishing (no API token committed). Gated: the job runs, but publishing only succeeds once the PyPI trusted-publisher is configured (documented in Task 9 / `RELEASING.md`). `skip-existing: true` makes re-runs idempotent.

- [ ] **Step 1: Create `.github/workflows/publish-pypi.yml`**

```yaml
name: Publish to PyPI

# Every push to main is a release. The version is derived from git by hatch-vcs
# (see pyproject.toml), so each commit produces a new, unique version -- no tag,
# no manual bump. Publishing uses PyPI Trusted Publishing (OIDC): there is no
# API token in the repo. FINAL HUMAN SETUP STEP: register this repo+workflow as a
# trusted publisher on PyPI and create the `pypi` environment (see RELEASING.md).
# Until that is done the build job still runs and the publish job is a no-op-safe
# gate.
on:
  push:
    branches: [main]
  workflow_dispatch:

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # full history for hatch-vcs version derivation

      - uses: astral-sh/setup-uv@v6

      - name: Build sdist + wheel
        run: uv build

      - name: Show derived version
        run: ls -1 dist/

      - uses: actions/upload-artifact@v4
        with:
          name: dist
          path: dist/

  publish:
    needs: build
    runs-on: ubuntu-latest
    # Trusted Publishing requires an OIDC token and a named environment.
    environment: pypi
    permissions:
      id-token: write
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: dist
          path: dist/

      - name: Publish to PyPI (OIDC trusted publishing)
        uses: pypa/gh-action-pypi-publish@release/v1
        with:
          skip-existing: true
```

- [ ] **Step 2: Verify valid YAML**

Run:

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/publish-pypi.yml')); print('OK')"
```

Expected: `OK`.

- [ ] **Step 3: Verify the build half works locally**

Run:

```bash
uv build && ls dist/ && rm -rf dist
```

Expected: an sdist + wheel named `python_netgear_switch_library-0.0.post66*` are produced (matches Task 1). This is exactly what the `build` job runs.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/publish-pypi.yml
git commit -m "ci: add PyPI publish workflow via OIDC trusted publishing"
```

---

### Task 5: Debian packaging (`debian/`) for a Python library + CLI

**Files:**
- Create: `debian/control`
- Create: `debian/rules`
- Create: `debian/changelog`
- Create: `debian/copyright`
- Create: `debian/source/format`

**Interfaces:**
- Consumes: the version scheme (via `deb-version.py`, Task 2) and the hatchling/hatch-vcs build backend (Task 1).
- Produces: a native Debian source package `python-netgear-switch-library` building one binary `python3-netgear-switch-library` (Architecture: all) that ships the `netgear_switch` module and the `/usr/bin/ngsw` entry point, Depends on `snmp` (net-snmp CLI, needed by the sync transport). Built with dh-python/pybuild; the package's Python metadata version is pinned to the changelog version via `SETUPTOOLS_SCM_PRETEND_VERSION`. Tests are NOT run during the .deb build (they run in the CI test job), keeping the deb build fast and dependency-light.
- Consumed by: Task 6 (`packaging/ci-build.sh`) and Task 7 (`deb.yml`).

- [ ] **Step 1: Create `debian/source/format`**

```
3.0 (native)
```

- [ ] **Step 2: Create `debian/control`**

```
Source: python-netgear-switch-library
Section: python
Priority: optional
Maintainer: Tim 'mithro' Ansell <me@mith.ro>
Build-Depends: debhelper-compat (= 13),
               dh-python,
               pybuild-plugin-pyproject,
               python3-all,
               python3-hatchling,
               python3-hatch-vcs,
               python3-setuptools-scm,
Standards-Version: 4.7.0
Homepage: https://github.com/mithro/netgear-stupid-control
Vcs-Git: https://github.com/mithro/netgear-stupid-control.git
Vcs-Browser: https://github.com/mithro/netgear-stupid-control
Rules-Requires-Root: no

Package: python3-netgear-switch-library
Architecture: all
Depends: ${python3:Depends},
         ${misc:Depends},
         snmp
Recommends: python3-httpx
Suggests: python3-pysnmp
Description: query and control Netgear switches over SNMP, NSDP and HTTP
 Python library (import name netgear_switch) and CLI (ngsw) to query and control
 Netgear managed and Plus switches behind one model-driven API. Managed switches
 are driven over SNMP, Plus switches over NSDP and the HTTP web UI.
 .
 The synchronous SNMP transport shells out to the net-snmp command-line tools
 (snmpget/snmpbulkwalk/snmpset) from the "snmp" package, which is why it is a
 hard runtime dependency. The optional asynchronous transport uses python3-pysnmp
 and the HTTP transport uses python3-httpx.
```

- [ ] **Step 3: Create `debian/rules`**

```makefile
#!/usr/bin/make -f

# Build the netgear_switch Python package with dh-python/pybuild straight from
# pyproject.toml (hatchling backend). The upstream version is normally derived
# from git by hatch-vcs, but during the .deb build there may be no VCS context in
# the unpacked source, so we pin it to the changelog version (set by
# packaging/deb-version.py) through SETUPTOOLS_SCM_PRETEND_VERSION. dpkg source
# format is native, so the changelog version has no Debian revision to strip.
export PYBUILD_NAME = netgear_switch
export SETUPTOOLS_SCM_PRETEND_VERSION = $(shell dpkg-parsechangelog -SVersion)

%:
	dh $@ --with python3 --buildsystem=pybuild

# The test suite (net-snmp subprocesses + live virtual-switch integration) runs
# in the CI test job, not during packaging. Skip it here to keep the build fast
# and free of extra build-deps.
override_dh_auto_test:
	:
```

Note: the recipe lines under the targets MUST be indented with a TAB, not spaces.

- [ ] **Step 4: Create the placeholder `debian/changelog`**

This is a committed placeholder; CI regenerates it from git before every build.

```
python-netgear-switch-library (0.0.post0) unstable; urgency=medium

  * Placeholder changelog. The real version is generated at build time by
    packaging/deb-version.py --write-changelog (git-derived, rolling release).

 -- Tim 'mithro' Ansell <me@mith.ro>  Sat, 18 Jul 2026 00:00:00 +0000
```

- [ ] **Step 5: Create `debian/copyright`**

```
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: python-netgear-switch-library
Upstream-Contact: Tim Ansell <me@mith.ro>
Source: https://github.com/mithro/netgear-stupid-control

Files: *
Copyright: 2026 Tim Ansell
License: Apache-2.0

License: Apache-2.0
 On Debian systems, the complete text of the Apache License Version 2.0
 can be found in '/usr/share/common-licenses/Apache-2.0'.
```

- [ ] **Step 6: Verify the changelog parses and the version script rewrites it**

Run:

```bash
python3 packaging/deb-version.py --write-changelog
python3 -c "import subprocess; print(subprocess.run(['dpkg-parsechangelog','-SVersion'],capture_output=True,text=True).stdout.strip())" 2>/dev/null \
  || echo "dpkg-parsechangelog not installed locally (fine; verified in container in Task 6)"
git checkout -- debian/changelog
```

Expected: the version prints `0.0.post66` (if `dpkg-parsechangelog` is available), or the skip message on a host without dpkg-dev. `git checkout` restores the committed placeholder.

- [ ] **Step 7: Commit**

```bash
chmod +x debian/rules
git add debian/control debian/rules debian/changelog debian/copyright debian/source/format
git commit -m "packaging: add Debian source package (dh-python, ships ngsw + snmp dep)"
```

---

### Task 6: Container build script + apt landing page (locally reproducible)

**Files:**
- Create: `packaging/ci-build.sh`
- Create: `packaging/apt-index.html`

**Interfaces:**
- Consumes: `debian/` (Task 5) and `packaging/deb-version.py` (Task 2).
- Produces: `packaging/ci-build.sh` — runs inside a `debian:trixie`/`debian:sid` container, installs build-deps, regenerates the changelog from git, runs `dpkg-buildpackage -b -us -uc`, and copies the resulting `.deb`(s) into `built-debs/`. `packaging/apt-index.html` — the landing page served at the apt repo root, containing the `sources.list` snippet users copy.
- Consumed by: Task 7 (`deb.yml` invokes `ci-build.sh` in the build matrix and copies `apt-index.html` into the published site).

- [ ] **Step 1: Create `packaging/ci-build.sh`**

```sh
#!/bin/sh
# Build python3-netgear-switch-library (.deb) inside a Debian container. Invoked
# by .github/workflows/deb.yml once per suite as:
#   docker run --rm -v "$PWD:/src" -w /src debian:trixie sh packaging/ci-build.sh
# and reproducible locally the same way. Writes the resulting .deb files to
# /src/built-debs (bind-mounted to the host/runner).
set -eux

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  build-essential ca-certificates git \
  dpkg-dev debhelper dh-python pybuild-plugin-pyproject \
  python3-all python3-hatchling python3-hatch-vcs python3-setuptools-scm

# dpkg-buildpackage / git refuse to operate on a repo owned by another uid.
git config --global --add safe.directory /src

# Rolling release: derive the version from git and regenerate the changelog.
python3 packaging/deb-version.py --write-changelog

# Binary-only build, unsigned (the apt repo is signed later, in the publish job).
dpkg-buildpackage -b -us -uc

mkdir -p built-debs
cp ../*.deb built-debs/
ls -l built-debs/
```

- [ ] **Step 2: Create `packaging/apt-index.html`**

```html
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>python-netgear-switch-library apt repository</title></head>
<body>
<h1>python-netgear-switch-library apt repository</h1>
<p>Debian packages of
<a href="https://github.com/mithro/netgear-stupid-control">python-netgear-switch-library</a>:
a Python library (<code>import netgear_switch</code>) and CLI (<code>ngsw</code>)
to query and control Netgear managed and Plus switches over SNMP, NSDP and HTTP.
Rolling release &mdash; every push to <code>main</code> publishes a new version
(no tags). Built for Debian trixie and sid; the package is architecture
<code>all</code> (pure Python).</p>

<h2>Setup (Debian trixie)</h2>
<pre>
sudo install -d -m0755 /etc/apt/keyrings
curl -fsSL https://mithro.github.io/netgear-stupid-control/netgear-switch.gpg \
  | sudo tee /etc/apt/keyrings/netgear-switch.gpg > /dev/null

echo "deb [signed-by=/etc/apt/keyrings/netgear-switch.gpg] https://mithro.github.io/netgear-stupid-control/trixie/ ./" \
  | sudo tee /etc/apt/sources.list.d/netgear-switch.list

sudo apt update
sudo apt install python3-netgear-switch-library
</pre>

<h2>Setup (Debian sid)</h2>
<pre>
sudo install -d -m0755 /etc/apt/keyrings
curl -fsSL https://mithro.github.io/netgear-stupid-control/netgear-switch.gpg \
  | sudo tee /etc/apt/keyrings/netgear-switch.gpg > /dev/null

echo "deb [signed-by=/etc/apt/keyrings/netgear-switch.gpg] https://mithro.github.io/netgear-stupid-control/sid/ ./" \
  | sudo tee /etc/apt/sources.list.d/netgear-switch.list

sudo apt update
sudo apt install python3-netgear-switch-library
</pre>
</body>
</html>
```

- [ ] **Step 3: Build a real `.deb` locally in a trixie container (primary verification)**

On the local arm64 host (docker or podman):

```bash
chmod +x packaging/ci-build.sh
docker run --rm -v "$PWD:/src" -w /src docker.io/library/debian:trixie sh packaging/ci-build.sh
```

Expected: the run ends with `ls -l built-debs/` listing `python3-netgear-switch-library_0.0.post66_all.deb`.

- [ ] **Step 4: Inspect the produced package**

```bash
dpkg-deb -I built-debs/python3-netgear-switch-library_*.deb | sed -n '1,20p'
dpkg-deb -c built-debs/python3-netgear-switch-library_*.deb | grep -E 'ngsw|netgear_switch/__init__|py.typed'
```

Expected: the control block shows `Package: python3-netgear-switch-library`, `Version: 0.0.post66`, `Depends:` includes `snmp`; the contents include `./usr/bin/ngsw`, the `netgear_switch` package under `usr/lib/python3/dist-packages/`, and `py.typed`.

- [ ] **Step 5: (Optional) confirm it also builds on sid**

```bash
docker run --rm -v "$PWD:/src" -w /src docker.io/library/debian:sid sh packaging/ci-build.sh
```

Expected: same successful build. Clean up: `rm -rf built-debs debian/changelog && git checkout -- debian/changelog`.

- [ ] **Step 6: Commit**

```bash
git add packaging/ci-build.sh packaging/apt-index.html
git commit -m "packaging: add container build script and apt landing page"
```

---

### Task 7: Debian build + signed apt repo on GitHub Pages (rolling release wiring)

**Files:**
- Create: `.github/workflows/deb.yml`

**Interfaces:**
- Consumes: `packaging/ci-build.sh` (Task 6), `packaging/apt-index.html` (Task 6), `debian/` (Task 5).
- Produces: a workflow that, on push to `main`, builds the `.deb` in both `debian:trixie` and `debian:sid` containers (matrix), then generates per-suite flat apt repositories (`trixie/`, `sid/`) with `Packages`/`Packages.gz`/`Release`, GPG-signs each `Release` (gated on the `APT_GPG_PRIVATE_KEY` secret — a documented final setup step), exports the public key at the site root, and deploys the whole tree to GitHub Pages. This is the rolling-release wiring for the apt side; combined with Task 4 it means every merge to main ships both PyPI and apt packages.
- Consumed by: end users (apt) and `RELEASING.md` (Task 9, documents the GPG secret + Pages setup).

- [ ] **Step 1: Create `.github/workflows/deb.yml`**

```yaml
name: Debian Packages + apt repo

# Rolling release: every push to main builds python3-netgear-switch-library for
# Debian trixie AND sid and republishes a signed flat apt repository on GitHub
# Pages (https://mithro.github.io/netgear-stupid-control/). Mirrors the pattern
# used by other mithro apt-repo projects (sensors2mqtt, ten64-controller). The
# package is Architecture: all (pure Python), so it builds on the default x86
# runner and installs on any Debian arch. No tags: the version is git-derived.
on:
  push:
    branches: [main]
  workflow_dispatch:

jobs:
  build-deb:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        suite: [trixie, sid]
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # full history so deb-version.py can count commits

      - name: Build package in debian:${{ matrix.suite }}
        run: |
          docker run --rm \
            -v "${PWD}:/src" -w /src \
            docker.io/library/debian:${{ matrix.suite }} \
            sh packaging/ci-build.sh

      - uses: actions/upload-artifact@v4
        with:
          name: debs-${{ matrix.suite }}
          path: built-debs/

  publish-apt:
    needs: build-deb
    runs-on: ubuntu-latest
    permissions:
      pages: write
      id-token: write
    environment:
      name: github-pages
      url: ${{ steps.deploy.outputs.page_url }}
    steps:
      - uses: actions/checkout@v4

      - name: Download trixie debs
        uses: actions/download-artifact@v4
        with:
          name: debs-trixie
          path: apt-repo/trixie/

      - name: Download sid debs
        uses: actions/download-artifact@v4
        with:
          name: debs-sid
          path: apt-repo/sid/

      - name: Generate apt repo metadata (per suite)
        run: |
          set -eux
          sudo apt-get update
          sudo apt-get install -y --no-install-recommends dpkg-dev apt-utils
          cp packaging/apt-index.html apt-repo/index.html
          for suite in trixie sid; do
            cd "apt-repo/$suite"
            dpkg-scanpackages --multiversion . > Packages
            gzip -k -f Packages
            {
              echo "Origin: python-netgear-switch-library"
              echo "Label: python-netgear-switch-library"
              echo "Suite: stable"
              echo "Codename: $suite"
              echo "Architectures: all"
              echo "Components: main"
              echo "Description: python-netgear-switch-library apt repository ($suite)"
            } > Release
            apt-ftparchive release . >> Release
            cd ../..
          done

      - name: Sign repo
        env:
          GPG_PRIVATE_KEY: ${{ secrets.APT_GPG_PRIVATE_KEY }}
        if: env.GPG_PRIVATE_KEY != ''
        run: |
          set -eux
          echo "$GPG_PRIVATE_KEY" | gpg --batch --import
          gpg --batch --yes --armor --export > apt-repo/netgear-switch.gpg
          for suite in trixie sid; do
            cd "apt-repo/$suite"
            gpg --batch --yes --armor --detach-sign --output Release.gpg Release
            gpg --batch --yes --armor --clearsign --output InRelease Release
            cd ../..
          done

      - uses: actions/configure-pages@v5

      - uses: actions/upload-pages-artifact@v3
        with:
          path: apt-repo/

      - id: deploy
        uses: actions/deploy-pages@v4
```

- [ ] **Step 2: Verify valid YAML**

Run:

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/deb.yml')); print('OK')"
```

Expected: `OK`.

- [ ] **Step 3: Verify the apt metadata generation locally (dry run)**

Reproduce the publish job's metadata step against a locally built `.deb` (from Task 6). Requires `dpkg-dev` + `apt-utils` (or run inside a debian container):

```bash
rm -rf /tmp/apt-repo && mkdir -p /tmp/apt-repo/trixie
cp built-debs/*.deb /tmp/apt-repo/trixie/ 2>/dev/null || echo "build a .deb first (Task 6 Step 3)"
docker run --rm -v /tmp/apt-repo/trixie:/r -w /r docker.io/library/debian:trixie sh -c '
  set -eux
  apt-get update && apt-get install -y --no-install-recommends dpkg-dev apt-utils
  dpkg-scanpackages --multiversion . > Packages
  gzip -k -f Packages
  echo "Origin: python-netgear-switch-library" > Release
  apt-ftparchive release . >> Release
  head -5 Packages
  head -3 Release
'
```

Expected: `Packages` lists `Package: python3-netgear-switch-library` with a `Filename:` and SHA sums; `Release` starts with the `Origin:` line followed by `apt-ftparchive` checksums. This proves the metadata step is correct without pushing to GitHub.

- [ ] **Step 4: Commit**

```bash
rm -rf /tmp/apt-repo built-debs
git add .github/workflows/deb.yml
git commit -m "ci: build trixie+sid debs and publish signed apt repo to gh-pages"
```

---

### Task 8: README installation section

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: the PyPI distribution name and the apt repo layout/URL from Tasks 4, 6, 7.
- Produces: user-facing install instructions (pip + apt for trixie/sid), including the net-snmp CLI note.

- [ ] **Step 1: Add an Installation section to `README.md`**

Insert the following block immediately after the intro paragraph (before the existing `## Development` heading). Use Edit, anchoring on the `## Development` line:

```markdown
## Installation

### pip / uv (PyPI)

```sh
pip install python-netgear-switch-library
# or: uv add python-netgear-switch-library
```

Optional extras: `[async]` (pysnmp), `[http]` (httpx). The synchronous SNMP
transport shells out to the **net-snmp command-line tools**, a system package
(not a Python dependency):

```sh
sudo apt install snmp   # provides snmpget/snmpbulkwalk/snmpset
```

### Debian / Ubuntu (apt)

Signed `.deb` packages for Debian **trixie** and **sid** are published to a
GitHub Pages apt repository. Pick the line matching your suite:

```sh
sudo install -d -m0755 /etc/apt/keyrings
curl -fsSL https://mithro.github.io/netgear-stupid-control/netgear-switch.gpg \
  | sudo tee /etc/apt/keyrings/netgear-switch.gpg > /dev/null

# trixie:
echo "deb [signed-by=/etc/apt/keyrings/netgear-switch.gpg] https://mithro.github.io/netgear-stupid-control/trixie/ ./" \
  | sudo tee /etc/apt/sources.list.d/netgear-switch.list
# sid:
echo "deb [signed-by=/etc/apt/keyrings/netgear-switch.gpg] https://mithro.github.io/netgear-stupid-control/sid/ ./" \
  | sudo tee /etc/apt/sources.list.d/netgear-switch.list

sudo apt update
sudo apt install python3-netgear-switch-library
```

This installs the `netgear_switch` library and the `ngsw` CLI, and pulls in the
`snmp` net-snmp CLI tools automatically.

### Versioning

This project is a **rolling release**: the version is derived from git
(`0.0.postN` / `X.Y.postN`), and every merge to `main` publishes a new version
to PyPI and the apt repo. There are no tags or manual version bumps.
```

- [ ] **Step 2: Verify the Markdown renders and links are intact**

Run:

```bash
grep -n "Installation" README.md
grep -c "mithro.github.io/netgear-stupid-control" README.md
```

Expected: the `## Installation` heading is present and the apt URL appears at least 3 times (key + 2 suites).

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: add pip + apt installation instructions"
```

---

### Task 9: RELEASING.md — the one-time human setup steps

**Files:**
- Create: `RELEASING.md`

**Interfaces:**
- Consumes: the PyPI publish workflow (Task 4), the deb/apt workflow (Task 7), and the GPG-signing gate.
- Produces: a checklist a human completes ONCE to arm the automated release: PyPI trusted-publisher registration + `pypi` environment, the apt GPG signing key (`APT_GPG_PRIVATE_KEY` secret), and enabling GitHub Pages. Documents that no secrets are ever committed.

- [ ] **Step 1: Create `RELEASING.md`**

```markdown
# Releasing

This project is a **rolling release**. There are no tags and no manual version
bumps: the version is derived from git (`hatch-vcs` for the wheel,
`packaging/deb-version.py` for the `.deb`), and **every merge to `main`
publishes new packages** automatically:

- `.github/workflows/ci.yml` — runs the gates (ruff, mypy --strict, pytest with
  coverage >= 90) on every push and PR. A green run is what "mergeable" means.
- `.github/workflows/publish-pypi.yml` — builds and uploads the wheel + sdist to
  PyPI on every push to `main`.
- `.github/workflows/deb.yml` — builds `.deb`s for trixie + sid and republishes
  the signed apt repo on GitHub Pages on every push to `main`.

Merges to `main` MUST use `--no-ff` merge commits so history stays linear per PR.

## One-time human setup

These steps are done ONCE by a maintainer. **No secret or key is ever committed
to the repo.** Until they are done, the workflows run but the publish/sign steps
are safely gated (PyPI publish needs the trusted publisher; signing is skipped if
`APT_GPG_PRIVATE_KEY` is unset).

### 1. PyPI trusted publishing (OIDC)

1. Create the project `python-netgear-switch-library` on https://pypi.org (or
   let the first trusted-publisher upload create it via a pending publisher).
2. On PyPI, go to the project (or your account's "Publishing" page) and add a
   **Trusted Publisher** with:
   - Owner: `mithro`
   - Repository: `netgear-stupid-control`
   - Workflow filename: `publish-pypi.yml`
   - Environment name: `pypi`
3. In the GitHub repo, create an **Environment** named `pypi`
   (Settings → Environments → New environment). No secrets needed — OIDC handles
   auth. Optionally add required reviewers to gate uploads.

After this, the next push to `main` uploads to PyPI. `skip-existing: true` makes
re-runs idempotent.

### 2. apt repo GPG signing key

1. Generate a signing key locally (RSA 4096, no passphrase so CI can use it
   unattended; keep the private key OFFLINE, never in the repo):

   ```sh
   gpg --batch --gen-key <<EOF
   %no-protection
   Key-Type: RSA
   Key-Length: 4096
   Name-Real: python-netgear-switch-library apt repo
   Name-Email: me@mith.ro
   Expire-Date: 0
   %commit
   EOF
   ```

2. Export the private key (armored) and add it as the GitHub Actions secret
   `APT_GPG_PRIVATE_KEY` (Settings → Secrets and variables → Actions → New
   repository secret):

   ```sh
   gpg --armor --export-secret-keys me@mith.ro | pbcopy   # or xclip / paste manually
   ```

   The workflow imports this key and exports the matching public key to
   `netgear-switch.gpg` at the apt repo root, which users install into
   `/etc/apt/keyrings/`.

### 3. GitHub Pages

1. Settings → Pages → Source: **GitHub Actions**.
2. The `deb.yml` `publish-apt` job deploys the apt repo to
   `https://mithro.github.io/netgear-stupid-control/`.

## Verifying a release

- PyPI: check https://pypi.org/project/python-netgear-switch-library/ for the new
  `0.0.postN` version.
- apt: `sudo apt update && apt-cache policy python3-netgear-switch-library` on a
  Debian trixie/sid box configured per the README.
```

- [ ] **Step 2: Verify the doc is complete and self-consistent**

Run:

```bash
grep -n "APT_GPG_PRIVATE_KEY" RELEASING.md .github/workflows/deb.yml
grep -n "publish-pypi.yml" RELEASING.md
grep -n "environment" .github/workflows/publish-pypi.yml
```

Expected: the secret name matches between `RELEASING.md` and `deb.yml`; the workflow filename and the `pypi` environment referenced in the doc match the actual workflow files.

- [ ] **Step 3: Commit**

```bash
git add RELEASING.md
git commit -m "docs: document one-time PyPI OIDC + apt GPG release setup"
```

---

## Self-Review Notes

**1. Spec coverage** (each Slice 8 scope item → task):

- Scope 1 (derived rolling version, no tags) → Task 1 (hatch-vcs for the wheel) + Task 2 (`deb-version.py` for the `.deb`). Both read git; agreement documented. Verified locally: `deb-version.py` prints `0.0.post66`.
- Scope 2 (PyPI publish via OIDC, gated on final setup) → Task 4 + `RELEASING.md` (Task 9). `py.typed` already shipped (force-include preserved in Task 1).
- Scope 3 (Debian packages for trixie AND sid) → Task 5 (`debian/`) + Task 6 (`ci-build.sh`, local docker build) + Task 7 (trixie/sid matrix). Verified with `dpkg-deb -I`/`-c`.
- Scope 4 (GitHub Pages apt repo, signed, mithro style) → Task 7 (per-suite `Packages`/`Packages.gz`/`Release`, GPG sign, `netgear-switch.gpg`, `apt-index.html`), matching `sensors2mqtt`/`ten64` patterns.
- Scope 5 (CI local == CI) → Task 3: `snmp` install, `uv sync --all-extras --dev`, ruff/mypy/pytest with the same coverage gate, matrix 3.11/3.12/3.13, 25-min timeout.
- Scope 6 (rolling release wiring, mergeable ⇒ released, no tags) → Tasks 3+4+7 on push to `main`; documented in `RELEASING.md`.
- Scope 7 (docs) → Task 8 (README pip+apt) + Task 9 (`RELEASING.md`).

**2. Placeholder scan:** No "TBD"/"handle edge cases"/"similar to Task N". Every file is given complete, real contents (TOML, YAML, Dockerfile-free container script, debian control/rules/changelog/copyright/format, HTML, Markdown). The one intentional placeholder — `debian/changelog` version `0.0.post0` — is explicitly a build-time-regenerated placeholder, not a plan gap.

**3. Type/name consistency:**
- Distribution `python-netgear-switch-library`, binary `python3-netgear-switch-library`, import `netgear_switch`, CLI `ngsw` — consistent across pyproject, debian/control, apt-index, README, RELEASING.
- Version scheme `0.0.postN` consistent between hatch-vcs (`version_scheme = "post-release"`, `local_scheme = "no-local-version"`) and `deb-version.py` fallback (`0.0.post<count>`).
- Secret `APT_GPG_PRIVATE_KEY` and public key filename `netgear-switch.gpg` consistent between `deb.yml`, `apt-index.html`, README, RELEASING.
- Apt URL `https://mithro.github.io/netgear-stupid-control/{trixie,sid}/` consistent everywhere; suite subdirectories match between `deb.yml` layout and the `sources.list` snippets.
- `SETUPTOOLS_SCM_PRETEND_VERSION` in `debian/rules` is fed the `dpkg-parsechangelog -SVersion` value that `deb-version.py --write-changelog` set — the `.deb`'s Python metadata version equals the changelog version.

**4. Safety checks:** No `git add -A` anywhere; every commit stages explicit paths, never the overlay char-device dotfiles. Generated `_version.py` and Debian byproducts are git-ignored (Task 1). Tests are skipped during the `.deb` build (`override_dh_auto_test`) so packaging stays fast and dependency-light, avoiding flaky deb builds; the full suite runs in the CI test job. Secrets/keys are documented human steps, never committed; signing is `if: env.GPG_PRIVATE_KEY != ''`-gated so the workflow is green before the key exists.

**5. Known risk / decision to flag for the executor:** `hatch-vcs` with `version_scheme = "post-release"` and NO tags: confirm the emitted wheel version in Task 1 Step 5 actually starts with `0.0.post` (setuptools-scm's no-tag fallback can vary by version). If it instead emits a `.dev`/`+g…` form, add `raw-options` `fallback_version` or a `SETUPTOOLS_SCM_FALLBACK_VERSION`/`version_file` guard so the wheel matches the `deb-version.py` `0.0.postN` form — the two must agree. The deterministic, network-free ground truth is `python3 packaging/deb-version.py` → `0.0.post66`.
```
