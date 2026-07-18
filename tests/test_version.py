# tests/test_version.py
"""The package version must be derived from git (hatch-vcs), never hard-coded."""
from __future__ import annotations

import re
from importlib.metadata import version as pkg_version

import netgear_switch

_PEP440_RE = re.compile(r"^\d+(\.\d+)*((a|b|rc)\d+)?(\.post\d+)?(\.dev\d+)?$")


def test_version_is_not_hardcoded_placeholder():
    assert netgear_switch.__version__ != "0.1.0"


def test_version_is_valid_pep440_string():
    assert _PEP440_RE.match(netgear_switch.__version__), netgear_switch.__version__


def test_version_matches_installed_package_metadata():
    assert netgear_switch.__version__ == pkg_version("python-netgear-switch-library")


def test_version_exported_in_all():
    assert "__version__" in netgear_switch.__all__
