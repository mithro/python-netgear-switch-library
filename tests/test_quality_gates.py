# tests/test_quality_gates.py
"""The quality gates and the new package path must be wired up."""

from __future__ import annotations

import tomllib
from pathlib import Path


def test_ruff_selects_type_aware_and_bug_rules():
    cfg = tomllib.loads(Path("pyproject.toml").read_text())
    select = cfg["tool"]["ruff"]["lint"]["select"]
    for rule in ("E", "F", "I", "UP", "B", "SIM", "RUF", "PT", "TC", "C4"):
        assert rule in select, f"ruff must select {rule}"


def test_mypy_strict_configured():
    cfg = tomllib.loads(Path("pyproject.toml").read_text())
    assert cfg["tool"]["mypy"]["strict"] is True
    assert "netgear_switch" in cfg["tool"]["mypy"]["packages"]


def test_coverage_floor_configured():
    cfg = tomllib.loads(Path("pyproject.toml").read_text())
    addopts = cfg["tool"]["pytest"]["ini_options"]["addopts"]
    assert "--cov=netgear_switch" in addopts
    assert "--cov-fail-under=90" in addopts


def test_dev_group_has_type_and_cov_tools():
    cfg = tomllib.loads(Path("pyproject.toml").read_text())
    dev = " ".join(cfg["dependency-groups"]["dev"])
    assert "mypy" in dev
    assert "pytest-cov" in dev


def test_protocols_snmp_package_importable():
    import netgear_switch.protocols.snmp  # noqa: F401
