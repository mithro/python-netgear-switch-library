# tests/conftest.py
"""Shared fixtures for the integration tests: a live VirtualSwitch."""
from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from netgear_switch.virtual.server import VirtualSwitch

if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture
def virtual_gsm7252ps() -> Iterator[VirtualSwitch]:
    """Start a seeded gsm7252ps VirtualSwitch on an ephemeral port; stop it
    after the test, even on failure, so no socket/task is leaked."""
    sw = VirtualSwitch(model="gsm7252ps")
    sw.start()
    try:
        yield sw
    finally:
        sw.stop()


@pytest.fixture
def virtual_gs110emx() -> Iterator[VirtualSwitch]:
    """Start a seeded gs110emx (NSDP) VirtualSwitch on an ephemeral UDP port."""
    sw = VirtualSwitch(model="gs110emx")
    sw.start()
    try:
        yield sw
    finally:
        sw.stop()
