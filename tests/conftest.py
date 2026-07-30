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
def virtual_gsm7228ps() -> Iterator[VirtualSwitch]:
    """Start a seeded gsm7228ps (S3300, Smart Managed Pro) VirtualSwitch on
    an ephemeral port; stop it after the test, even on failure."""
    sw = VirtualSwitch(model="gsm7228ps")
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


@pytest.fixture
def virtual_gs305ep() -> Iterator[VirtualSwitch]:
    """Start a seeded gs305ep VirtualSwitch (HTTP face) on an ephemeral port;
    stop it after the test, even on failure, so no socket is leaked."""
    sw = VirtualSwitch(model="gs305ep")
    sw.start()
    try:
        yield sw
    finally:
        sw.stop()


@pytest.fixture
def virtual_m4300_24x() -> Iterator[VirtualSwitch]:
    """Start a seeded m4300-24x (non-PoE, Fully Managed) VirtualSwitch on an
    ephemeral SNMP port; stop it after the test, even on failure."""
    sw = VirtualSwitch(model="m4300-24x")
    sw.start()
    try:
        yield sw
    finally:
        sw.stop()


@pytest.fixture
def virtual_m4300_16x() -> Iterator[VirtualSwitch]:
    """Start a seeded m4300-16x (all-16-ports-PoE, Fully Managed) VirtualSwitch
    on an ephemeral SNMP port; stop it after the test, even on failure."""
    sw = VirtualSwitch(model="m4300-16x")
    sw.start()
    try:
        yield sw
    finally:
        sw.stop()
