"""Resolve CLI arguments into a live ``SyncSwitch``.

This is deliberately a stub: real resolution (loading the ``--config``
inventory, picking a switch by ``--switch``/``--host``+``--model``,
resolving SNMP/HTTP credentials) is business logic that belongs to a later
CLI-slice task, not to the framework wiring built here.

``main.main()`` only calls into this module when no ``switch_factory`` was
injected, i.e. real end-user CLI invocations. Tests always inject a fake
factory, so this path is never exercised by the test suite.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import argparse

    from netgear_switch.sync_api import SyncSwitch


def resolve_switch(args: argparse.Namespace) -> SyncSwitch:
    """Build a ``SyncSwitch`` from ``--config``/``--switch``/``--host``/``--model``.

    Not implemented yet — see module docstring.
    """
    del args
    raise NotImplementedError(
        "switch resolution (--config/--switch/--host/--model) is not "
        "implemented yet; pass switch_factory= explicitly until it lands"
    )
