"""Virtual switch: an in-memory device state plus protocol "faces" onto it.

``VirtualSwitchState`` (state.py) is the one authoritative in-memory device
state; ``seed.py`` hand-authors a realistic instance for a given model; the
``faces`` subpackage (Task 15+) serves that state over a real protocol (e.g.
SNMP) so both transport clients can be tested against it end-to-end.
"""
from __future__ import annotations
