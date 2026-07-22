# tests/http_specs.py
"""Test-only helper for models whose HTTP reads are fixture-grounded but not
yet LIVE cross-verified.

``HttpReader``/``AsyncHttpReader`` refuse to construct while a model's
``HttpModelSpec.reads_verified`` is ``False`` -- deliberately, so the facade
can never serve data from a scrape nobody has checked against hardware. The
gsm7252ps XE backend is in exactly that state: every parser is grounded in a
real capture of 10.1.5.22, but the live HTTP<->SNMP cross-verify has not run,
so the shipped spec says ``reads_verified=False``.

``reads_verified(...)`` flips that ONE flag for the duration of a test so the
fixture-driven parser/dispatch tests can exercise the reader, and restores the
shipped spec afterwards. It is a test seam only: nothing in ``src/`` can reach
it, so the production honesty gate is untouched.
"""
from __future__ import annotations

import contextlib
import dataclasses
from typing import TYPE_CHECKING

from netgear_switch.protocols.http import endpoints

if TYPE_CHECKING:
    from collections.abc import Iterator


@contextlib.contextmanager
def reads_verified(*model_keys: str) -> Iterator[None]:
    """Temporarily mark ``model_keys``' HTTP reads as verified."""
    original = {key: endpoints._SPECS[key] for key in model_keys}
    for key, spec in original.items():
        endpoints._SPECS[key] = dataclasses.replace(spec, reads_verified=True)
    try:
        yield
    finally:
        endpoints._SPECS.update(original)
