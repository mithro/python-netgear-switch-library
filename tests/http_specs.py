# tests/http_specs.py
"""Test-only helper for models whose HTTP reads are fixture-grounded but not
yet LIVE cross-verified.

``HttpReader``/``AsyncHttpReader`` refuse to construct while a model's
``HttpModelSpec.reads_verified`` is ``False`` -- deliberately, so the facade
can never serve data from a scrape nobody has checked against hardware. A model
in exactly that state is gsm7228ps: its CHEETAH_FORM login is proven, but no
read pages have been captured and no cross-verify has run.

``reads_verified(...)`` flips that ONE flag for the duration of a test so the
fixture-driven parser/dispatch tests can exercise an unverified model's reader,
and restores the shipped spec afterwards. It is a test seam only: nothing in
``src/`` can reach it, so the production honesty gate is untouched. (gsm7252ps
no longer needs it -- its shipped spec is ``reads_verified=True`` after the live
cross-verify -- so passing it here is a harmless no-op.)
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
