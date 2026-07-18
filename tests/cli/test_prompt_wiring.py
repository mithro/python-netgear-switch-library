"""Prove the interactive credential PROMPT tier is reachable end-to-end
through the real ``main()`` entry point, not just via ``resolve_switch``
called directly (as ``test_resolve.py`` already covers).

``main()`` must thread its ``prompt``/``env`` kwargs into the REAL
``resolve_switch`` (the ``switch_factory`` seam is deliberately NOT used
here) so that, with no community available from a CLI flag, env var, or
config, the prompt tier actually fires in production.
"""
from __future__ import annotations

import io

import pytest

from netgear_switch.cli.main import main


class _PromptCalledError(Exception):
    """Raised by the fake prompt so the test can prove it fired WITHOUT ever
    letting execution reach a real network call (SNMP client construction
    happens only after the community is resolved, so raising here stops the
    test before any socket touches the wire)."""


def test_main_wires_prompt_and_env_into_real_resolve_switch() -> None:
    seen: list[str] = []

    def fake_prompt(text: str) -> str:
        seen.append(text)
        raise _PromptCalledError(text)

    out, err = io.StringIO(), io.StringIO()
    with pytest.raises(_PromptCalledError):
        main(
            ["ports", "--host", "10.0.0.9", "--model", "gsm7252ps"],
            env={},
            prompt=fake_prompt,
            stdout=out,
            stderr=err,
        )
    assert seen  # the real resolve_switch's prompt tier was actually invoked
    assert "community" in seen[0].lower()
