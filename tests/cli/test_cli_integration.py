# tests/cli/test_cli_integration.py
"""End-to-end ``ngsw`` CLI tests: drive the real ``main()`` against a real
``VirtualSwitch`` over live SNMP.

The ``resolve`` seam is bypassed via ``switch_factory`` (exactly how ``main``
is designed to be driven in tests -- see ``resolve.py``'s docstring), but
every layer downstream of it is real: ``SyncSwitch`` -> ``SnmpReader`` /
``SnmpWriter`` -> the live net-snmp CLI subprocess (``NetsnmpCliClient``) ->
the ``VirtualSwitch``'s bound SNMP face -> ``VirtualSwitchState``. This is
the same wiring pattern as ``tests/test_snmp_integration.py``.
"""
from __future__ import annotations

import io
import json
from typing import TYPE_CHECKING

from netgear_switch.cli import context
from netgear_switch.cli.main import main
from netgear_switch.registry import get_model
from netgear_switch.sync_api import SyncSwitch
from netgear_switch.transport.sync.snmp_netsnmp_cli import NetsnmpCliClient

if TYPE_CHECKING:
    import argparse

    from netgear_switch.virtual.server import VirtualSwitch


def _factory(
    sw: VirtualSwitch,
) -> object:
    def build(args: argparse.Namespace, ctx: context.CliContext) -> SyncSwitch:
        del args, ctx  # resolve seam is bypassed entirely for this e2e test
        client = NetsnmpCliClient(f"{sw.host}:{sw.port}", "public")
        return SyncSwitch(
            get_model("gsm7252ps"),
            sw.host,
            snmp_client=client,
            # The same client also serves writes: NetsnmpCliClient wraps the
            # net-snmp CLI's "HOST:PORT" agent-spec form, so a SET routes to
            # the VirtualSwitch's ephemeral port too. Without an explicit
            # snmp_write_client, SyncSwitch would build its OWN write client
            # against `sw.host` alone (the default SNMP port 161), missing
            # the mock entirely -- so every write command below would fail
            # (or hit real infrastructure) instead of exercising the mock.
            snmp_write_client=client,
        )

    return build


def test_ports_json_against_virtual_switch(virtual_gsm7252ps: VirtualSwitch) -> None:
    out, err = io.StringIO(), io.StringIO()
    code = main(
        ["--json", "ports"],
        switch_factory=_factory(virtual_gsm7252ps),
        stdout=out,
        stderr=err,
    )
    assert code == context.EXIT_OK
    ports = json.loads(out.getvalue())
    assert any(p["name"] == "1/0/1" for p in ports)


def test_ports_table_against_virtual_switch(virtual_gsm7252ps: VirtualSwitch) -> None:
    out = io.StringIO()
    code = main(
        ["ports"],
        switch_factory=_factory(virtual_gsm7252ps),
        stdout=out,
        stderr=io.StringIO(),
    )
    assert code == context.EXIT_OK
    assert "1/0/1" in out.getvalue()
    assert "Port" in out.getvalue()  # table header, proves table_fn (not JSON) ran


def test_show_snapshot_against_virtual_switch(virtual_gsm7252ps: VirtualSwitch) -> None:
    out = io.StringIO()
    code = main(
        ["show"],
        switch_factory=_factory(virtual_gsm7252ps),
        stdout=out,
        stderr=io.StringIO(),
    )
    assert code == context.EXIT_OK
    assert "## VLANs" in out.getvalue()
    assert "iot" in out.getvalue()


def test_dry_run_write_makes_no_change(virtual_gsm7252ps: VirtualSwitch) -> None:
    out = io.StringIO()
    code = main(
        ["poe", "1", "off", "--dry-run"],
        switch_factory=_factory(virtual_gsm7252ps),
        stdout=out,
        stderr=io.StringIO(),
    )
    assert code == context.EXIT_OK
    assert "DRY-RUN" in out.getvalue()
    # PoE port 1 is still delivering after the dry-run: safety.do_write never
    # calls `action` when dry_run short-circuits, so the VirtualSwitch's own
    # admin flag -- not just the CLI's stdout message -- proves nothing was
    # sent over the wire.
    assert virtual_gsm7252ps.state.poe[1].admin is True


def test_poe_off_write_mutates_virtual_switch_state(
    virtual_gsm7252ps: VirtualSwitch,
) -> None:
    """A real (non-dry-run) write, driven through main(), must reach the
    virtual device: prove it both by inspecting the mock's own state
    directly and via a follow-up CLI read through the same stack."""
    sw = virtual_gsm7252ps
    assert sw.state.poe[1].admin is True  # seed precondition (delivering)

    out = io.StringIO()
    code = main(
        ["poe", "1", "off", "--yes"],
        switch_factory=_factory(sw),
        stdout=out,
        stderr=io.StringIO(),
    )
    assert code == context.EXIT_OK
    assert "ok:" in out.getvalue()

    # The real proof: the virtual switch's own state changed -- the full
    # resolve(bypassed)->SyncSwitch->SnmpWriter->live SNMP SET->VirtualSwitch
    # face->VirtualSwitchState.apply_write path actually ran.
    assert sw.state.poe[1].admin is False

    # And a follow-up read through the SAME CLI stack confirms it too.
    read_out = io.StringIO()
    read_code = main(
        ["--json", "poe"],
        switch_factory=_factory(sw),
        stdout=read_out,
        stderr=io.StringIO(),
    )
    assert read_code == context.EXIT_OK
    poe_rows = json.loads(read_out.getvalue())
    row = next(r for r in poe_rows if r["port"] == 1)
    assert row["admin_enabled"] is False


def test_write_to_unsupported_poe_port_surfaces_cleanly(
    virtual_gsm7252ps: VirtualSwitch,
) -> None:
    """Port 49 is a data-only port on the GSM7252PS (only ports 1-48 are
    PoE-capable -- ``seed.py``'s ``_POE_PORT_COUNT = 48``). Controlling PoE
    there is an unsupported-capability scenario at port granularity: the SNMP
    SET is accepted (the OID column is a recognized writable prefix) but the
    mock has no PoE row for port 49 to mutate, so the facade's
    verify-after-write can never read the port back and raises
    WriteVerificationError -- a real, clean (non-traceback) failure surfacing
    end to end through main()."""
    out, err = io.StringIO(), io.StringIO()
    code = main(
        ["poe", "49", "off", "--yes"],
        switch_factory=_factory(virtual_gsm7252ps),
        stdout=out,
        stderr=err,
    )
    assert code != context.EXIT_OK
    assert code == context.EXIT_VERIFY
    assert err.getvalue().startswith("error:")
    assert "Traceback" not in err.getvalue()
