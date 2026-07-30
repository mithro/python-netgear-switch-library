"""The FASTPATH CLI VLAN write backend (``cli_write.CliWriter``).

Everything here runs against the in-process mock CLI face over a real
``VirtualSwitchState`` -- no network, no SSH -- but the COMMANDS being asserted
are the ones proven by hand on a real M4300-24X (FASTPATH 12.0.13.8, 10.1.5.13,
2026-07-30):

    create      vlan database / vlan <vid> / vlan name <vid> <name> / exit
    delete      vlan database / no vlan <vid> / exit
    membership  configure / interface <iface> / switchport mode general /
                vlan participation include <vid> (+ [no] vlan tagging <vid>)
                | vlan participation exclude <vid> / exit / exit
    pvid        configure / interface <iface> / switchport mode general /
                vlan pvid <vid> / exit / exit

The load-bearing live finding these tests exist to pin down: the per-port
``vlan participation``/``vlan tagging``/``vlan pvid`` commands are ACCEPTED into
running-config while a port is in ``switchport mode access`` yet stay completely
INERT (``show vlan <vid>`` keeps reporting Exclude/Autodetect). The mock
reproduces that inertness, so ``test_membership_is_inert_without_general_mode``
fails the moment the writer stops sending ``switchport mode general`` -- which is
exactly the regression that would silently "succeed" against hardware.
"""

from __future__ import annotations

import itertools
from typing import TYPE_CHECKING

import pytest

from netgear_switch.cli_read import CliReader
from netgear_switch.cli_write import CliWriter
from netgear_switch.errors import (
    CliCommandError,
    ProtectedPortError,
    UnsupportedCapabilityError,
    WriteVerificationError,
)
from netgear_switch.models import VlanMode
from netgear_switch.snmp_write import PoeCycleTimeouts

if TYPE_CHECKING:
    from collections.abc import Callable
from netgear_switch.protocols.cli.commands import cli_spec
from netgear_switch.protocols.snmp.client import SnmpRow
from netgear_switch.registry import Backend, get_model
from netgear_switch.snmp_read import SnmpReader
from netgear_switch.sync_api import SyncSwitch
from netgear_switch.virtual import web_gsm7252ps
from netgear_switch.virtual.server import VirtualSwitch

_MODEL = "gsm7252ps"


class _RecordingSession:
    """A ``CliSession`` that forwards to the mock face and records every command.

    Lets a test assert the EXACT command sequence the writer put on the wire (the
    part that has to match hardware) as well as the resulting device state.
    """

    def __init__(self, inner: object) -> None:
        self.inner = inner
        self.commands: list[str] = []

    def run(self, command: str) -> str:
        self.commands.append(command)
        return self.inner.run(command)  # type: ignore[attr-defined]

    def run_scp_copy(self, command: str, scp_password: str) -> str:
        raise AssertionError("VLAN writes never use run_scp_copy")

    def run_write_memory(self, command: str = "write memory", *, prestuff: bool) -> str:
        raise AssertionError("VLAN writes must NOT save the config")

    def close(self) -> None:
        pass

    def config_commands(self) -> list[str]:
        """Only the configuration commands, dropping the verification ``show``s."""
        return [c for c in self.commands if not c.startswith("show ")]


def _writer(
    model_key: str = _MODEL, *, protected_ports: frozenset[int] = frozenset()
) -> tuple[CliWriter, VirtualSwitch, _RecordingSession]:
    sw = VirtualSwitch(model_key)
    session = _RecordingSession(sw.cli_session())
    writer = CliWriter(session, get_model(model_key), protected_ports=protected_ports)
    return writer, sw, session


def _fake_clock() -> Callable[[], float]:
    """A monotonic clock that advances 1s per call, so the PoE polling loops in
    CliWriter run to their deadline instantly instead of sleeping."""
    ticks = itertools.count()

    def clock() -> float:
        return float(next(ticks))

    return clock


def _vlan(sw: VirtualSwitch, vid: int) -> object:
    return sw.state.vlans.get(vid)


# --- per-model interface naming --------------------------------------------


def test_iface_template_is_per_model() -> None:
    # The Fully Managed FASTPATH line addresses ports "1/0/<n>"...
    for key in ("gsm7252ps", "m4300-24x", "m4300-16x"):
        assert cli_spec(get_model(key)).iface(7) == "1/0/7"
        assert cli_spec(get_model(key)).iface(49) == "1/0/49"
    # ...while the Smart-firmware S3300-52X uses "1/g<n>" for its 48 1G ports and
    # "1/xg<n>" for the four 10G uplinks. Both shapes are in that model's own
    # captured transcripts (tests/fixtures/cli/gsm7228ps_port_all.txt: "1/g1";
    # gsm7228ps_vlan_port_all.txt: "1/xg49"), which is why a single hardcoded
    # "1/0/<port>" would have addressed interfaces that do not exist there.
    s3300 = cli_spec(get_model("gsm7228ps"))
    assert s3300.iface(7) == "1/g7"
    assert s3300.iface(48) == "1/g48"
    assert s3300.iface(49) == "1/xg49"
    assert s3300.iface(52) == "1/xg52"


def test_read_and_write_commands_share_the_iface_template() -> None:
    # The refactor: interface_stats() no longer hardcodes "1/0/<port>", so the
    # read path and the write path address a port identically.
    s3300 = cli_spec(get_model("gsm7228ps"))
    assert s3300.interface_stats(49) == "show interface ethernet 1/xg49"
    assert s3300.interface(49) == "interface 1/xg49"
    m4300 = cli_spec(get_model("m4300-24x"))
    assert m4300.interface_stats(3) == "show interface ethernet 1/0/3"
    assert m4300.interface(3) == "interface 1/0/3"


def test_s3300_per_port_reads_reach_the_mock_with_smart_names() -> None:
    # Consequence of the template fix, proven end-to-end: get_stats issues
    # "show interface ethernet 1/g<n>"/"1/xg<n>" and the mock CLI face resolves
    # those names (it used to only match \d+/0/\d+, so every S3300 per-port read
    # fell through to "Command not found" and parsed as zeros).
    sw = VirtualSwitch("gsm7228ps")
    reader = CliReader(sw.cli_session(), get_model("gsm7228ps"))
    stats = {s.port: s for s in reader.get_stats()}
    assert stats[1].rx_bytes == sw.state.ports[1].rx_octets
    # Port 49 is an "1/xg49" UPLINK -- the name shape a "1/0/<n>" (or even a
    # "1/g<n>"-only) template could never address -- and the only kind of port on
    # this seed with real traffic, so a nonzero read proves the command reached
    # the right interface rather than falling through to "Command not found".
    assert stats[49].rx_bytes == sw.state.ports[49].rx_octets == 492931


# --- create / delete --------------------------------------------------------


def test_create_vlan_issues_the_proven_sequence_and_verifies() -> None:
    writer, sw, session = _writer()
    assert 4001 not in sw.state.vlans
    writer.create_vlan(4001, "agent-test")
    # Exactly the hand-proven command sequence, in order.
    assert session.config_commands() == [
        "vlan database",
        "vlan 4001",
        "vlan name 4001 agent-test",
        "exit",
    ]
    vsim = sw.state.vlans[4001]
    assert vsim.name == "agent-test"  # type: ignore[union-attr]
    assert vsim.member == set()  # created EMPTY: no membership, so no disruption


def test_create_vlan_verification_reads_back_through_the_cli_reader() -> None:
    # The verify step is a real CLI read: "show vlan brief" (for existence +
    # name) plus one "show vlan <vid>" per VLAN, i.e. the same commands and the
    # same parsers CliReader.get_vlans() uses for a plain read.
    writer, _sw, session = _writer()
    writer.create_vlan(4002, "verify-me")
    shows = [c for c in session.commands if c.startswith("show ")]
    assert "show vlan brief" in shows
    assert "show vlan 4002" in shows


def test_create_vlan_raises_when_the_switch_silently_ignores_it() -> None:
    # A device (or mock) that ACCEPTS the commands but does not actually create
    # the VLAN must surface as WriteVerificationError, never a silent success.
    class _SwallowingSession(_RecordingSession):
        def run(self, command: str) -> str:
            if command.startswith(("vlan 4003", "vlan name 4003")):
                return ""  # "accepted" and quietly dropped
            return super().run(command)

    sw = VirtualSwitch(_MODEL)
    session = _SwallowingSession(sw.cli_session())
    writer = CliWriter(session, get_model(_MODEL))
    with pytest.raises(WriteVerificationError) as exc:
        writer.create_vlan(4003, "ghost")
    assert exc.value.before is None
    assert exc.value.after is None


def test_rejected_command_raises_cli_command_error() -> None:
    # FASTPATH answers an ACCEPTED config command with empty output, so any text
    # back means it did not apply. Here the mock rejects "vlan name" for a VLAN
    # that does not exist, which is what a wrong/unsupported command looks like.
    writer, sw, _session = _writer()
    with pytest.raises(CliCommandError) as exc:
        # Drive the sequence's second half directly against a missing VLAN by
        # deleting the VLAN out from under the name command is not possible, so
        # use the mock's own rejection path: a bare "vlan <vid>" outside the VLAN
        # database is invalid on real hardware too.
        writer._run("vlan 4004")  # the output contract, exercised directly
    assert "vlan 4004" in str(exc.value)
    assert 4004 not in sw.state.vlans


def test_delete_vlan_issues_the_proven_sequence_and_verifies() -> None:
    writer, sw, session = _writer()
    writer.create_vlan(4001, "doomed")
    session.commands.clear()
    writer.delete_vlan(4001)
    assert session.config_commands() == ["vlan database", "no vlan 4001", "exit"]
    assert 4001 not in sw.state.vlans


def test_delete_vlan_refuses_a_missing_vlan_before_sending_anything() -> None:
    # Precondition failure, NOT a verification divergence: nothing may be sent.
    writer, _sw, session = _writer()
    with pytest.raises(CliCommandError):
        writer.delete_vlan(4099)
    assert session.config_commands() == []


def test_delete_vlan_guards_protected_member_ports() -> None:
    # VLAN 90 in the gsm7252ps seed carries real member ports; making one of them
    # protected must block the delete (it would strip that port's membership)
    # unless force=True -- mirroring SnmpWriter.delete_vlan.
    model_vlan = 90
    sw = VirtualSwitch(_MODEL)
    member = sorted(sw.state.vlans[model_vlan].member)[0]
    session = _RecordingSession(sw.cli_session())
    writer = CliWriter(
        session, get_model(_MODEL), protected_ports=frozenset({member})
    )
    with pytest.raises(ProtectedPortError):
        writer.delete_vlan(model_vlan)
    assert session.config_commands() == []
    assert model_vlan in sw.state.vlans
    writer.delete_vlan(model_vlan, force=True)
    assert model_vlan not in sw.state.vlans


# --- membership -------------------------------------------------------------


def _general_prelude(model_key: str) -> list[str]:
    """The ``switchport mode general`` step, for the models that HAVE the command.

    Live-probed 2026-07-30: the gsm7252ps XE image answers "% Unrecognized
    command" to ``switchport mode ?`` (its ``switchport ?`` offers only
    private-group/protected), while the M4300 12.0.x images and the S3300 Smart
    image all offer access|general|trunk. Sending it on the gsm7252ps would be a
    REJECTED command, not a harmless extra.
    """
    return [] if model_key == "gsm7252ps" else ["switchport mode general"]


@pytest.mark.parametrize(
    ("mode", "tagging_cmd"),
    [
        (VlanMode.TAGGED, "vlan tagging 4001"),
        (VlanMode.UNTAGGED, "no vlan tagging 4001"),
    ],
)
def test_membership_include_sequence(mode: VlanMode, tagging_cmd: str) -> None:
    writer, sw, session = _writer()
    writer.create_vlan(4001, "members")
    session.commands.clear()
    writer.set_vlan_membership(4001, 3, mode)
    assert session.config_commands() == [
        "configure",
        "interface 1/0/3",
        *_general_prelude(_MODEL),
        "vlan participation include 4001",
        tagging_cmd,
        "exit",  # leave interface config
        "exit",  # leave global config
    ]
    vsim = sw.state.vlans[4001]
    assert 3 in vsim.member
    assert (3 in vsim.untagged) is (mode is VlanMode.UNTAGGED)


@pytest.mark.parametrize(
    "model_key", ["gsm7252ps", "m4300-24x", "m4300-16x", "gsm7228ps"]
)
def test_membership_sequence_per_model(model_key: str) -> None:
    """EVERY CLI model, not just the M4300 the commands were proven on.

    Two per-model differences show up in one assertion: the interface NAME
    ("1/0/3" vs the S3300's "1/g3") and whether ``switchport mode general`` is
    part of the sequence at all.
    """
    writer, sw, session = _writer(model_key)
    writer.create_vlan(4001, "parity")
    session.commands.clear()
    writer.set_vlan_membership(4001, 3, VlanMode.TAGGED)
    iface = "1/g3" if model_key == "gsm7228ps" else "1/0/3"
    assert session.config_commands() == [
        "configure",
        f"interface {iface}",
        *_general_prelude(model_key),
        "vlan participation include 4001",
        "vlan tagging 4001",
        "exit",
        "exit",
    ]
    assert 3 in sw.state.vlans[4001].member
    assert 3 not in sw.state.vlans[4001].untagged  # tagged


def test_membership_exclude_sequence() -> None:
    writer, sw, session = _writer()
    writer.create_vlan(4001, "members")
    writer.set_vlan_membership(4001, 3, VlanMode.UNTAGGED)
    session.commands.clear()
    writer.set_vlan_membership(4001, 3, VlanMode.EXCLUDED)
    assert session.config_commands() == [
        "configure",
        "interface 1/0/3",
        *_general_prelude(_MODEL),
        "vlan participation exclude 4001",
        "exit",
        "exit",
    ]
    assert 3 not in sw.state.vlans[4001].member


def test_membership_is_inert_without_general_mode() -> None:
    """THE finding this backend is built around, reproduced by the mock.

    Driving the raw command sequence WITHOUT ``switchport mode general`` against
    an access-mode port leaves ``show vlan <vid>`` reporting the port as
    excluded -- the commands are accepted (empty output, i.e. "success") and do
    nothing. Proven live on 10.1.5.13 with before/after
    ``show running-config interface 1/0/4`` + ``show vlan 4007``, which is an
    M4300, so this is asserted on the M4300 mock (the gsm7252ps XE image has no
    switchport modes at all -- see _general_prelude).
    """
    writer, sw, session = _writer("m4300-24x")
    writer.create_vlan(4001, "inert")
    sw.state.ports[4].switchport_mode = "access"
    session.commands.clear()
    for command in (
        "configure",
        "interface 1/0/4",
        "vlan participation include 4001",
        "no vlan tagging 4001",
        "exit",
        "exit",
    ):
        assert session.run(command) == ""  # every command "succeeds"...
    assert 4 not in sw.state.vlans[4001].member  # ...and nothing happened.

    # The real writer recovers on the very same port, because it sends
    # "switchport mode general" first.
    writer.set_vlan_membership(4001, 4, VlanMode.UNTAGGED)
    assert 4 in sw.state.vlans[4001].untagged
    assert sw.state.ports[4].switchport_mode == "general"


def test_switchport_mode_is_rejected_on_the_gsm7252ps_image() -> None:
    # The mock must REJECT what the device rejects (CLAUDE.md principle 5).
    # Probed live on 10.1.5.22: "switchport mode ?" -> "% Unrecognized command".
    _writer_obj, _sw, session = _writer("gsm7252ps")
    assert session.run("configure") == ""
    assert session.run("interface 1/0/3") == ""
    assert session.run("switchport mode general") != ""  # rejected, like the device
    # ...while the S3300 Smart image, which does have the command, accepts it.
    sw2 = VirtualSwitch("gsm7228ps")
    s2 = _RecordingSession(sw2.cli_session())
    assert s2.run("configure") == ""
    assert s2.run("interface 1/g3") == ""
    assert s2.run("switchport mode general") == ""
    assert sw2.state.ports[3].switchport_mode == "general"


def test_membership_verification_catches_a_dropped_command() -> None:
    # A session that swallows the participation command (a stand-in for firmware
    # that accepts it but does not apply it) must raise WriteVerificationError
    # carrying the before/after participation of the target port.
    class _DroppingSession(_RecordingSession):
        def run(self, command: str) -> str:
            if command.startswith("vlan participation"):
                return ""
            return super().run(command)

    sw = VirtualSwitch(_MODEL)
    session = _DroppingSession(sw.cli_session())
    writer = CliWriter(session, get_model(_MODEL))
    writer.create_vlan(4001, "dropped")
    with pytest.raises(WriteVerificationError) as exc:
        writer.set_vlan_membership(4001, 5, VlanMode.TAGGED)
    assert exc.value.before is VlanMode.EXCLUDED
    assert exc.value.after is VlanMode.EXCLUDED


def test_membership_requires_the_vlan_to_exist() -> None:
    writer, _sw, session = _writer()
    with pytest.raises(CliCommandError):
        writer.set_vlan_membership(4098, 5, VlanMode.TAGGED)
    assert session.config_commands() == []  # precondition: nothing sent


def test_membership_honours_protected_ports() -> None:
    writer, _sw, session = _writer(protected_ports=frozenset({11}))
    writer.create_vlan(4001, "guarded")
    session.commands.clear()
    with pytest.raises(ProtectedPortError):
        writer.set_vlan_membership(4001, 11, VlanMode.TAGGED)
    assert session.config_commands() == []


def test_failed_command_still_unwinds_the_config_mode_stack() -> None:
    # If a body command is rejected the writer must still back out of interface
    # and global config mode, or every later read would run in the wrong mode.
    class _RejectingSession(_RecordingSession):
        def run(self, command: str) -> str:
            if command.startswith("vlan participation"):
                return "% Invalid input detected at '^' marker."
            return super().run(command)

    sw = VirtualSwitch(_MODEL)
    session = _RejectingSession(sw.cli_session())
    writer = CliWriter(session, get_model(_MODEL))
    writer.create_vlan(4001, "rejected")
    session.commands.clear()
    with pytest.raises(CliCommandError):
        writer.set_vlan_membership(4001, 6, VlanMode.TAGGED)
    assert session.config_commands()[-2:] == ["exit", "exit"]
    # ...and the session really is back in EXEC mode: a fresh read works.
    assert CliReader(session, get_model(_MODEL)).get_pvids()


# --- PVID -------------------------------------------------------------------


def test_set_pvid_sequence_and_verification() -> None:
    writer, sw, session = _writer()
    writer.create_vlan(4001, "pvid")
    session.commands.clear()
    writer.set_pvid(7, 4001)
    assert session.config_commands() == [
        "configure",
        "interface 1/0/7",
        *_general_prelude(_MODEL),
        "vlan pvid 4001",
        "exit",
        "exit",
    ]
    assert sw.state.pvids[7] == 4001


def test_set_pvid_honours_protected_ports() -> None:
    writer, sw, session = _writer(protected_ports=frozenset({7}))
    writer.create_vlan(4001, "pvid")
    before = sw.state.pvids[7]
    session.commands.clear()
    with pytest.raises(ProtectedPortError):
        writer.set_pvid(7, 4001)
    assert session.config_commands() == []
    assert sw.state.pvids[7] == before
    writer.set_pvid(7, 4001, force=True)
    assert sw.state.pvids[7] == 4001


def test_set_pvid_verification_catches_an_ignored_write() -> None:
    class _DroppingSession(_RecordingSession):
        def run(self, command: str) -> str:
            if command.startswith("vlan pvid"):
                return ""
            return super().run(command)

    sw = VirtualSwitch(_MODEL)
    session = _DroppingSession(sw.cli_session())
    writer = CliWriter(session, get_model(_MODEL))
    writer.create_vlan(4001, "pvid")
    with pytest.raises(WriteVerificationError) as exc:
        writer.set_pvid(8, 4001)
    assert exc.value.after == sw.state.pvids[8]


# --- the mock's state really is shared by every face ------------------------


class _StateSnmpClient:
    """In-memory SnmpClient answering from a ``VirtualSwitchState.oid_map()``.

    Same helper shape as tests/virtual/test_cli_cross_backend.py: it re-projects
    the state on every call, so it observes CLI-driven mutations.
    """

    def __init__(self, state: object) -> None:
        self._state = state

    def _scan(self, base: str) -> list[SnmpRow]:
        rows: list[SnmpRow] = []
        for oid, (typ, val) in self._state.oid_map().items():  # type: ignore[attr-defined]
            if oid == base or oid.startswith(base + "."):
                rows.append(SnmpRow(oid, val, typ))
        return rows

    def get(self, oids: list[str]) -> list[SnmpRow]:
        return [row for oid in oids for row in self._scan(oid)]

    def walk(self, base_oid: str) -> list[SnmpRow]:
        return self._scan(base_oid)


def test_cli_write_is_visible_over_snmp_and_http_on_the_same_mock() -> None:
    # Requirement of the mock, not of the writer: a CLI config command mutates
    # the ONE authoritative VirtualSwitchState, so the switch's other protocol
    # faces report the change too -- exactly as on real hardware.
    writer, sw, _session = _writer()
    writer.create_vlan(4001, "shared")
    writer.set_vlan_membership(4001, 12, VlanMode.TAGGED)
    writer.set_pvid(12, 4001)

    snmp = SnmpReader(_StateSnmpClient(sw.state), get_model(_MODEL))
    snmp_vlan = {v.vlan_id: v for v in snmp.get_vlans()}[4001]
    assert snmp_vlan.name == "shared"
    assert 12 in snmp_vlan.tagged_ports
    assert dict(snmp.get_pvids())[12] == 4001

    # And the web UI's VLAN page (a pure renderer over the same state) lists it.
    assert "4001" in web_gsm7252ps.render_vlans(sw.state)


def test_cli_delete_resets_pvids_pointing_at_the_deleted_vlan() -> None:
    # Device coherence in the mock: no port may be left with its PVID pointing at
    # a VLAN that no longer exists.
    writer, sw, _session = _writer()
    writer.create_vlan(4001, "temp")
    writer.set_pvid(9, 4001)
    writer.delete_vlan(4001)
    assert sw.state.pvids[9] == 1


# --- facade wiring ----------------------------------------------------------


def test_facade_builds_a_real_cli_writer_for_a_cli_backend() -> None:
    # SyncSwitch._writer_for used to raise "has no CLI write backend" here.
    sw = VirtualSwitch(_MODEL)
    switch = SyncSwitch(get_model(_MODEL), "10.1.5.22", cli_client=sw.cli_session())
    writer = switch._writer_for(Backend.SSH)  # facade internals, on purpose
    assert isinstance(writer, CliWriter)
    # ...and it is a WORKING writer over the injected session, not a stub.
    writer.create_vlan(4001, "facade")
    assert sw.state.vlans[4001].name == "facade"


def test_facade_cli_writer_carries_protected_ports() -> None:
    sw = VirtualSwitch(_MODEL)
    switch = SyncSwitch(
        get_model(_MODEL),
        "10.1.5.22",
        cli_client=sw.cli_session(),
        protected_ports=frozenset({11}),
    )
    writer = switch._writer_for(Backend.SSH)  # facade internals, on purpose
    assert isinstance(writer, CliWriter)
    with pytest.raises(ProtectedPortError):
        writer.set_vlan_membership(90, 11, VlanMode.TAGGED)


def test_facade_refuses_a_cli_writer_for_a_model_without_a_cli_backend() -> None:
    # gs305ep is NSDP+HTTP: no CLI backend at all, so cli_spec refuses.
    switch = SyncSwitch(get_model("gs305ep"), "10.1.5.30")
    with pytest.raises(UnsupportedCapabilityError):
        switch._writer_for(Backend.SSH)  # facade internals, on purpose


def test_cli_writer_offers_the_same_ops_as_the_other_writers() -> None:
    # CLAUDE.md principle 2: a caller picks the backend, so the CLI backend must
    # expose the SAME write surface as SnmpWriter/HttpWriter -- checked as a
    # signature-level parity assertion so a future op added to one writer and not
    # the other is caught here.
    from netgear_switch.http_write import HttpWriter
    from netgear_switch.snmp_write import SnmpWriter

    ops = {
        "set_poe",
        "cycle_poe",
        "clear_poe_fault",
        "set_port_enabled",
        "set_pvid",
        "set_vlan_membership",
        "create_vlan",
        "delete_vlan",
        "set_mgmt_ip",
    }
    for op in ops:
        assert callable(getattr(CliWriter, op)), op
        assert callable(getattr(SnmpWriter, op)), op
        assert callable(getattr(HttpWriter, op)), op
    # reboot is offered by the HTTP and CLI backends (SNMP has no reboot OID in
    # this library); the CLI one must exist so a caller can choose the CLI.
    assert callable(CliWriter.reboot)
    assert callable(HttpWriter.reboot)


# --- PoE over the CLI -------------------------------------------------------


def test_set_poe_off_and_on_verify_through_show_poe() -> None:
    # "poe" / "no poe" in interface config mode (probed live on all three
    # PoE-capable models). Verification reads the Status column, which reports
    # "Disabled" for an admin-off port -- the only admin signal this command has.
    writer, sw, session = _writer("m4300-16x")
    assert sw.state.poe[11].admin is True
    writer.set_poe(11, False, force=True)
    assert session.config_commands() == [
        "configure",
        "interface 1/0/11",
        "no poe",
        "exit",
        "exit",
    ]
    assert sw.state.poe[11].admin is False
    session.commands.clear()
    # Re-enabling needs the POLLED read-back: the mock reproduces the hardware's
    # one-read status lag (see PoeSim.cli_status_lag_reads), so a writer that
    # verified with a single immediate read would report this working write as a
    # failure -- which is exactly what happened live on 10.1.5.20.
    writer.set_poe(11, True, sleep=lambda _s: None, clock=_fake_clock())
    assert session.config_commands()[2] == "poe"
    assert sw.state.poe[11].admin is True


def test_mock_reproduces_the_poe_status_lag_measured_live() -> None:
    # Pins the hardware finding itself (M4300-16X 10.1.5.20, FASTPATH 12.0.19.15,
    # 2026-07-30): immediately after "poe" re-enables a port, "show poe port info
    # all" still says Disabled; a later read shows Searching/Delivering.
    sw = VirtualSwitch("m4300-16x")
    reader = CliReader(sw.cli_session(), get_model("m4300-16x"))
    sw.state.apply_poe_admin(11, on=False)
    sw.state.apply_poe_admin(11, on=True)
    first = {p.port: p for p in reader.get_poe()}[11]
    second = {p.port: p for p in reader.get_poe()}[11]
    assert first.admin_enabled is False  # stale "Disabled", as on hardware
    assert second.admin_enabled is True  # caught up on the next read


def test_set_poe_off_honours_protected_ports() -> None:
    writer, sw, session = _writer("m4300-16x", protected_ports=frozenset({11}))
    with pytest.raises(ProtectedPortError):
        writer.set_poe(11, False)
    assert session.config_commands() == []
    assert sw.state.poe[11].admin is True
    # Enabling PoE is not disruptive, so it needs no force.
    writer.set_poe(11, True, sleep=lambda _s: None, clock=_fake_clock())


def test_poe_ops_refused_on_a_model_with_no_pse_ports() -> None:
    # The M4300-24X has no PoE hardware and its firmware has no "poe" command at
    # all -- probed live on 10.1.5.13: `poe ?` -> "% Unrecognized command". That
    # is a hardware fact quoted from the device, not a CLI-backend gap.
    writer, _sw, session = _writer("m4300-24x")
    with pytest.raises(UnsupportedCapabilityError) as exc:
        writer.set_poe(1, False, force=True)
    assert "no PSE ports" in str(exc.value)
    assert session.config_commands() == []
    # ...and the mock rejects the command itself, exactly as the device does.
    assert session.run("configure") == ""
    assert session.run("interface 1/0/1") == ""
    assert session.run("poe") != ""


def test_cycle_poe_resets_and_polls_until_delivering() -> None:
    # "poe reset" is the device's own atomic re-arm (probed on all three PoE
    # models). Port 11 of the m4300-16x seed draws real power, so detection
    # settles back to delivering.
    writer, sw, session = _writer("m4300-16x")
    assert sw.state.poe[11].power_mw
    sw.state.poe[11].detect = 4  # faulted
    writer.cycle_poe(11, force=True, sleep=lambda _s: None, clock=_fake_clock())
    assert session.config_commands() == [
        "configure",
        "interface 1/0/11",
        "poe reset",
        "exit",
        "exit",
    ]
    assert sw.state.poe[11].detect == 3


def test_cycle_poe_times_out_on_a_port_with_no_powered_device() -> None:
    # Faithful mock behaviour: a reset does NOT conjure a PD onto an empty port,
    # so the port returns to Searching and cycle_poe (which waits for
    # "delivering") must FAIL rather than silently report success.
    writer, sw, _session = _writer("m4300-16x")
    empty = next(p for p, s in sw.state.poe.items() if not s.power_mw)
    with pytest.raises(WriteVerificationError):
        writer.cycle_poe(
            empty,
            force=True,
            timeouts=PoeCycleTimeouts(
                off_timeout=0.0, on_timeout=0.0, poll_interval=0.0
            ),
            sleep=lambda _s: None,
            clock=_fake_clock(),
        )


def test_clear_poe_fault_accepts_searching_as_recovery() -> None:
    # Same command, weaker recovery predicate (detect has LEFT fault), matching
    # SnmpWriter.clear_poe_fault -- so an empty port clears successfully.
    writer, sw, _session = _writer("gsm7228ps")
    faulted = next(p for p, s in sw.state.poe.items() if s.detect == 4)
    writer.clear_poe_fault(
        faulted, force=True, sleep=lambda _s: None, clock=_fake_clock()
    )
    assert sw.state.poe[faulted].detect in (2, 3)


# --- port admin state -------------------------------------------------------


def test_set_port_enabled_uses_shutdown_and_verifies() -> None:
    writer, sw, session = _writer()
    writer.set_port_enabled(6, False, force=True)
    assert session.config_commands() == [
        "configure",
        "interface 1/0/6",
        "shutdown",
        "exit",
        "exit",
    ]
    assert sw.state.ports[6].admin is False
    session.commands.clear()
    writer.set_port_enabled(6, True)
    assert session.config_commands()[2] == "no shutdown"
    assert sw.state.ports[6].admin is True


def test_set_port_disable_honours_protected_ports() -> None:
    writer, sw, session = _writer(protected_ports=frozenset({6}))
    with pytest.raises(ProtectedPortError):
        writer.set_port_enabled(6, False)
    assert session.config_commands() == []
    assert sw.state.ports[6].admin is True


# --- management IP: two per-model dialects ----------------------------------


def test_set_mgmt_ip_uses_network_parms_on_the_older_images() -> None:
    # gsm7252ps / gsm7228ps: ONE privileged-EXEC command (probed live:
    # "network parms 10.1.5.22 255.255.255.0 ?" -> <cr>|<gateway>).
    for model_key in ("gsm7252ps", "gsm7228ps"):
        writer, sw, session = _writer(model_key)
        writer.set_mgmt_ip("10.9.9.9", "255.255.255.0", "10.9.9.1", force=True)
        assert session.config_commands() == [
            "network parms 10.9.9.9 255.255.255.0 10.9.9.1"
        ]
        assert sw.state.mgmt.address == "10.9.9.9"
        assert sw.state.mgmt.gateway == "10.9.9.1"


def test_set_mgmt_ip_uses_ip_management_on_the_m4300_images() -> None:
    # M4300 12.0.x has NO "network parms" (probed live: "% Unrecognized command"
    # in both EXEC and Config mode) and takes two global-config commands.
    for model_key in ("m4300-24x", "m4300-16x"):
        writer, sw, session = _writer(model_key)
        writer.set_mgmt_ip("10.9.9.9", "255.255.255.0", "10.9.9.1", force=True)
        assert session.config_commands() == [
            "configure",
            "ip management address 10.9.9.9 255.255.255.0",
            "ip default-gateway 10.9.9.1",
            "exit",
        ]
        assert sw.state.mgmt.address == "10.9.9.9"
        assert sw.state.mgmt.gateway == "10.9.9.1"


def test_mock_rejects_the_wrong_mgmt_ip_dialect_per_model() -> None:
    # The mock must reject what the device rejects, per firmware family --
    # otherwise a spec with the wrong dialect would still "work" in tests.
    m4300 = _RecordingSession(VirtualSwitch("m4300-24x").cli_session())
    assert m4300.run("enable") == ""
    assert m4300.run("network parms 10.9.9.9 255.255.255.0 10.9.9.1") != ""
    old = _RecordingSession(VirtualSwitch("gsm7252ps").cli_session())
    assert old.run("configure") == ""
    assert old.run("ip management address 10.9.9.9 255.255.255.0") != ""


def test_set_mgmt_ip_requires_force() -> None:
    writer, _sw, session = _writer()
    with pytest.raises(ProtectedPortError):
        writer.set_mgmt_ip("10.9.9.9", "255.255.255.0", "10.9.9.1")
    assert session.config_commands() == []


# --- reboot -----------------------------------------------------------------


def test_reboot_issues_reload_with_its_confirm() -> None:
    # "reload ?" -> <cr>|<unit> on all four models. It cannot be verified by
    # reading back (the switch stops answering), so the mock records the request.
    sw = VirtualSwitch(_MODEL)
    writer = CliWriter(sw.cli_session(), get_model(_MODEL))
    writer.reboot(force=True)
    assert sw.state.reboots == 1
    # A reload must NOT be recorded as a config save.
    assert sw.state.scp_cert_deploy is None


def test_reboot_requires_force() -> None:
    sw = VirtualSwitch(_MODEL)
    writer = CliWriter(sw.cli_session(), get_model(_MODEL))
    with pytest.raises(ProtectedPortError):
        writer.reboot()
    assert sw.state.reboots == 0


def test_async_facade_has_no_cli_write_backend_and_says_why() -> None:
    from netgear_switch.aio_api import AsyncSwitch

    switch = AsyncSwitch(get_model(_MODEL), "10.1.5.22")
    with pytest.raises(UnsupportedCapabilityError) as exc:
        switch._writer_for(Backend.SSH)  # facade internals, on purpose
    # Honest reason: a CLI writer EXISTS, it is just synchronous-only.
    assert "synchronous" in str(exc.value)
