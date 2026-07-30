"""CliReader over the in-process mock CLI face, plus the CLI command spec, the
shared ShellDriver, the SSH legacy-algorithm helper, and the facade's CLI gate.
"""

from __future__ import annotations

import pytest

from netgear_switch.cli_read import CliReader
from netgear_switch.errors import UnsupportedCapabilityError
from netgear_switch.models import IpMode, PoEDetect
from netgear_switch.protocols.cli.commands import CLI_SPECS, cli_spec
from netgear_switch.registry import Backend, get_model
from netgear_switch.transport.cli.session import CliTransportError, ShellDriver
from netgear_switch.virtual.server import VirtualSwitch


def _reader(model_key: str) -> CliReader:
    sw = VirtualSwitch(model_key)
    return CliReader(sw.cli_session(), get_model(model_key))


# --- CliReader over the mock face ------------------------------------------


def test_cli_reader_ports() -> None:
    ports = {p.port: p for p in _reader("gsm7252ps").get_ports()}
    assert len(ports) == 52
    assert ports[1].link_up is True
    assert ports[1].speed_mbps == 1000
    assert ports[6].link_up is False


def test_cli_reader_pvids() -> None:
    pvids = dict(_reader("gsm7252ps").get_pvids())
    assert pvids[45] == 20
    assert pvids[1] == 90


def test_cli_reader_vlans() -> None:
    vlans = {v.vlan_id: v for v in _reader("gsm7252ps").get_vlans()}
    assert set(vlans) == {1, 4, 5, 6, 7, 10, 20, 21, 41, 89, 90, 99, 121, 141}
    assert vlans[90].name == "iot"
    assert 11 in vlans[90].member_ports


def test_cli_reader_poe() -> None:
    poe = {p.port: p for p in _reader("gsm7252ps").get_poe()}
    assert poe[1].detect is PoEDetect.DELIVERING
    assert poe[1].power_mw == 3500


def test_cli_reader_macs_use_mapped_ifindex() -> None:
    macs = _reader("gsm7252ps").get_macs()
    by_mac = {m.mac: m for m in macs}
    assert by_mac["C8:00:84:89:71:70"].port == 110  # bridge-port 10 -> ifIndex 110
    assert by_mac["00:1B:21:3C:4D:5E"].port == 11


def test_cli_reader_lldp() -> None:
    lldp = _reader("gsm7252ps").get_lldp()
    assert lldp[0].local_port == 49
    assert lldp[0].remote_sys_name == "sw-cisco-shed"


def test_cli_reader_mgmt_ip() -> None:
    mgmt = _reader("gsm7252ps").get_mgmt_ip()
    assert mgmt.address == "10.1.5.22"
    assert mgmt.base_mac == "E0:91:F5:0C:D6:DB"
    assert mgmt.mode is IpMode.STATIC  # seed mgmt.mode == "static"


def test_cli_reader_sensors_nonempty() -> None:
    sensors = _reader("gsm7252ps").get_sensors()
    assert sensors  # fan + PSU rows from the seed's SNMP sensor set
    assert {s.kind for s in sensors} <= {"temperature", "fan", "power"}


def test_cli_reader_stats() -> None:
    stats = {s.port: s for s in _reader("gsm7252ps").get_stats()}
    assert len(stats) == 52
    assert stats[1].rx_bytes == 45747246  # seed rx_octets for port 1


def test_cli_reader_identify() -> None:
    assert _reader("gsm7252ps").identify().key == "gsm7252ps"


def test_cli_reader_m4300_uses_overridden_commands() -> None:
    # The M4300 reader drives "show vlan" / "show ip management"; the mock face
    # is spec-driven, so these route to the same renderers and round-trip.
    reader = _reader("m4300-24x")
    vlans = {v.vlan_id for v in reader.get_vlans()}
    assert vlans  # non-empty -> "show vlan" dispatched and parsed
    assert reader.get_mgmt_ip().address  # "show ip management" dispatched


def test_cli_reader_m4300_stats_only_physical_ports() -> None:
    # m4300-24x registry port_count is 28 but the switch has 24 physical ports.
    # get_stats must iterate the real ports (24), never phantom ports 25-28.
    reader = _reader("m4300-24x")
    n_ports = len(reader.get_ports())
    stats = reader.get_stats()
    assert n_ports == 24
    assert len(stats) == 24
    assert {s.port for s in stats} == {p.port for p in reader.get_ports()}
    assert max(s.port for s in stats) == 24  # no phantom 25-28


def test_cli_reader_poe_unsupported_on_non_poe_model() -> None:
    with pytest.raises(UnsupportedCapabilityError):
        _reader("m4300-24x").get_poe()  # M4300-24X has 0 PSE ports


def test_cli_reader_works_for_every_fastpath_model() -> None:
    # gsm7228ps (S3300-52X) is NOT here: it has no functional CLI (SSH absent,
    # telnet enabled-but-never-listens -- live-verified 2026-07-30), so no CLI
    # backend and no CLI spec.
    for key in ("gsm7252ps", "m4300-24x", "m4300-16x"):
        assert _reader(key).get_ports()  # command dispatch + parse round trip


def test_mock_face_rejects_unknown_command() -> None:
    sess = VirtualSwitch("gsm7252ps").cli_session()
    assert "Command not found" in sess.run("show nonsense")


# --- command spec + registry ------------------------------------------------


def test_cli_reads_verified_only_for_live_checked_models() -> None:
    assert CLI_SPECS  # non-empty
    # gsm7252ps (10.1.5.22, CLI<->SNMP), m4300-24x (10.1.5.13) and m4300-16x
    # (10.1.5.20) were all cross-verified against real hardware, so their reads
    # are verified. These are the ONLY CLI models: gsm7228ps (S3300-52X) has no
    # functional CLI (live-verified 2026-07-30) and so has no CLI spec at all.
    verified = {"gsm7252ps", "m4300-24x", "m4300-16x"}
    assert set(CLI_SPECS) == verified
    assert {k for k, s in CLI_SPECS.items() if s.reads_verified} == verified
    # The live-captured models carry real transcripts.
    assert {k for k, s in CLI_SPECS.items() if s.captured} == verified


def test_m4300_cli_command_overrides() -> None:
    # FASTPATH 12.0 renamed two commands; both M4300 specs carry the overrides,
    # while the older-image SKUs keep the defaults.
    for key in ("m4300-24x", "m4300-16x"):
        assert CLI_SPECS[key].vlan_brief_cmd == "show vlan"
        assert CLI_SPECS[key].network_cmd == "show ip management"
    # gsm7252ps keeps the older-image defaults (gsm7228ps has no CLI spec).
    assert CLI_SPECS["gsm7252ps"].vlan_brief_cmd == "show vlan brief"
    assert CLI_SPECS["gsm7252ps"].network_cmd == "show network"


def test_cli_spec_raises_for_non_cli_model() -> None:
    with pytest.raises(UnsupportedCapabilityError):
        cli_spec(get_model("gs110emx"))  # Plus switch: no CLI backend


@pytest.mark.parametrize("key", ["gsm7252ps", "m4300-24x", "m4300-16x"])
def test_fastpath_models_register_ssh_and_telnet(key: str) -> None:
    backends = get_model(key).backends
    assert Backend.SSH in backends
    assert Backend.TELNET in backends


def test_s3300_gsm7228ps_has_no_cli_backend() -> None:
    # The S3300-52X exposes no functional CLI (SSH absent; telnet enabled but
    # never listens -- live-verified 2026-07-30 incl. a reboot), so unlike the
    # FASTPATH SKUs above it declares NEITHER SSH nor TELNET; its CLI pathway is
    # consistently UnsupportedCapabilityError across the library and the mock.
    backends = get_model("gsm7228ps").backends
    assert Backend.SSH not in backends
    assert Backend.TELNET not in backends


def test_plus_models_have_no_cli_backend() -> None:
    for key in ("gs110emx", "gs105pe", "gs305ep"):
        backends = get_model(key).backends
        assert Backend.SSH not in backends
        assert Backend.TELNET not in backends


# --- facade gate: CLI reads/writes refused while reads_verified is False -----


def test_sync_facade_refuses_cli_backend() -> None:
    from netgear_switch.sync_api import SyncSwitch

    # gsm7228ps (S3300-52X) has NO CLI backend (no functional CLI on the real
    # switch), so the facade must refuse any CLI read/write dispatch to it.
    sw = SyncSwitch(get_model("gsm7228ps"), "10.0.0.1")
    with pytest.raises(UnsupportedCapabilityError):
        sw._reader_for(Backend.SSH)
    with pytest.raises(UnsupportedCapabilityError):
        sw._writer_for(Backend.SSH)


def test_async_facade_refuses_cli_backend() -> None:
    from netgear_switch.aio_api import AsyncSwitch

    sw = AsyncSwitch(get_model("gsm7228ps"), "10.0.0.1")
    with pytest.raises(UnsupportedCapabilityError):
        sw._reader_for(Backend.SSH)
    with pytest.raises(UnsupportedCapabilityError):
        sw._writer_for(Backend.SSH)


# --- shared ShellDriver (transport byte-framing) ----------------------------


class _FakeChannel:
    """A scripted send/recv channel for driving ShellDriver without a socket."""

    def __init__(self, responses: list[bytes]) -> None:
        self._responses = list(responses)
        self.sent: list[bytes] = []

    def send(self, data: bytes) -> None:
        self.sent.append(data)

    def recv(self, _n: int) -> bytes:
        return self._responses.pop(0) if self._responses else b""


def _driver(responses: list[bytes]) -> tuple[ShellDriver, _FakeChannel]:
    ch = _FakeChannel(responses)
    return ShellDriver(ch.send, ch.recv), ch


def test_shell_driver_setup_and_run() -> None:
    drv, ch = _driver(
        [
            b"\r\n(GSM7252PS) #",  # initial prompt
            b"enable\r\n(GSM7252PS) #",  # after enable
            b"terminal length 0\r\n(GSM7252PS) #",  # after paging off
            b"show version\r\nMachine Model.... GSM7252PS\r\n(GSM7252PS) #",
        ]
    )
    drv.setup()
    out = drv.run("show version")
    assert "GSM7252PS" in out
    assert "(GSM7252PS)" not in out  # prompt stripped
    assert out.splitlines()[0].startswith("Machine Model")  # echo line stripped
    # enable + terminal length 0 + show version were all written.
    assert any(b"enable" in s for s in ch.sent)
    assert any(b"terminal length 0" in s for s in ch.sent)


def test_shell_driver_handles_enable_password_prompt() -> None:
    _, ch = _driver(
        [
            b"\r\n(GSM7252PS) >",  # initial prompt (unprivileged)
            b"enable\r\nPassword:",  # enable asks for a password
            b"\r\n(GSM7252PS) #",  # after password -> privileged
            b"terminal length 0\r\n(GSM7252PS) #",
        ]
    )
    drv = ShellDriver(ch.send, ch.recv, enable_password="secret")
    drv.setup()
    assert any(b"secret" in s for s in ch.sent)


def test_shell_driver_raises_without_prompt() -> None:
    drv, _ = _driver([b"garbage with no prompt", b""])
    with pytest.raises(CliTransportError):
        drv.setup()


# --- SSH transport legacy-algorithm helper (no paramiko needed) -------------


class _FakeSecurityOptions:
    def __init__(self) -> None:
        self.kex = ["ecdh-sha2-nistp256", "diffie-hellman-group14-sha1"]
        self.key_types = ["ecdsa-sha2-nistp256", "ssh-rsa"]


class _FakeTransport:
    def __init__(self) -> None:
        self._opts = _FakeSecurityOptions()

    def get_security_options(self) -> _FakeSecurityOptions:
        return self._opts


def test_ssh_prefers_legacy_algorithms() -> None:
    from netgear_switch.transport.cli.ssh import SshCliTransport

    t = _FakeTransport()
    SshCliTransport._prefer_legacy_algorithms(t)
    assert t.get_security_options().kex[0] == "diffie-hellman-group14-sha1"
    assert t.get_security_options().key_types[0] == "ssh-rsa"
