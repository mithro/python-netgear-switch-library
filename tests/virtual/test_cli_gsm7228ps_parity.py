"""Cross-backend parity for the S3300-52X (gsm7228ps) telnet CLI mock face.

The gsm7228ps CLI face and SNMP face of ONE ``VirtualSwitch`` (driven from a
single shared seed) must report the SAME data for every op both serve -- exactly
like ``test_cli_cross_backend.py`` does for the gsm7252ps, but here proving the
Smart-firmware ``1/gN``/``1/xgN`` port-name path (mock renderer + parser fix)
round-trips end to end. Both readers observe one identical device state without a
socket: the CLI reader over the in-process mock CLI face, the SNMP reader over an
in-memory client answering from the state's own ``oid_map()``.

Only the fields BOTH interfaces expose are compared (see the gsm7252ps test for
the rationale): ports on ``(admin, link, speed-when-up)`` for physical ports;
VLANs on name + physical member/tagged sets (the SNMP untagged bitmap and the
lag-ifIndex members ``show vlan`` cannot express are excluded); PoE on
``(admin, power_mw, delivering)``. Sensors are NOT cross-compared (the two
hardware interfaces expose different sensor sets, as documented elsewhere).
"""

from __future__ import annotations

from netgear_switch.cli_read import CliReader
from netgear_switch.protocols.snmp.client import SnmpRow
from netgear_switch.registry import get_model
from netgear_switch.snmp_read import SnmpReader
from netgear_switch.virtual.server import VirtualSwitch

_MODEL = "gsm7228ps"
_PHYS = set(range(1, 53))  # 48 gigabit + 4 10G uplinks


class _StateSnmpClient:
    """In-memory SnmpClient answering from a ``VirtualSwitchState.oid_map()``."""

    def __init__(self, state: object) -> None:
        self._map: dict[str, tuple[str, str]] = state.oid_map()  # type: ignore[attr-defined]

    def _scan(self, base: str) -> list[SnmpRow]:
        return [
            SnmpRow(oid, val, typ)
            for oid, (typ, val) in self._map.items()
            if oid == base or oid.startswith(base + ".")
        ]

    def get(self, oids: list[str]) -> list[SnmpRow]:
        return [row for oid in oids for row in self._scan(oid)]

    def walk(self, base_oid: str) -> list[SnmpRow]:
        return self._scan(base_oid)


def _readers() -> tuple[CliReader, SnmpReader]:
    sw = VirtualSwitch(_MODEL)
    model = get_model(_MODEL)
    cli = CliReader(sw.cli_session(), model)
    snmp = SnmpReader(_StateSnmpClient(sw.state), model)
    return cli, snmp


def test_mock_cli_renders_smart_firmware_port_names() -> None:
    sess = VirtualSwitch(_MODEL).cli_session()
    port_all = sess.run("show port all")
    assert "1/g1" in port_all
    assert "1/xg49" in port_all
    assert "1/0/" not in port_all  # Smart firmware never prints 1/0/N


def test_ports_agree_on_physical_ports() -> None:
    cli, snmp = _readers()

    def proj(p: object) -> tuple:
        return (
            p.admin_enabled,  # type: ignore[attr-defined]
            p.link_up,  # type: ignore[attr-defined]
            p.speed_mbps if p.link_up else None,  # type: ignore[attr-defined]
        )

    cli_p = {p.port: proj(p) for p in cli.get_ports() if p.port in _PHYS}
    snmp_p = {p.port: proj(p) for p in snmp.get_ports() if p.port in _PHYS}
    assert cli_p == snmp_p
    assert len(cli_p) == 52


def test_pvids_agree() -> None:
    cli, snmp = _readers()
    assert dict(cli.get_pvids()) == dict(snmp.get_pvids())


def test_vlans_agree_on_physical_membership() -> None:
    cli, snmp = _readers()

    def proj(reader: CliReader | SnmpReader) -> dict[int, tuple]:
        return {
            v.vlan_id: (
                v.name,
                frozenset(v.member_ports & _PHYS),
                frozenset(v.tagged_ports & _PHYS),
            )
            for v in reader.get_vlans()
        }

    assert proj(cli) == proj(snmp)


def test_poe_agrees_on_admin_power_delivering() -> None:
    cli, snmp = _readers()
    cli_p = {p.port: (p.admin_enabled, p.power_mw, p.delivering) for p in cli.get_poe()}
    snmp_p = {
        p.port: (p.admin_enabled, p.power_mw, p.delivering) for p in snmp.get_poe()
    }
    assert cli_p == snmp_p
    assert len(cli_p) == 48


def test_macs_agree() -> None:
    cli, snmp = _readers()
    cli_m = {(m.mac, m.port, m.vlan_id) for m in cli.get_macs()}
    snmp_m = {(m.mac, m.port, m.vlan_id) for m in snmp.get_macs()}
    assert cli_m == snmp_m


def test_mgmt_ip_agrees() -> None:
    cli, snmp = _readers()
    assert cli.get_mgmt_ip() == snmp.get_mgmt_ip()


def test_stats_agree_on_physical_ports() -> None:
    cli, snmp = _readers()
    cli_s = {s.port: s for s in cli.get_stats() if s.port in _PHYS}
    snmp_s = {s.port: s for s in snmp.get_stats() if s.port in _PHYS}
    assert cli_s == snmp_s
    assert len(cli_s) == 52


def test_identify_returns_none_no_sysobjectid_over_cli() -> None:
    # HONEST divergence: the S3300's sysDescr text is deliberately unmatchable
    # (same shape as the unregistered S3300-28X); it is auto-detected only via
    # the SNMP sysObjectID, which the CLI has no equivalent of. So a CLI-only
    # identify legitimately returns None rather than fabricating a match.
    cli, _ = _readers()
    assert cli.identify().key is None
