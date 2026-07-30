"""Cross-backend equivalence: the CLI face and the SNMP face of ONE
``VirtualSwitch`` (driven from a single shared ``VirtualSwitchState``) must
report the SAME data for every op both serve.

The CLI reader runs over the in-process mock CLI face; the SNMP reader runs over
an in-memory client answering from the state's own ``oid_map()`` (the same
projection the UDP SNMP face serves), so both observe one identical device
state without standing up net-snmp or a socket.

Only the fields BOTH interfaces expose are compared:
* ``get_ports`` -- the SNMP walk includes the CPU/LAG pseudo-interfaces
  (ifIndex 417/418) that never appear on a ``show port all`` page, so port
  equality is restricted to physical ports and compares ``(admin, link, speed
  when up)`` (SNMP additionally reads ifAlias descriptions the CLI has no column
  for, and reports a DOWN port's configured ``ifHighSpeed`` where
  ``show port all`` blanks a down port's Physical Status -- a real interface
  difference, visible in the fixture's down 10G SFP 1/0/52, so speed is compared
  only for link-up ports).
* ``get_vlans`` -- the SNMP untagged bitmap legitimately lists non-member ports
  (a real hardware quirk preserved in the seed) that ``show vlan <id>`` cannot
  express, so VLAN equality is on name + the member/tagged sets restricted to
  physical egress ports.
* ``get_poe`` -- compared on ``(admin, power_mw, delivering)``; the exact detect
  enum can differ for a non-standard PoE detect code (SNMP UNKNOWN vs the CLI's
  status text) but neither is "delivering" and both agree on admin/power.

``get_stats``/``get_pvids``/``get_macs``/``get_mgmt_ip`` are compared in full for
physical ports -- those DO agree field-for-field. Sensors are deliberately NOT
cross-compared: the two hardware interfaces genuinely expose different sensor
sets (``show environment`` temperatures vs the SNMP fan-RPM/PSU walk), exactly
as the codebase already documents for its HTTP ``http_sensors`` vs ``sensors``.
"""

from __future__ import annotations

from netgear_switch.cli_read import CliReader
from netgear_switch.protocols.snmp.client import SnmpRow
from netgear_switch.registry import get_model
from netgear_switch.snmp_read import SnmpReader
from netgear_switch.virtual.server import VirtualSwitch

_MODEL = "gsm7252ps"
_PHYS = set(range(1, 53))  # 52 physical ports


class _StateSnmpClient:
    """In-memory SnmpClient answering from a ``VirtualSwitchState.oid_map()``."""

    def __init__(self, state: object) -> None:
        self._map: dict[str, tuple[str, str]] = state.oid_map()  # type: ignore[attr-defined]

    def _scan(self, base: str) -> list[SnmpRow]:
        rows: list[SnmpRow] = []
        for oid, (typ, val) in self._map.items():
            if oid == base or oid.startswith(base + "."):
                rows.append(SnmpRow(oid, val, typ))
        return rows

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
        out = {}
        for v in reader.get_vlans():
            out[v.vlan_id] = (
                v.name,
                frozenset(v.member_ports & _PHYS),
                frozenset(v.tagged_ports & _PHYS),
            )
        return out

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


def test_identify_agrees() -> None:
    cli, _ = _readers()
    # SnmpReader identity via read_system_info is exercised elsewhere; here the
    # CLI identify must land on the same registry key.
    assert cli.identify().key == _MODEL
