"""Pure output formatting for ngsw: JSON and human-readable tables.

Every function is a pure ``model object(s) -> str`` map (except ``emit``, which
prints), so the whole module is unit-testable without a switch or network.
"""

from __future__ import annotations

import dataclasses
import enum
import json
from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from netgear_switch.models import (
        DetectedModel,
        LLDPNeighbor,
        MacEntry,
        MgmtIpConfig,
        PoEStatus,
        PortStats,
        PortStatus,
        Sensor,
        SwitchData,
        VLANInfo,
    )
    from netgear_switch.protocols.nsdp.types import NsdpDevice

    from .context import CliContext

T = TypeVar("T")


def jsonify(obj: object) -> object:
    """Recursively convert dataclasses / enums / sets into JSON-native values."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: jsonify(getattr(obj, f.name)) for f in dataclasses.fields(obj)}
    if isinstance(obj, enum.Enum):
        return obj.value
    if isinstance(obj, set | frozenset):
        return sorted(obj)
    if isinstance(obj, list | tuple):
        return [jsonify(x) for x in obj]
    return obj


def to_json(obj: object) -> str:
    return json.dumps(jsonify(obj), indent=2)


def emit(ctx: CliContext, obj: T, table_fn: Callable[[T], str]) -> None:
    """Print ``obj`` as JSON (when ``ctx.as_json``) or via ``table_fn``."""
    print(to_json(obj) if ctx.as_json else table_fn(obj), file=ctx.out)


def _table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def render(cells: Sequence[str]) -> str:
        return "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(cells))

    return "\n".join([render(headers), *(render(r) for r in rows)])


def _ports(port_set: frozenset[int]) -> str:
    return ",".join(str(p) for p in sorted(port_set)) or "-"


def ports_table(ports: Sequence[PortStatus]) -> str:
    rows = [
        [
            str(p.port),
            p.name or "-",
            "up" if p.link_up else "down",
            "enabled" if p.admin_enabled else "disabled",
            "-" if p.speed_mbps is None else str(p.speed_mbps),
            p.description or "-",
        ]
        for p in ports
    ]
    return _table(("Port", "Name", "Link", "Admin", "Speed", "Description"), rows)


def poe_table(entries: Sequence[PoEStatus]) -> str:
    rows = [
        [
            str(e.port),
            "enabled" if e.admin_enabled else "disabled",
            e.detect.value,
            "-" if e.power_mw is None else str(e.power_mw),
        ]
        for e in entries
    ]
    return _table(("Port", "Admin", "Detect", "Power(mW)"), rows)


def vlans_table(vlans: Sequence[VLANInfo]) -> str:
    rows = [
        [
            str(v.vlan_id),
            v.name or "-",
            _ports(v.untagged_ports),
            _ports(v.tagged_ports),
        ]
        for v in vlans
    ]
    return _table(("VLAN", "Name", "Untagged", "Tagged"), rows)


def pvids_table(pvids: Sequence[tuple[int, int]]) -> str:
    rows = [[str(port), str(vlan)] for port, vlan in pvids]
    return _table(("Port", "PVID"), rows)


def lldp_table(neighbors: Sequence[LLDPNeighbor]) -> str:
    rows = [
        [
            str(n.local_port),
            n.remote_sys_name or "-",
            n.remote_port_id or "-",
            n.remote_port_desc or "-",
            n.remote_chassis_id or "-",
        ]
        for n in neighbors
    ]
    return _table(
        ("Port", "Neighbor", "RemotePortId", "RemotePortDesc", "ChassisID"), rows
    )


def macs_table(entries: Sequence[MacEntry]) -> str:
    rows = [
        [e.mac, str(e.port), "-" if e.vlan_id is None else str(e.vlan_id)]
        for e in entries
    ]
    return _table(("MAC", "Port", "VLAN"), rows)


def stats_table(stats: Sequence[PortStats]) -> str:
    def cell(value: int | None) -> str:
        return "-" if value is None else str(value)

    rows = [
        [
            str(s.port),
            cell(s.rx_bytes),
            cell(s.tx_bytes),
            cell(s.rx_packets),
            cell(s.tx_packets),
            cell(s.rx_errors),
            cell(s.tx_errors),
        ]
        for s in stats
    ]
    headers = (
        "Port",
        "RxBytes",
        "TxBytes",
        "RxPackets",
        "TxPackets",
        "RxErrors",
        "TxErrors",
    )
    return _table(headers, rows)


def sensors_table(sensors: Sequence[Sensor]) -> str:
    rows = [[s.name, s.kind, f"{s.value:g}", s.unit] for s in sensors]
    return _table(("Sensor", "Kind", "Value", "Unit"), rows)


def detected_model_text(detected: DetectedModel) -> str:
    """Render an SNMP model-detection result. ``key`` is ``None`` (shown as
    ``(unmatched)``) when the sysDescr matched no registered model -- never a
    fabricated guess (see ``models.DetectedModel``)."""
    return "\n".join(
        [
            f"key:           {detected.key or '(unmatched)'}",
            f"sys_descr:     {detected.sys_descr or '-'}",
            f"sys_object_id: {detected.sys_object_id or '-'}",
        ]
    )


def nsdp_device_text(device: NsdpDevice) -> str:
    """Render the headline fields of a raw NSDP device record. The full record
    (per-port status/statistics, VLANs, QoS, etc.) is available via ``--json``."""
    return "\n".join(
        [
            f"model:    {device.model}",
            f"mac:      {device.mac}",
            f"hostname: {device.hostname or '-'}",
            f"ip:       {device.ip or '-'}",
            f"netmask:  {device.netmask or '-'}",
            f"gateway:  {device.gateway or '-'}",
            f"firmware: {device.firmware_version or '-'}",
            f"serial:   {device.serial_number or '-'}",
            f"ports:    {'-' if device.port_count is None else device.port_count}",
        ]
    )


def mgmt_ip_text(cfg: MgmtIpConfig) -> str:
    return "\n".join(
        [
            f"mode:    {cfg.mode.value}",
            f"address: {cfg.address or '-'}",
            f"netmask: {cfg.netmask or '-'}",
            f"gateway: {cfg.gateway or '-'}",
            f"mac:     {cfg.base_mac or '-'}",
        ]
    )


def snapshot_text(data: SwitchData) -> str:
    sections = [
        f"# {data.model} @ {data.host}",
        "## Ports",
        ports_table(data.ports),
        "## PoE",
        poe_table(data.poe),
        "## VLANs",
        vlans_table(data.vlans),
        "## PVIDs",
        pvids_table(data.pvids),
        "## LLDP",
        lldp_table(data.lldp),
        "## MACs",
        macs_table(data.macs),
        "## Sensors",
        sensors_table(data.sensors),
    ]
    if data.mgmt_ip is not None:
        sections += ["## Mgmt IP", mgmt_ip_text(data.mgmt_ip)]
    return "\n".join(sections)
