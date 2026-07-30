"""Model-driven CLI read operations over a ``CliSession``.

The CLI analogue of ``http_read.py``: dispatches each ``get_*`` op to its
FASTPATH ``show`` command (via ``protocols.cli.commands.cli_spec``) over a
``CliSession`` transport, and parses the returned text with the pure functions
in ``protocols.cli.parse``. Works unchanged against a real SSH/telnet/console
session or the in-process mock face (``virtual.faces.cli.VirtualCliFace``).

Unlike ``HttpReader``, construction is NOT gated on ``reads_verified``: the
reader is always usable directly (mock tests, and a future live-verified flip),
and it is the FACADE that refuses live CLI dispatch while ``reads_verified`` is
False (see ``_dispatch.cli_reads_supported`` / ``SyncSwitch._reader_for``).

Ops a FASTPATH model's CLI genuinely lacks raise ``UnsupportedCapabilityError``
honestly rather than fabricating: ``get_poe`` on the non-PoE M4300-24X (PoE port
count 0) is the only such carve-out -- every other ``show`` command exists on
every FASTPATH switch.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .errors import UnsupportedCapabilityError
from .protocols.cli import parse
from .protocols.cli.commands import cli_spec
from .registry import MODELS

if TYPE_CHECKING:
    from .models import (
        DetectedModel,
        LLDPNeighbor,
        MacEntry,
        MgmtIpConfig,
        PoEStatus,
        PortStats,
        PortStatus,
        Sensor,
        VLANInfo,
    )
    from .registry import SwitchModel
    from .transport.cli.session import CliSession


def _unsupported(model_key: str, op: str) -> UnsupportedCapabilityError:
    return UnsupportedCapabilityError(f"model {model_key!r} CLI does not expose {op}")


class CliReader:
    """Synchronous FASTPATH-CLI read facade over one switch."""

    def __init__(self, session: CliSession, model: SwitchModel) -> None:
        self._spec = cli_spec(model)
        self.session = session
        self.model = model

    def get_ports(self) -> list[PortStatus]:
        return parse.parse_port_status(self.session.run(self._spec.port_status_cmd))

    def get_stats(self) -> list[PortStats]:
        # FASTPATH has no "all ports" octet-counter command; counters come from
        # a per-port ``show interface ethernet 1/0/<n>``. One round trip per
        # physical port, in port order. Iterate the ACTUAL physical ports the
        # switch reports (``show port all``) rather than ``range(1, port_count+1)``:
        # registry ``port_count`` is a nominal value that can exceed the real
        # physical-port count (e.g. m4300-24x registry port_count=28 but the
        # XSM4324CS has only 24 physical ports), which would otherwise issue
        # doomed queries for phantom ports and fabricate empty PortStats. Deriving
        # the port list from the port table is correct on any switch.
        out: list[PortStats] = []
        for status in self.get_ports():
            text = self.session.run(self._spec.interface_stats(status.port))
            out.append(parse.parse_interface_counters(text, status.port))
        return out

    def get_vlans(self) -> list[VLANInfo]:
        brief = parse.parse_vlan_brief(self.session.run(self._spec.vlan_brief_cmd))
        out: list[VLANInfo] = []
        for vid, name in brief:
            detail = self.session.run(self._spec.vlan_detail(vid))
            out.append(parse.parse_vlan_detail(detail, name=name))
        return out

    def get_pvids(self) -> list[tuple[int, int]]:
        return parse.parse_pvids(self.session.run(self._spec.pvid_cmd))

    def get_macs(self) -> list[MacEntry]:
        if not self.model.has_mac_table:
            raise _unsupported(self.model.key, "a MAC/FDB table")
        return parse.parse_mac_table(self.session.run(self._spec.mac_table_cmd))

    def get_lldp(self) -> list[LLDPNeighbor]:
        return parse.parse_lldp(self.session.run(self._spec.lldp_cmd))

    def get_poe(self) -> list[PoEStatus]:
        if self.model.poe_port_count == 0:
            raise _unsupported(self.model.key, "PoE (model has no PSE ports)")
        return parse.parse_poe(self.session.run(self._spec.poe_cmd))

    def get_sensors(self) -> list[Sensor]:
        return parse.parse_environment(self.session.run(self._spec.environment_cmd))

    def get_mgmt_ip(self) -> MgmtIpConfig:
        return parse.parse_mgmt_ip(self.session.run(self._spec.network_cmd))

    def identify(self) -> DetectedModel:
        return parse.parse_version(self.session.run(self._spec.version_cmd), MODELS)
