"""Model-driven web-UI read operations over a sync or async ``HttpSession``.

Parallel to ``snmp_read.py``/``nsdp_read.py``. Construction is gated on
``HttpModelSpec.reads_verified``: a model whose web reads are still
UNVERIFIED-pending-capture (gs110emx Gambit, gsm7228ps cheetah/S3300) refuses
to construct rather than return fabricated data -- the facade never gets a
plausible-but-wrong result from an unverified scrape. Web-UI-impossible ops
(MAC/FDB, box sensors, LLDP, management-IP config) raise
``UnsupportedCapabilityError`` honestly instead of silently returning ``[]``.

All page-path selection and HTML-to-model conversion lives in the
module-level helpers below (pure, I/O-free); ``HttpReader``/``AsyncHttpReader``
differ only in whether ``session.get_page``/``post_form`` is awaited.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from .errors import UnsupportedCapabilityError
from .models import VLANInfo, VlanMode
from .protocols.http import parse
from .protocols.http.endpoints import http_spec

if TYPE_CHECKING:
    from .models import (
        LLDPNeighbor,
        MacEntry,
        MgmtIpConfig,
        PoEStatus,
        PortStats,
        PortStatus,
        Sensor,
    )
    from .protocols.http.endpoints import HttpModelSpec
    from .protocols.http.session import AsyncHttpSession, HttpSession
    from .registry import SwitchModel


def _require_verified_reads(spec: HttpModelSpec) -> None:
    if not spec.reads_verified:
        raise UnsupportedCapabilityError(
            f"model {spec.model_key!r} HTTP reads are UNVERIFIED-pending-capture"
        )


def _unsupported(model_key: str, op: str) -> UnsupportedCapabilityError:
    return UnsupportedCapabilityError(
        f"model {model_key!r} web UI does not expose {op}"
    )


def _require_path(model_key: str, path: str | None, op: str) -> str:
    """Return ``path`` or raise honestly if this model's spec has none for ``op``."""
    if path is None:
        raise _unsupported(model_key, op)
    return path


def _vlan_info(vid: int, membership_html: str, port_count: int) -> VLANInfo:
    """Pure conversion of one 8021qMembe.cgi response into a ``VLANInfo``."""
    states = parse.parse_membership(membership_html, port_count)
    tagged = frozenset(p for p, m in states.items() if m is VlanMode.TAGGED)
    untagged = frozenset(p for p, m in states.items() if m is VlanMode.UNTAGGED)
    return VLANInfo(
        vlan_id=vid,
        name=None,
        member_ports=tagged | untagged,
        tagged_ports=tagged,
        untagged_ports=untagged,
    )


class HttpReader:
    """Synchronous web-UI read facade over one switch."""

    def __init__(self, session: HttpSession, model: SwitchModel) -> None:
        self._spec = http_spec(model)
        _require_verified_reads(self._spec)
        self.session = session
        self.model = model

    def get_ports(self) -> list[PortStatus]:
        path = _require_path(self.model.key, self._spec.dashboard_path, "port status")
        return parse.parse_port_status(self.session.get_page(path))

    def get_stats(self) -> list[PortStats]:
        path = _require_path(self.model.key, self._spec.stats_path, "port statistics")
        return parse.parse_port_stats(self.session.get_page(path))

    def get_poe(self) -> list[PoEStatus]:
        path = _require_path(self.model.key, self._spec.poe_status_path, "PoE status")
        return parse.parse_poe_status(self.session.get_page(path))

    def get_pvids(self) -> list[tuple[int, int]]:
        path = _require_path(self.model.key, self._spec.pvid_path, "port PVIDs")
        return parse.parse_pvids(self.session.get_page(path))

    def get_vlans(self) -> list[VLANInfo]:
        cfg_path = _require_path(
            self.model.key, self._spec.vlan_config_path, "VLAN configuration"
        )
        member_path = _require_path(
            self.model.key, self._spec.vlan_membership_path, "VLAN membership"
        )
        cfg = self.session.get_page(cfg_path)
        result: list[VLANInfo] = []
        for vid in parse.parse_vlan_ids(cfg):
            html = self.session.post_form(member_path, {"VLAN_ID": str(vid)})
            result.append(_vlan_info(vid, html, self.model.port_count))
        return result

    def get_macs(self) -> list[MacEntry]:
        raise _unsupported(self.model.key, "a MAC/FDB table")

    def get_lldp(self) -> list[LLDPNeighbor]:
        raise _unsupported(self.model.key, "LLDP neighbours")

    def get_sensors(self) -> list[Sensor]:
        raise _unsupported(self.model.key, "box sensors")

    def get_mgmt_ip(self) -> MgmtIpConfig:
        raise _unsupported(self.model.key, "management-IP config")


class AsyncHttpReader:
    """Asynchronous web-UI read facade (mirror of ``HttpReader``)."""

    def __init__(self, session: AsyncHttpSession, model: SwitchModel) -> None:
        self._spec = http_spec(model)
        _require_verified_reads(self._spec)
        self.session = session
        self.model = model

    async def get_ports(self) -> list[PortStatus]:
        path = _require_path(self.model.key, self._spec.dashboard_path, "port status")
        return parse.parse_port_status(await self.session.get_page(path))

    async def get_stats(self) -> list[PortStats]:
        path = _require_path(self.model.key, self._spec.stats_path, "port statistics")
        return parse.parse_port_stats(await self.session.get_page(path))

    async def get_poe(self) -> list[PoEStatus]:
        path = _require_path(self.model.key, self._spec.poe_status_path, "PoE status")
        return parse.parse_poe_status(await self.session.get_page(path))

    async def get_pvids(self) -> list[tuple[int, int]]:
        path = _require_path(self.model.key, self._spec.pvid_path, "port PVIDs")
        return parse.parse_pvids(await self.session.get_page(path))

    async def get_vlans(self) -> list[VLANInfo]:
        cfg_path = _require_path(
            self.model.key, self._spec.vlan_config_path, "VLAN configuration"
        )
        member_path = _require_path(
            self.model.key, self._spec.vlan_membership_path, "VLAN membership"
        )
        cfg = await self.session.get_page(cfg_path)
        result: list[VLANInfo] = []
        for vid in parse.parse_vlan_ids(cfg):
            html = await self.session.post_form(member_path, {"VLAN_ID": str(vid)})
            result.append(_vlan_info(vid, html, self.model.port_count))
        return result

    async def get_macs(self) -> list[MacEntry]:
        raise _unsupported(self.model.key, "a MAC/FDB table")

    async def get_lldp(self) -> list[LLDPNeighbor]:
        raise _unsupported(self.model.key, "LLDP neighbours")

    async def get_sensors(self) -> list[Sensor]:
        raise _unsupported(self.model.key, "box sensors")

    async def get_mgmt_ip(self) -> MgmtIpConfig:
        raise _unsupported(self.model.key, "management-IP config")
