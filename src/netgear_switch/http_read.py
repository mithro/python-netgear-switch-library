"""Model-driven web-UI read operations over a sync or async ``HttpSession``.

Parallel to ``snmp_read.py``/``nsdp_read.py``. Construction is gated on
``HttpModelSpec.reads_verified``: a model whose web reads are still
UNVERIFIED-pending-capture (gsm7228ps cheetah/S3300) refuses to construct
rather than return fabricated data -- the facade never gets a
plausible-but-wrong result from an unverified scrape. Ops a model's HTTP
surface genuinely does not expose (e.g. gs110emx has no PoE, so PoE/MAC/LLDP/
sensor reads; see ``protocols/http/endpoints.py``) raise
``UnsupportedCapabilityError`` honestly instead of silently returning ``[]``,
via ``_require_path``'s per-op ``None``-path check below. gs110emx's web UI
DOES cover the full NSDP read surface (ports/stats/VLANs/PVIDs/mgmt-IP) -- the
port/stats/PVID/VLAN-list parsers are selected by ``HttpModelSpec.html_dialect``
and ``get_mgmt_ip`` by ``sysinfo_path`` because gs110emx's pages use a
different HTML dialect than gs305ep's (see ``protocols/http/parse.py``).

The gsm7252ps (XE_FASTPATH) web UI covers EVERY read op this library has --
ports/stats/PVIDs/VLANs/MACs/PoE/LLDP plus sensors and mgmt-IP from
``sysInfo.html`` -- so no op is carved out for that model. Its spec says
``reads_verified=True``: the HTTP output was cross-verified against SNMP on the
live switch (10.1.5.22). The honesty gate (which refuses to construct while
``reads_verified`` is ``False``) still guards models that have NOT been
cross-verified, e.g. gsm7228ps.

All page-path selection and HTML-to-model conversion lives in the
module-level helpers below (pure, I/O-free); ``HttpReader``/``AsyncHttpReader``
differ only in whether ``session.get_page``/``post_form`` is awaited.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from .errors import HttpUnexpectedPageError, UnsupportedCapabilityError
from .models import MgmtIpConfig, VLANInfo, VlanMode
from .protocols.http import parse
from .protocols.http.endpoints import http_spec

if TYPE_CHECKING:
    from .models import (
        LLDPNeighbor,
        MacEntry,
        PoEStatus,
        PortStats,
        PortStatus,
        Sensor,
    )
    from .protocols.http.endpoints import HttpModelSpec
    from .protocols.http.session import AsyncHttpSession, HttpSession
    from .protocols.http.types import HttpSysInfo
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


def _is_gs110emx_dialect(spec: HttpModelSpec) -> bool:
    from .protocols.http.endpoints import HtmlDialect

    return spec.html_dialect is HtmlDialect.GS110EMX


def _is_gs105pe_dialect(spec: HttpModelSpec) -> bool:
    from .protocols.http.endpoints import HtmlDialect

    return spec.html_dialect is HtmlDialect.GS105PE


def _is_m4300_dialect(spec: HttpModelSpec) -> bool:
    from .protocols.http.endpoints import HtmlDialect

    return spec.html_dialect is HtmlDialect.M4300


def _is_xe_fastpath_dialect(spec: HttpModelSpec) -> bool:
    from .protocols.http.endpoints import HtmlDialect

    return spec.html_dialect is HtmlDialect.XE_FASTPATH


def _is_goahead_dialect(spec: HttpModelSpec) -> bool:
    from .protocols.http.endpoints import HtmlDialect

    return spec.html_dialect is HtmlDialect.GOAHEAD_XML


def _has_inline_vlan_egress(spec: HttpModelSpec) -> bool:
    """True for the FASTPATH dialects whose VLAN page carries each VLAN's
    egress list INLINE (M4300 vlanStatus.html and the XE one), so there is no
    per-VLAN membership POST to make -- and requiring
    ``vlan_membership_path`` for them would wrongly raise."""
    return _is_m4300_dialect(spec) or _is_xe_fastpath_dialect(spec)


def _parse_vlans(spec: HttpModelSpec, html: str) -> list[VLANInfo]:
    """Dispatch an inline-egress VLAN page to its dialect's parser."""
    if _is_xe_fastpath_dialect(spec):
        return parse.parse_xe_vlans(html)
    return parse.parse_m4300_vlans(html)


def _parse_macs(spec: HttpModelSpec, html: str) -> list[MacEntry]:
    """Dispatch the MAC/FDB page to its dialect's parser. Both FASTPATH
    dialects refuse a paginated (truncated) table rather than returning a
    partial FDB -- see the parsers' docstrings."""
    if _is_goahead_dialect(spec):
        return parse.parse_goahead_macs(html)
    if _is_xe_fastpath_dialect(spec):
        return parse.parse_xe_macs(html)
    return parse.parse_m4300_macs(html)


def _parse_poe(spec: HttpModelSpec, html: str) -> list[PoEStatus]:
    """Dispatch the PoE page: the XE ``poeInterfaceConfiguration.html`` cells
    vs gs305ep's ``getPoePortStatus.cgi`` portID rows."""
    if _is_goahead_dialect(spec):
        return parse.parse_goahead_poe(html)
    if _is_xe_fastpath_dialect(spec):
        return parse.parse_xe_poe(html)
    return parse.parse_poe_status(html)


def _parse_lldp(spec: HttpModelSpec, html: str) -> list[LLDPNeighbor]:
    """Dispatch the LLDP page to its dialect's parser."""
    if _is_goahead_dialect(spec):
        return parse.parse_goahead_lldp(html)
    return parse.parse_xe_lldp(html)


def _parse_sensors(spec: HttpModelSpec, html: str) -> list[Sensor]:
    """Dispatch the sensor-bearing sysInfo page to its dialect's parser."""
    if _is_goahead_dialect(spec):
        return parse.parse_goahead_sensors(html)
    if _is_xe_fastpath_dialect(spec):
        return parse.parse_xe_sensors(html)
    return parse.parse_m4300_sensors(html)


def _supports_sensors(spec: HttpModelSpec) -> bool:
    """Only the FASTPATH / GoAhead dialects have a sysInfo page carrying box
    sensors; a Plus model's sysInfo (gs110emx/gs105pe) has none, so
    ``get_sensors`` raises rather than returning an empty list."""
    return (
        _is_m4300_dialect(spec)
        or _is_xe_fastpath_dialect(spec)
        or _is_goahead_dialect(spec)
    ) and spec.sysinfo_path is not None


def _parse_stats(spec: HttpModelSpec, html: str) -> list[PortStats]:
    """Dispatch ``stats_path``'s HTML to the right parser, keyed off
    ``spec.html_dialect``: gs110emx's interface_stats.html has a different
    (and, on real hardware, malformed -- see ``parse._OPEN_ROW_RE``) row shape
    than gs305ep's portStatistics.cgi."""
    if _is_gs110emx_dialect(spec):
        return parse.parse_interface_stats(html)
    if _is_gs105pe_dialect(spec):
        return parse.parse_gs105pe_stats(html)
    if _is_m4300_dialect(spec):
        return parse.parse_m4300_stats(html)
    if _is_xe_fastpath_dialect(spec):
        return parse.parse_xe_stats(html)
    return parse.parse_port_stats(html)


def _parse_ports(spec: HttpModelSpec, html: str) -> list[PortStatus]:
    """Dispatch the port-status page to the dialect's parser: gs110emx's
    port_settings.html (open rows, speed text) vs gs305ep's dashboard.cgi."""
    if _is_gs110emx_dialect(spec):
        return parse.parse_gs110emx_port_status(html)
    if _is_gs105pe_dialect(spec):
        return parse.parse_gs105pe_port_status(html)
    if _is_m4300_dialect(spec):
        return parse.parse_m4300_port_status(html)
    if _is_xe_fastpath_dialect(spec):
        return parse.parse_xe_port_status(html)
    if _is_goahead_dialect(spec):
        return parse.parse_goahead_ports(html)
    return parse.parse_port_status(html)


def _parse_pvids(spec: HttpModelSpec, html: str) -> list[tuple[int, int]]:
    """Dispatch the PVID page: gs110emx's vlan_pvidsetting.html vs
    gs305ep's portPVID.cgi."""
    if _is_gs110emx_dialect(spec):
        return parse.parse_gs110emx_pvids(html)
    if _is_gs105pe_dialect(spec):
        return parse.parse_gs105pe_pvids(html)
    if _is_m4300_dialect(spec):
        return parse.parse_m4300_pvids(html)
    if _is_xe_fastpath_dialect(spec):
        return parse.parse_xe_pvids(html)
    if _is_goahead_dialect(spec):
        return parse.parse_goahead_pvids(html)
    return parse.parse_pvids(html)


def _parse_vlan_ids(spec: HttpModelSpec, html: str) -> list[int]:
    """Dispatch the VLAN-list page: gs110emx's Cf8021q.html (Advanced 802.1Q
    rows) vs gs305ep's 8021qCf.cgi (vlanckN checkboxes)."""
    if _is_gs110emx_dialect(spec):
        return parse.parse_gs110emx_vlan_ids(html)
    return parse.parse_vlan_ids(html)


def _membership_form(
    spec: HttpModelSpec, vid: int, csrf_hash: str | None = None
) -> dict[str, str]:
    """The POST body that selects VLAN ``vid``'s membership page.

    Each model needs a different extra field, all confirmed live 2026-07-21:
    gs110emx's vlanMembership.html returns an EMPTY body unless the hidden
    ``vlanIdSel`` is present (``VLAN_ID`` alone is silently ignored); gs105pe's
    8021qMembe.cgi ignores ``VLAN_ID`` (returning VLAN 1 every time) unless the
    per-page CSRF ``hash`` accompanies it. gs305ep needs only ``VLAN_ID``.
    ``ACTION`` is deliberately never sent so the POST stays a READ -- a
    non-empty ACTION would APPLY a membership change."""
    data = {"VLAN_ID": str(vid)}
    if _is_gs110emx_dialect(spec):
        data["vlanIdSel"] = str(vid)
    if _is_gs105pe_dialect(spec) and csrf_hash:
        data["hash"] = csrf_hash
    return data


def _require_csrf_hash(member_page: str) -> str:
    """The gs105pe membership page's CSRF ``hash``, or raise.

    Without it the switch IGNORES ``VLAN_ID`` and returns the currently-selected
    VLAN's membership for every request -- which would be silently mislabelled
    as the requested VLAN. Refuse rather than return another VLAN's ports."""
    csrf = parse.parse_csrf_hash(member_page)
    if not csrf:
        raise HttpUnexpectedPageError(
            "8021qMembe.cgi: no CSRF 'hash' field -- without it the switch "
            "ignores VLAN_ID and every VLAN would report the selected VLAN's "
            "membership"
        )
    return csrf


def _check_membership_is_for(spec: HttpModelSpec, html: str, vid: int) -> None:
    """Verify a membership page really is the VLAN we asked for.

    The gs105pe/gs305ep membership CGI silently falls back to the currently
    selected VLAN when the request is not accepted, so without this check a
    wrong-but-plausible membership would be attributed to ``vid``. Only checked
    when the page actually reports a selection."""
    if not _is_gs105pe_dialect(spec):
        return
    shown = parse.parse_selected_vlan(html)
    if shown is not None and shown != vid:
        raise HttpUnexpectedPageError(
            f"8021qMembe.cgi: asked for VLAN {vid} but the page shows VLAN "
            f"{shown} -- refusing to report the wrong VLAN's membership"
        )


def _parse_sysinfo(spec: HttpModelSpec, html: str) -> HttpSysInfo:
    """Dispatch the device-identity/mgmt-IP page: gs105pe's switch_info.cgi
    (lowercase ip_address inputs, dhcpMode select) vs gs110emx's sysInfo.html."""
    if _is_gs105pe_dialect(spec):
        return parse.parse_gs105pe_sysinfo(html)
    return parse.parse_sysinfo(html)


def _mgmt_ip_from_sysinfo(info: HttpSysInfo) -> MgmtIpConfig:
    """GS110EMX sysInfo.html -> the shared ``MgmtIpConfig`` shape. The page's
    own MAC Address row is the switch's base MAC, so it fills ``base_mac``
    exactly like the SNMP/NSDP backends' dot1dBaseBridgeAddress/identity-MAC
    reads do -- uppercased to match those backends' formatting (the real
    capture's page text is lowercase, e.g. "bc:a5:11:b8:ec:f1"; see
    ``models.MgmtIpConfig.base_mac``)."""
    return MgmtIpConfig(
        mode=info.ip_mode,
        address=info.ip_address,
        netmask=info.subnet_mask,
        gateway=info.gateway_address,
        base_mac=info.mac_address.upper() or None,
    )


def _mgmt_ip_path(spec: HttpModelSpec) -> str | None:
    """The page whose HTML ``get_mgmt_ip`` reads for this model.

    The GoAhead dialect's ``sysinfo_path`` wcd query serves device identity +
    sensors, NOT the IPv4 config, so mgmt-IP comes from the dedicated
    ``mgmt_ip_path`` there; every other model reads it from ``sysinfo_path``.
    ``None`` means this model exposes no mgmt-IP page at all."""
    if _is_goahead_dialect(spec):
        return spec.mgmt_ip_path
    return spec.sysinfo_path


def _mgmt_ip(spec: HttpModelSpec, page: str) -> MgmtIpConfig:
    """Dispatch ``sysinfo_path``'s HTML to the dialect's mgmt-IP reader.

    The two FASTPATH dialects have their own page shapes (both reporting
    address/netmask + base MAC and NO DHCP indicator, hence IpMode.UNKNOWN);
    the GoAhead dialect reads a dedicated IPConf wcd query (address/netmask/
    gateway, no base MAC); the Plus models go through ``HttpSysInfo``."""
    if _is_goahead_dialect(spec):
        return parse.parse_goahead_mgmt_ip(page)
    if _is_xe_fastpath_dialect(spec):
        return parse.parse_xe_mgmt_ip(page)
    if _is_m4300_dialect(spec):
        return parse.parse_m4300_sysinfo(page)
    return _mgmt_ip_from_sysinfo(_parse_sysinfo(spec, page))


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
        return _parse_ports(self._spec, self.session.get_page(path))

    def get_stats(self) -> list[PortStats]:
        path = _require_path(self.model.key, self._spec.stats_path, "port statistics")
        return _parse_stats(self._spec, self.session.get_page(path))

    def get_poe(self) -> list[PoEStatus]:
        path = _require_path(self.model.key, self._spec.poe_status_path, "PoE status")
        return _parse_poe(self._spec, self.session.get_page(path))

    def get_pvids(self) -> list[tuple[int, int]]:
        path = _require_path(self.model.key, self._spec.pvid_path, "port PVIDs")
        return _parse_pvids(self._spec, self.session.get_page(path))

    def get_vlans(self) -> list[VLANInfo]:
        cfg_path = _require_path(
            self.model.key, self._spec.vlan_config_path, "VLAN configuration"
        )
        if _is_goahead_dialect(self._spec):
            # The GoAhead VLANList carries names only; membership comes from the
            # per-port JoinVLANList on the PVID page. Fetch both and combine.
            pvid_path = _require_path(
                self.model.key, self._spec.pvid_path, "VLAN membership"
            )
            return parse.parse_goahead_vlans(
                self.session.get_page(cfg_path), self.session.get_page(pvid_path)
            )
        if _has_inline_vlan_egress(self._spec):
            # vlanStatus.html carries each VLAN's egress list inline, so there
            # is no per-VLAN membership POST for these models.
            return _parse_vlans(self._spec, self.session.get_page(cfg_path))
        member_path = _require_path(
            self.model.key, self._spec.vlan_membership_path, "VLAN membership"
        )
        cfg = self.session.get_page(cfg_path)
        member_page = csrf = selected = None
        if _is_gs105pe_dialect(self._spec):
            member_page = self.session.get_page(member_path)
            csrf = _require_csrf_hash(member_page)
            selected = parse.parse_selected_vlan(member_page)
        result: list[VLANInfo] = []
        for vid in _parse_vlan_ids(self._spec, cfg):
            if member_page is not None and vid == selected:
                html = member_page  # already shown; re-POSTing it drops the link
            else:
                form = _membership_form(self._spec, vid, csrf)
                html = self.session.post_form(member_path, form)
            _check_membership_is_for(self._spec, html, vid)
            result.append(_vlan_info(vid, html, self.model.port_count))
        return result

    def get_macs(self) -> list[MacEntry]:
        path = _require_path(
            self.model.key, self._spec.mac_table_path, "a MAC/FDB table"
        )
        return _parse_macs(self._spec, self.session.get_page(path))

    def get_lldp(self) -> list[LLDPNeighbor]:
        # Only a model whose spec names an lldp_path has a neighbour table:
        # the M4300 /v1 UI exposes LLDP-MED remote data only (no chassis/port-id
        # table) and Plus switches expose no LLDP at all, so both keep raising
        # and SNMP stays the honest source. The gsm7252ps XE UI DOES have one.
        path = _require_path(self.model.key, self._spec.lldp_path, "LLDP neighbours")
        return _parse_lldp(self._spec, self.session.get_page(path))

    def get_sensors(self) -> list[Sensor]:
        if not _supports_sensors(self._spec):
            raise _unsupported(self.model.key, "box sensors")
        assert self._spec.sysinfo_path is not None  # guarded above (for mypy)
        return _parse_sensors(
            self._spec, self.session.get_page(self._spec.sysinfo_path)
        )

    def get_mgmt_ip(self) -> MgmtIpConfig:
        path = _mgmt_ip_path(self._spec)
        if path is None:
            raise _unsupported(self.model.key, "management-IP config")
        return _mgmt_ip(self._spec, self.session.get_page(path))


class AsyncHttpReader:
    """Asynchronous web-UI read facade (mirror of ``HttpReader``)."""

    def __init__(self, session: AsyncHttpSession, model: SwitchModel) -> None:
        self._spec = http_spec(model)
        _require_verified_reads(self._spec)
        self.session = session
        self.model = model

    async def get_ports(self) -> list[PortStatus]:
        path = _require_path(self.model.key, self._spec.dashboard_path, "port status")
        return _parse_ports(self._spec, await self.session.get_page(path))

    async def get_stats(self) -> list[PortStats]:
        path = _require_path(self.model.key, self._spec.stats_path, "port statistics")
        return _parse_stats(self._spec, await self.session.get_page(path))

    async def get_poe(self) -> list[PoEStatus]:
        path = _require_path(self.model.key, self._spec.poe_status_path, "PoE status")
        return _parse_poe(self._spec, await self.session.get_page(path))

    async def get_pvids(self) -> list[tuple[int, int]]:
        path = _require_path(self.model.key, self._spec.pvid_path, "port PVIDs")
        return _parse_pvids(self._spec, await self.session.get_page(path))

    async def get_vlans(self) -> list[VLANInfo]:
        cfg_path = _require_path(
            self.model.key, self._spec.vlan_config_path, "VLAN configuration"
        )
        if _is_goahead_dialect(self._spec):
            pvid_path = _require_path(
                self.model.key, self._spec.pvid_path, "VLAN membership"
            )
            return parse.parse_goahead_vlans(
                await self.session.get_page(cfg_path),
                await self.session.get_page(pvid_path),
            )
        # The inline-egress check MUST precede the vlan_membership_path
        # requirement: those models have no membership page (vlanStatus.html
        # carries the egress list inline), so requiring it first made this
        # async op raise while the sync twin worked -- a real sync/async
        # divergence.
        if _has_inline_vlan_egress(self._spec):
            return _parse_vlans(self._spec, await self.session.get_page(cfg_path))
        member_path = _require_path(
            self.model.key, self._spec.vlan_membership_path, "VLAN membership"
        )
        cfg = await self.session.get_page(cfg_path)
        member_page = csrf = selected = None
        if _is_gs105pe_dialect(self._spec):
            member_page = await self.session.get_page(member_path)
            csrf = _require_csrf_hash(member_page)
            selected = parse.parse_selected_vlan(member_page)
        result: list[VLANInfo] = []
        for vid in _parse_vlan_ids(self._spec, cfg):
            if member_page is not None and vid == selected:
                html = member_page  # already shown; re-POSTing it drops the link
            else:
                form = _membership_form(self._spec, vid, csrf)
                html = await self.session.post_form(member_path, form)
            _check_membership_is_for(self._spec, html, vid)
            result.append(_vlan_info(vid, html, self.model.port_count))
        return result

    async def get_macs(self) -> list[MacEntry]:
        path = _require_path(
            self.model.key, self._spec.mac_table_path, "a MAC/FDB table"
        )
        return _parse_macs(self._spec, await self.session.get_page(path))

    async def get_lldp(self) -> list[LLDPNeighbor]:
        path = _require_path(self.model.key, self._spec.lldp_path, "LLDP neighbours")
        return _parse_lldp(self._spec, await self.session.get_page(path))

    async def get_sensors(self) -> list[Sensor]:
        if not _supports_sensors(self._spec):
            raise _unsupported(self.model.key, "box sensors")
        assert self._spec.sysinfo_path is not None  # guarded above (for mypy)
        return _parse_sensors(
            self._spec, await self.session.get_page(self._spec.sysinfo_path)
        )

    async def get_mgmt_ip(self) -> MgmtIpConfig:
        path = _mgmt_ip_path(self._spec)
        if path is None:
            raise _unsupported(self.model.key, "management-IP config")
        return _mgmt_ip(self._spec, await self.session.get_page(path))
