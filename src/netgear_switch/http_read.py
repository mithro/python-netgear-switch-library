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

import dataclasses
from typing import TYPE_CHECKING

from .errors import HttpUnexpectedPageError, UnsupportedCapabilityError
from .models import MgmtIpConfig, VLANInfo, VlanMode
from .protocols.http import forms, parse
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
    from .protocols.http.types import FastpathMembership, HttpSysInfo
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


def _is_s3300_dialect(spec: HttpModelSpec) -> bool:
    from .protocols.http.endpoints import HtmlDialect

    return spec.html_dialect is HtmlDialect.S3300


def _uses_xe_grid(spec: HttpModelSpec) -> bool:
    """True for the models that share the XE_FASTPATH cell grid for
    ports/stats/PVIDs/VLANs/PoE/LLDP: gsm7252ps (XE_FASTPATH) and the S3300-52X
    (gsm7228ps), whose MAC/mgmt/sensor pages diverge but whose six other reads
    are byte-identical -- see ``parse_s3300_*`` and ``HtmlDialect.S3300``."""
    return _is_xe_fastpath_dialect(spec) or _is_s3300_dialect(spec)


def _is_goahead_dialect(spec: HttpModelSpec) -> bool:
    from .protocols.http.endpoints import HtmlDialect

    return spec.html_dialect is HtmlDialect.GOAHEAD_XML


def _is_fastpath_dialect(spec: HttpModelSpec) -> bool:
    """True for the managed FASTPATH/Cheetah models (gsm7252ps, gsm7228ps and
    both M4300 SKUs), which share the ``switching/dot1q/vlan_port_cfg.html``
    VLAN-membership page -- see ``parse.parse_fastpath_membership``."""
    return _is_m4300_dialect(spec) or _uses_xe_grid(spec)


def _parse_vlans(spec: HttpModelSpec, html: str) -> list[VLANInfo]:
    """Dispatch an inline-egress VLAN page to its dialect's parser. The S3300
    shares the XE page shape but names egress ports ``1/gN``/``1/xgN``, which
    the XE (``1/0/N``-only) member expander reads as empty -- so it needs its
    own parser (see ``parse_s3300_vlans``)."""
    if _is_s3300_dialect(spec):
        return parse.parse_s3300_vlans(html)
    if _uses_xe_grid(spec):
        return parse.parse_xe_vlans(html)
    return parse.parse_m4300_vlans(html)


def _parse_macs(spec: HttpModelSpec, html: str) -> list[MacEntry]:
    """Dispatch the MAC/FDB page to its dialect's parser. Both FASTPATH
    dialects refuse a paginated (truncated) table rather than returning a
    partial FDB -- see the parsers' docstrings."""
    if _is_goahead_dialect(spec):
        return parse.parse_goahead_macs(html)
    if _is_s3300_dialect(spec):
        return parse.parse_s3300_macs(html)
    if _is_xe_fastpath_dialect(spec):
        return parse.parse_xe_macs(html)
    return parse.parse_m4300_macs(html)


def _parse_poe(spec: HttpModelSpec, html: str) -> list[PoEStatus]:
    """Dispatch the PoE page: the FASTPATH ``poeInterfaceConfiguration.html``
    cells (XE gsm7252ps *and* the M4300 Cheetah 16X -- byte-identical format)
    vs gs305ep's ``getPoePortStatus.cgi`` portID rows."""
    if _is_goahead_dialect(spec):
        return parse.parse_goahead_poe(html)
    if _uses_xe_grid(spec) or _is_m4300_dialect(spec):
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
    ``get_sensors`` raises rather than returning an empty list. The S3300
    (gsm7228ps) is deliberately NOT listed even though it has a sysinfo_path:
    its sysInfo carries no live fan/temp sensor table (only a base MAC and a
    temperature-trap threshold), so sensors over HTTP are unsupported and SNMP
    is the only source -- see ``HtmlDialect.S3300``."""
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
    if _uses_xe_grid(spec):
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
    if _uses_xe_grid(spec):
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
    if _uses_xe_grid(spec):
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


def fastpath_membership_paths(spec: HttpModelSpec, model_key: str) -> tuple[str, str]:
    """``(GET page, POST target)`` for the managed FASTPATH VLAN-membership page.

    Both must be populated for a managed model; a ``None`` here is a spec defect,
    not a device limitation, so it raises with the field name rather than
    degrading the read (principle 1: fail loud).
    """
    get_path = _require_path(model_key, spec.vlan_membership_path, "VLAN membership")
    post_path = _require_path(
        model_key, spec.vlan_membership_post_path, "the VLAN-membership form target"
    )
    return get_path, post_path


def _check_fastpath_membership_is_for(
    page: FastpathMembership, vid: int
) -> FastpathMembership:
    """Refuse a membership page that is showing a DIFFERENT VLAN.

    The firmware re-renders whichever VLAN its ``vlanId`` field selected; if a
    POST were rejected it would silently answer with the previously-shown VLAN,
    and that VLAN's ports would be attributed to ``vid``. Same guard the
    Plus-class ``_check_membership_is_for`` makes, and it is not theoretical --
    it is exactly what ``8021qMembe.cgi`` does without its CSRF hash.
    """
    if page.vlan_id is not None and page.vlan_id != vid:
        raise HttpUnexpectedPageError(
            f"vlan_port_cfg_rw.html: asked for VLAN {vid} but the page shows VLAN "
            f"{page.vlan_id} -- refusing to report the wrong VLAN's membership"
        )
    return page


def _with_fastpath_egress(
    vlans: list[VLANInfo], pages: dict[int, FastpathMembership]
) -> list[VLANInfo]:
    """Rebuild each VLAN's egress sets from its VLAN-Membership page.

    All three sets come from that page: ``tagged``/``untagged`` from its
    ``hiddenTagged``/``hiddenUnTagged`` ifName lists, and ``member`` as their
    union -- NOT from ``vlanStatus.html``'s Member Ports cell.

    That is a deliberate correction, not a shortcut. The two pages' member cells
    genuinely disagree, and the disagreement is per-FIRMWARE, so neither can be
    trusted as "the" membership on every model:

    * GSM7252PS @10.1.5.22, VLAN 1: ``vlanStatus`` lists 17 ports, matching
      ``show vlan 1``'s CURRENT column. Its own membership page agrees.
    * M4300-24X @10.1.5.13, VLAN 10: ``vlanStatus`` lists
      ``1/0/1 - 1/0/2, 1/0/5, 1/0/15 - 1/0/24``, i.e. 13 ports -- but
      ``show vlan 10`` reports 1/0/21..1/0/24 as ``Current: Exclude /
      Configured: Include``, so only 9 are current members. Despite its field
      name (``SwitchingVlanCurrentConfig_VlanCurrentEgressPortList``) that cell
      is reporting the CONFIGURED set on this firmware.

    The membership page's two ifName lists matched ``show vlan <id>`` on EVERY
    VLAN of all four switches (14 + 5 + 14 + 14), so they are the consistent
    source, and using them also guarantees
    ``member_ports == tagged_ports | untagged_ports`` -- an invariant a caller
    can rely on and which the vlanStatus cell breaks.

    A VLAN with no membership page (it disappeared between the two reads) is left
    exactly as ``vlanStatus`` reported it rather than being dropped or guessed.
    """
    out: list[VLANInfo] = []
    for v in vlans:
        page = pages.get(v.vlan_id)
        if page is None:
            out.append(v)
            continue
        out.append(
            dataclasses.replace(
                v,
                member_ports=page.tagged_ports | page.untagged_ports,
                tagged_ports=page.tagged_ports,
                untagged_ports=page.untagged_ports,
            )
        )
    return out


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

    A model that names a ``mgmt_ip_path`` uses it -- the managed FASTPATH models
    (whose ``ipConfiguration.html`` / ``mgmtVlanIpv4Configuration.html`` carry
    the address, mask, gateway AND the DHCP/static method, none of which their
    sysInfo page has) and the GoAhead GS728TPP (whose ``sysinfo_path`` wcd query
    serves identity + sensors only). Everything else reads it from
    ``sysinfo_path``; ``None`` in both means this model exposes no mgmt-IP page
    at all."""
    return spec.mgmt_ip_path or spec.sysinfo_path


def _mgmt_ip(spec: HttpModelSpec, page: str) -> MgmtIpConfig:
    """Dispatch the mgmt-IP page's HTML to the dialect's reader.

    The managed FASTPATH models read their dedicated XUI management-IP page
    (per-model field names -- see ``endpoints.XuiMgmtIpFields``); the GoAhead
    dialect reads its IPConf wcd query; the Plus models go through
    ``HttpSysInfo``. The two older FASTPATH sysInfo readers
    (``parse_xe_mgmt_ip``/``parse_s3300_mgmt``/``parse_m4300_sysinfo``) are
    still used, but only for the BASE MAC these pages do not carry -- see
    ``_with_fastpath_base_mac``."""
    if _is_goahead_dialect(spec):
        return parse.parse_goahead_mgmt_ip(page)
    if spec.mgmt_ip_fields is not None:
        f = spec.mgmt_ip_fields
        return parse.parse_xui_mgmt_ip(
            page,
            address_field=f.address,
            netmask_field=f.netmask,
            gateway_field=f.gateway,
            mode_field=f.mode,
            page=spec.mgmt_ip_path or "XUI management-IP page",
        )
    if _is_s3300_dialect(spec):
        return parse.parse_s3300_mgmt(page)
    if _is_xe_fastpath_dialect(spec):
        return parse.parse_xe_mgmt_ip(page)
    if _is_m4300_dialect(spec):
        return parse.parse_m4300_sysinfo(page)
    return _mgmt_ip_from_sysinfo(_parse_sysinfo(spec, page))


def _fastpath_base_mac(spec: HttpModelSpec, sysinfo_html: str) -> str | None:
    """The switch's BASE MAC from a managed model's sysInfo page.

    Read separately from the management address because no FASTPATH mgmt-IP page
    carries it, and because it must be the BASE MAC to stay field-for-field
    equal to SNMP's ``dot1dBaseBridgeAddress`` -- the M4300's mgmt page does
    show a MAC (``v_4_4_1``), but that is the management INTERFACE's, one off
    from the base MAC.
    """
    if _is_s3300_dialect(spec):
        return parse.parse_s3300_mgmt(sysinfo_html).base_mac
    if _is_xe_fastpath_dialect(spec):
        return parse.parse_xe_mgmt_ip(sysinfo_html).base_mac
    return parse.parse_m4300_sysinfo(sysinfo_html).base_mac


def _needs_fastpath_base_mac(spec: HttpModelSpec, cfg: MgmtIpConfig) -> bool:
    """Whether a second GET of ``sysinfo_path`` is needed to fill ``base_mac``."""
    return (
        spec.mgmt_ip_fields is not None
        and cfg.base_mac is None
        and spec.sysinfo_path is not None
    )


def _with_base_mac(cfg: MgmtIpConfig, sysinfo_page: str) -> MgmtIpConfig:
    """Merge the GoAhead SystemInfo page's base MAC into an IPConf MgmtIpConfig.

    The GoAhead IPConf page (address/netmask/gateway) carries NO MAC, so the
    switch's base MAC is read from the separate SystemInfo page
    (``DeviceBasicInfo/MacAddre``) and merged here -- matching the SNMP
    dot1dBaseBridgeAddress read so the HTTP and SNMP mgmt-IP agree field-for-
    field (including ``base_mac``)."""
    return dataclasses.replace(cfg, base_mac=parse.parse_goahead_base_mac(sysinfo_page))


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
        if _is_fastpath_dialect(self._spec):
            # vlanStatus.html gives the VLAN list, names and member ports; the
            # separate VLAN Membership page (live-discovered 2026-07-30) is what
            # splits those members into tagged vs untagged. Both are read here --
            # returning empty tagged/untagged sets from vlanStatus alone was the
            # defect this replaces.
            vlans = _parse_vlans(self._spec, self.session.get_page(cfg_path))
            return _with_fastpath_egress(vlans, self._fastpath_membership(vlans))
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

    def read_fastpath_membership(self, vlan: int) -> FastpathMembership:
        """One VLAN's membership page from the managed FASTPATH web UI.

        The GET shows whichever VLAN the firmware last selected, so any other
        VLAN needs the form POST the browser's own ``screen_refresh()`` makes:
        the full field set with ``submt=0``, which re-renders WITHOUT applying
        (confirmed live -- re-reading a VLAN returned a byte-identical page).
        Shared by ``get_vlans`` and ``HttpWriter.set_vlan_membership``.
        """
        get_path, post_path = fastpath_membership_paths(self._spec, self.model.key)
        page = parse.parse_fastpath_membership(self.session.get_page(get_path))
        if page.vlan_id == vlan:
            return page
        body = forms.fastpath_membership_form(page, vlan=vlan)
        return _check_fastpath_membership_is_for(
            parse.parse_fastpath_membership(self.session.post_form(post_path, body)),
            vlan,
        )

    def _fastpath_membership(
        self, vlans: list[VLANInfo]
    ) -> dict[int, FastpathMembership]:
        """Every VLAN's membership page, reusing ONE base GET.

        Deliberately not ``read_fastpath_membership`` per VLAN: that would re-GET
        the base page for each of the 14 VLANs these switches carry.
        """
        get_path, post_path = fastpath_membership_paths(self._spec, self.model.key)
        base = parse.parse_fastpath_membership(self.session.get_page(get_path))
        pages: dict[int, FastpathMembership] = {}
        for v in vlans:
            if base.vlan_id == v.vlan_id:
                pages[v.vlan_id] = base
                continue
            body = forms.fastpath_membership_form(base, vlan=v.vlan_id)
            pages[v.vlan_id] = _check_fastpath_membership_is_for(
                parse.parse_fastpath_membership(
                    self.session.post_form(post_path, body)
                ),
                v.vlan_id,
            )
        return pages

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
        cfg = _mgmt_ip(self._spec, self.session.get_page(path))
        # GoAhead: the IPConf page has no MAC row, so read the base MAC from
        # the SystemInfo page to reach SNMP parity on base_mac.
        if _is_goahead_dialect(self._spec) and self._spec.sysinfo_path is not None:
            cfg = _with_base_mac(cfg, self.session.get_page(self._spec.sysinfo_path))
        elif _needs_fastpath_base_mac(self._spec, cfg):
            assert self._spec.sysinfo_path is not None  # guarded above (for mypy)
            cfg = dataclasses.replace(
                cfg,
                base_mac=_fastpath_base_mac(
                    self._spec, self.session.get_page(self._spec.sysinfo_path)
                ),
            )
        return cfg


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
        # The FASTPATH check MUST precede the vlan_membership_path requirement,
        # because these models' VLAN LIST comes from vlanStatus.html while their
        # membership page is a separate URL -- requiring the membership path
        # first once made this async op raise while the sync twin worked, a real
        # sync/async divergence.
        if _is_fastpath_dialect(self._spec):
            # Mirror of the sync twin: vlanStatus.html for the list/names/members,
            # the VLAN Membership page for the tagged/untagged split.
            vlans = _parse_vlans(self._spec, await self.session.get_page(cfg_path))
            return _with_fastpath_egress(vlans, await self._fastpath_membership(vlans))
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

    async def read_fastpath_membership(self, vlan: int) -> FastpathMembership:
        """Async twin of ``HttpReader.read_fastpath_membership`` (see its docs)."""
        get_path, post_path = fastpath_membership_paths(self._spec, self.model.key)
        page = parse.parse_fastpath_membership(await self.session.get_page(get_path))
        if page.vlan_id == vlan:
            return page
        body = forms.fastpath_membership_form(page, vlan=vlan)
        return _check_fastpath_membership_is_for(
            parse.parse_fastpath_membership(
                await self.session.post_form(post_path, body)
            ),
            vlan,
        )

    async def _fastpath_membership(
        self, vlans: list[VLANInfo]
    ) -> dict[int, FastpathMembership]:
        """Async twin of ``HttpReader._fastpath_membership`` (see its docs)."""
        get_path, post_path = fastpath_membership_paths(self._spec, self.model.key)
        base = parse.parse_fastpath_membership(await self.session.get_page(get_path))
        pages: dict[int, FastpathMembership] = {}
        for v in vlans:
            if base.vlan_id == v.vlan_id:
                pages[v.vlan_id] = base
                continue
            body = forms.fastpath_membership_form(base, vlan=v.vlan_id)
            pages[v.vlan_id] = _check_fastpath_membership_is_for(
                parse.parse_fastpath_membership(
                    await self.session.post_form(post_path, body)
                ),
                v.vlan_id,
            )
        return pages

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
        cfg = _mgmt_ip(self._spec, await self.session.get_page(path))
        # GoAhead: base MAC comes from the SystemInfo page (see sync twin).
        if _is_goahead_dialect(self._spec) and self._spec.sysinfo_path is not None:
            cfg = _with_base_mac(
                cfg, await self.session.get_page(self._spec.sysinfo_path)
            )
        elif _needs_fastpath_base_mac(self._spec, cfg):
            assert self._spec.sysinfo_path is not None  # guarded above (for mypy)
            cfg = dataclasses.replace(
                cfg,
                base_mac=_fastpath_base_mac(
                    self._spec, await self.session.get_page(self._spec.sysinfo_path)
                ),
            )
        return cfg
