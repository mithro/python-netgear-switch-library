"""HTTP-only device-info types that don't fit the shared cross-backend
``models`` module (mirrors ``protocols/nsdp/types.py::NsdpDevice`` -- a
backend-specific read shape lives next to the protocol that produces it, not
in ``models.py``, until/unless a second backend needs the same shape).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

    from ...models import IpMode, VlanMode


@dataclass(frozen=True)
class FastpathMembership:
    """One render of the FASTPATH "VLAN Membership" page
    (``switching/dot1q/vlan_port_cfg.html`` -> ``..._rw.html``).

    LIVE-DISCOVERED 2026-07-30 on all four managed switches (gsm7252ps
    10.1.5.22, gsm7228ps/S3300-52X 10.1.5.11, m4300-24x 10.1.5.13,
    m4300-16x 10.1.5.20:49152) -- see ``parse.parse_fastpath_membership`` and
    the fixtures ``tests/fixtures/http/{gsm7252ps,gsm7228ps,m4300,m4300_16x}_
    vlanPortCfg_*.html``. The page carries TWO different views of the same VLAN,
    and the difference is real, not noise:

    ``tagged_ports``/``untagged_ports`` come from the page's own
    ``hiddenTagged``/``hiddenUnTagged`` ifName lists, which are the **CURRENT**
    (operational) egress lists -- byte-for-byte what ``show vlan <id>`` reports
    under ``Current: Include`` and what ``vlanStatus.html``'s Member Ports cell
    lists. Their union therefore equals ``member_ports`` exactly.

    ``configured`` comes from ``hidden_mem``, the tri-state code the page
    SUBMITS, and is the **CONFIGURED** participation -- what ``show vlan``
    reports under ``Configured`` and what SNMP's
    ``dot1qVlanStaticEgressPorts`` returns. These two views genuinely disagree
    on real hardware: on gsm7252ps VLAN 1, ports ``1/0/50`` and ``1/0/51`` are
    ``Current: Exclude / Configured: Include``, so they appear in
    ``configured`` (and in SNMP's static egress) but NOT in
    ``untagged_ports`` (nor in the CLI's current list). Reads therefore report
    the current view (consistent with ``member_ports``), while
    ``HttpWriter.set_vlan_membership`` writes and verifies the configured view
    -- the only one the form can actually set.

    ``fields`` is every form field the page rendered, verbatim, so a re-POST
    can be byte-faithful to what the browser sends instead of a guessed
    subset (the M4300-16X, for one, refuses a POST that drops its per-page
    ``CSRFToken``).
    """

    vlan_id: int | None
    vlan_ids: tuple[int, ...]
    name: str | None
    vlan_type: str | None
    tagged_ports: frozenset[int]
    untagged_ports: frozenset[int]
    hidden_mem: str
    # Physical port number -> its 0-based slot in ``hidden_mem``'s comma-separated
    # code list. Read off the page's own port grid, never computed as ``port - 1``:
    # the grid interleaves LAG pseudo-interfaces after the physical ports, and the
    # two firmware generations index the grid differently (see the parser).
    port_slots: Mapping[int, int]
    configured: Mapping[int, VlanMode]
    fields: Mapping[str, str]
    # The ``<form ACTION=...>`` target the page itself declares (the ``_rw.html``
    # twin). Exposed so a test can pin it against the model spec's
    # ``vlan_membership_post_path`` rather than that path being an unchecked
    # constant.
    action: str


@dataclass(frozen=True)
class XuiRow:
    """One repeating row of a FASTPATH "XE"/Cheetah XUI list page.

    These pages (``portsConfiguration.html``, ``poeInterfaceConfiguration.html``,
    ``basicAddressTable.html`` ...) render every cell as a hidden input whose
    NAME is ``<unit>.<row0>.<count>.v_1_2_<column>`` -- e.g. ``1.35.52.v_1_2_6``
    is column 6 of the 36th row of a 52-row table on unit 1. ``prefix`` is that
    ``<unit>.<row0>.<count>.`` string, taken verbatim from the device (never
    computed from the port number: the row order is the device's, and the count
    is the rendered row count, not the model's port count -- the PoE page of a
    52-port switch has 48 rows).

    ``checkbox`` is the row's own ``gecb*`` selector, whose NAME differs per
    firmware (``1.0.52.gecb5`` on gsm7252ps, ``1.0.52.gecb10`` on gsm7228ps,
    ``1.0.24.gecb_1_2`` on the M4300s) -- so it is scraped, not constructed.
    LIVE-CONFIRMED 2026-07-30 on all four managed switches: an apply POST
    changes ONLY the rows whose checkbox is present in the body.
    """

    prefix: str
    checkbox: str | None
    fields: Mapping[str, str]

    def field(self, column: str) -> str | None:
        """This row's value for ``column`` (e.g. ``"v_1_2_6"``), or ``None``."""
        return self.fields.get(self.prefix + column)


@dataclass(frozen=True)
class XuiListPage:
    """One render of a FASTPATH XUI *list* page (a table of ``XuiRow``).

    ``action`` is the ``<FORM ACTION=...>`` of the page's SECOND form -- the
    write form (``<page>.html/a1``); the first (``/a0``) is the applet/redirect
    form and carries no data. ``hidden`` is that form's trailing "redirection
    elements" block (``submit_flag``/``submit_target``/``err_flag``/``err_msg``/
    ``clazz_information``), echoed back on every POST. ``buttons`` maps the
    page's button fields to their rendered labels (``v_2_1_2`` -> ``APPLY``,
    ``v_2_1_3`` -> ``RESET`` / ``Power Cycle Port(s)``); the firmware's own
    ``xuiProcessButtonActions`` ENABLES the clicked button's hidden input before
    submitting, so the POST carries it.

    ``tokens`` is the form's page-level NON-DATA fields -- in practice the
    per-page ``CSRFToken`` the AV-era M4300-16X firmware issues. It is carried
    into every apply because that firmware answers ``403 Forbidden`` to a POST
    that drops it (live 2026-07-30 on 10.1.5.20:49152: the identical body with
    the token returned 200 and applied). Data cells (``v_*``) are deliberately
    NOT included -- an apply must mention only the row it is changing.

    ``nav`` is the page's list-NAVIGATION block: the ``v_*`` fields the firmware
    renders in its ``class=deftestme`` navigation rows above and below the table
    (the "Go To Port" bar), which scope the list -- e.g. ``v_1_1_1`` =
    ``"1"``/``v_1_3_1`` = ``"1"`` (``xc="url-list"``, ``xeleName="Port Group
    Index"``, both aliased by the page's own
    ``xeData["xalias_urlListUnit"] = "1_1_1|1_3_1|3_1_1|3_4_1"``) plus the
    interface-type filter ``v_1_1_2`` = ``"^Physical$"``. They are ENABLED hidden
    inputs, so a browser submits them on every apply -- and on the GSM7252PS PoE
    page the firmware REQUIRES one of the ``urlListUnit`` aliases to resolve the
    row at all (see ``forms.xui_row_apply_form``). Kept separate from ``rows``
    and from the ``v_g_*`` global "apply to all" row, neither of which belongs in
    a one-row apply.
    """

    action: str
    hidden: Mapping[str, str]
    buttons: Mapping[str, str]
    rows: tuple[XuiRow, ...]
    # default_factory, NOT a bare ``MappingProxyType({})`` default, because that
    # breaks on Python 3.11 -- the floor this project supports (CI caught it on
    # 3.11 while 3.12 and 3.13 passed). ``dataclasses`` uses "the default's CLASS
    # is unhashable" as its proxy for mutability, and ``mappingproxy`` only
    # gained a class-level ``__hash__`` in 3.12; on 3.11 it has none, so the
    # field is rejected as a mutable default. Matches the pattern already used by
    # ``HttpModelSpec.cert_upload_form_fields``.
    tokens: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    nav: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    #: The page's blank ``v_g_<table>_<tr>_<col>`` TEMPLATE row, keyed by its
    #: FULL field name. This is the row an ADD fills in: the firmware renders it
    #: with every value empty inside ``display:none`` cells, and the page's Apply
    #: button writes the row-status into it (``xa_4_2_1`` targets
    #: ``"2_1_5|g_2_1_5"`` with ``"Active"``; Delete targets the same pair with
    #: ``"Delete"``).
    #:
    #: Empty for a page that renders no template row -- which is most of them,
    #: and is why this is a separate field rather than being folded into
    #: ``rows``: a one-row apply must never mention it, and the existing
    #: ``xui_row_apply_form`` deliberately does not.
    template: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))

    def row_for(self, column: str, value: str) -> XuiRow | None:
        """The row whose ``column`` renders ``value`` (e.g. the ifName cell)."""
        return next((r for r in self.rows if r.field(column) == value), None)


@dataclass(frozen=True)
class XuiFormPage:
    """One render of a FASTPATH XUI *detail* page (flat ``v_<a>_<b>_<c>`` fields).

    Same second-form/``hidden``/``buttons`` shape as ``XuiListPage``, but the
    values are not in repeating rows -- ``ipConfiguration.html`` and the M4300's
    ``mgmtVlanIpv4Configuration.html`` are of this kind. ``fields`` is every
    named input the form rendered, verbatim, so a re-POST can echo the device's
    own body (the M4300-16X refuses a POST that drops its per-page
    ``CSRFToken``, which lives in exactly this map).
    """

    action: str
    hidden: Mapping[str, str]
    buttons: Mapping[str, str]
    fields: Mapping[str, str]


@dataclass(frozen=True)
class HttpSysInfo:
    """GS110EMX ``sysInfo.html``: device identity + management-IP config.

    GROUNDED in ``tests/fixtures/http/gs110emx_sysinfo.html`` (a real capture
    from a physical GS110EMX) -- see ``parse.parse_sysinfo``. ``ip_mode`` is
    inferred from the page's ``<tr data-select-value="N">`` wrapping the
    DHCP-mode ``<select>``: the real capture carries no explicit ``selected``
    attribute on either ``<option>`` (that gets set client-side by the page's
    own JavaScript), so ``data-select-value`` -- 0 selects the "Disable"
    option at index 0 (static IP), 1 selects "Enable" (DHCP) -- is the
    best-grounded reading available; it is corroborated by the same capture
    carrying a fully-populated static IP/netmask/gateway alongside
    ``data-select-value="0"``.

    CAVEAT: only the STATIC-IP branch above (``data-select-value="0"``) was
    directly observed in the one real capture that exists. The DHCP branch
    (``data-select-value="1"`` -> ``IpMode.DHCP``) is inferred from the same
    ``<select>``'s option ordering, not itself captured from a real
    DHCP-configured device -- treat it as plausible-but-unverified until a
    DHCP-mode capture confirms it, even though ``HttpModelSpec.reads_verified``
    is ``True`` for this model's grounded surface overall.
    """

    product_name: str
    switch_name: str
    serial_number: str
    mac_address: str
    firmware_version: str
    ip_mode: IpMode
    ip_address: str
    subnet_mask: str
    gateway_address: str
