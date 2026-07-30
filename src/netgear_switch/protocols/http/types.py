"""HTTP-only device-info types that don't fit the shared cross-backend
``models`` module (mirrors ``protocols/nsdp/types.py::NsdpDevice`` -- a
backend-specific read shape lives next to the protocol that produces it, not
in ``models.py``, until/unless a second backend needs the same shape).
"""

from __future__ import annotations

from dataclasses import dataclass
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
