"""HTTP-only device-info types that don't fit the shared cross-backend
``models`` module (mirrors ``protocols/nsdp/types.py::NsdpDevice`` -- a
backend-specific read shape lives next to the protocol that produces it, not
in ``models.py``, until/unless a second backend needs the same shape).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ...models import IpMode


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
