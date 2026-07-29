"""Per-model FASTPATH CLI command specs (pure data).

The CLI equivalent of ``protocols/http/endpoints.py``. Each ``CliModelSpec``
records the ``show`` command each read op issues plus the session-setup commands
(``enable`` + disable output paging), and two honesty flags:

* ``captured`` -- True only for a model with a REAL captured CLI transcript
  backing its parsers: ``gsm7252ps`` (see ``tests/fixtures/cli/gsm7252ps_*.txt``),
  ``m4300-24x`` (``tests/fixtures/cli/m4300_24x_*.txt``, captured live from
  10.1.5.13 on 2026-07-29) and ``m4300-16x`` (``tests/fixtures/cli/m4300_16x_*.txt``,
  captured live from 10.1.5.20 on 2026-07-29). The gsm7228ps runs the identical
  FASTPATH firmware CLI, so the command set and parsers carry over -- but no
  transcript was captured from that SKU, so ``captured`` is False and its CLI
  surface is INHERITED-not-captured, marked exactly like the M4300-16X HTTP spec.
* ``reads_verified`` -- True for gsm7252ps (live CLI-vs-SNMP cross-verified on
  10.1.5.22), m4300-24x (live CLI-verified on 10.1.5.13, 2026-07-29) and
  m4300-16x (live CLI-verified on 10.1.5.20, 2026-07-29: ports/PVIDs/VLANs/MACs/
  LLDP/sensors/stats/mgmt-IP AND PoE all correct). False for the gsm7228ps SKU:
  it shares the same grounded FASTPATH parsers but has NOT been live-checked on
  that model, so the facade refuses to dispatch a read to its CLI backend until
  someone cross-verifies it against that hardware (mirroring the HTTP backend's
  ``reads_verified`` gate). The parsers and the mock CLI face are fully exercised
  in tests regardless of this flag.

FASTPATH's ``show`` grammar is nearly identical across the Fully Managed
(M4300/GSM7252PS) and Smart Managed Pro (GSM7228PS/S3300) lines, but the newer
M4300 firmware (12.0.13.8) renamed two commands -- see ``_M4300_OVERRIDES``.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING

from ...errors import UnsupportedCapabilityError
from ...registry import Backend

if TYPE_CHECKING:
    from collections.abc import Mapping

    from ...registry import SwitchModel

# The three CLI transports all speak the same FASTPATH CLI; a model that has any
# of them uses this spec set.
CLI_BACKENDS = frozenset({Backend.SSH, Backend.TELNET, Backend.CONSOLE})


@dataclass(frozen=True)
class CliModelSpec:
    model_key: str
    captured: bool
    reads_verified: bool
    # Session setup, run once after the shell opens.
    enable_cmd: str = "enable"
    paging_off_cmd: str = "terminal length 0"
    # Read-op commands. The two templated ones take a positional format arg.
    version_cmd: str = "show version"
    port_status_cmd: str = "show port all"
    vlan_brief_cmd: str = "show vlan brief"
    vlan_detail_cmd: str = "show vlan {vlan}"
    pvid_cmd: str = "show vlan port all"
    mac_table_cmd: str = "show mac-addr-table"
    lldp_cmd: str = "show lldp remote-device all"
    poe_cmd: str = "show poe port info all"
    environment_cmd: str = "show environment"
    network_cmd: str = "show network"
    interface_stats_cmd: str = "show interface ethernet {iface}"

    def vlan_detail(self, vlan: int) -> str:
        return self.vlan_detail_cmd.format(vlan=vlan)

    def interface_stats(self, port: int) -> str:
        # FASTPATH physical interfaces are addressed "1/0/<port>".
        return self.interface_stats_cmd.format(iface=f"1/0/{port}")


# M4300 FASTPATH 12.0.13.8 renamed two read commands vs the older gsm7252ps
# image (live-confirmed on 10.1.5.13):
#   "show vlan brief" -> "show vlan"          ("show vlan brief" is Invalid input)
#   "show network"    -> "show ip management" ("show network" deprecated)
# The output formats are otherwise the same fixed-width tables/dotted-leader
# scalars, so the existing parse_vlan_brief/parse_mgmt_ip parsers apply unchanged.
_M4300_OVERRIDES = {
    "vlan_brief_cmd": "show vlan",
    "network_cmd": "show ip management",
}

# gsm7252ps: real captured transcript (SSH, 10.1.5.22).
# reads_verified=True: live CLI<->SNMP cross-verified 2026-07-25 on 10.1.5.22.
_GSM7252PS = CliModelSpec(model_key="gsm7252ps", captured=True, reads_verified=True)

# m4300-24x: real captured transcript (10.1.5.13, tests/fixtures/cli/m4300_24x_*).
# reads_verified=True: live CLI-verified 2026-07-29 on 10.1.5.13 (M4300-24X,
# FASTPATH 12.0.13.8) -- ports/pvids/vlans/macs/lldp/sensors/stats/mgmt-IP all
# correct with the two command overrides above.
_M4300_24X = CliModelSpec(
    model_key="m4300-24x", captured=True, reads_verified=True, **_M4300_OVERRIDES
)
# m4300-16x: real captured transcript (tests/fixtures/cli/m4300_16x_*).
# reads_verified=True: live CLI-verified 2026-07-29 on 10.1.5.20 (M4300-16X-PoE,
# FASTPATH 12.0.19.15) -- ports/pvids/vlans/macs/lldp/sensors/stats/mgmt-IP AND
# `show poe port info all` (16 PoE ports; the M4300 image omits the Temperature
# column, handled by the header-name column lookup in parse_poe) all correct.
_M4300_16X = CliModelSpec(
    model_key="m4300-16x", captured=True, reads_verified=True, **_M4300_OVERRIDES
)
# gsm7228ps: INHERITED-not-captured, older-image default commands.
_GSM7228PS = CliModelSpec(model_key="gsm7228ps", captured=False, reads_verified=False)

_SPECS: dict[str, CliModelSpec] = {
    s.model_key: s
    for s in (_GSM7252PS, _M4300_24X, _M4300_16X, _GSM7228PS)
}

CLI_SPECS: Mapping[str, CliModelSpec] = MappingProxyType(_SPECS)


def cli_spec(model: SwitchModel) -> CliModelSpec:
    """Return the CLI command spec for ``model`` or raise if it has no CLI backend."""
    if not (CLI_BACKENDS & model.backends):
        raise UnsupportedCapabilityError(f"model {model.key!r} has no CLI backend")
    try:
        return _SPECS[model.key]
    except KeyError:
        raise UnsupportedCapabilityError(
            f"model {model.key!r} has a CLI backend but no command spec"
        ) from None
