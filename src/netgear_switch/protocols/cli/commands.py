"""Per-model FASTPATH CLI command specs (pure data).

The CLI equivalent of ``protocols/http/endpoints.py``. Each ``CliModelSpec``
records the ``show`` command each read op issues plus the session-setup commands
(``enable`` + disable output paging), and two honesty flags:

* ``captured`` -- True only for a model with a REAL captured CLI transcript
  backing its parsers (today only ``gsm7252ps``; see
  ``tests/fixtures/cli/gsm7252ps_*.txt``). The M4300 pair and gsm7228ps run the
  identical FASTPATH firmware CLI, so the command set and parsers carry over --
  but no transcript was captured from those SKUs, so ``captured`` is False and
  their CLI surface is INHERITED-not-captured, marked exactly like the M4300-16X
  HTTP spec is.
* ``reads_verified`` -- True for gsm7252ps (its CLI reader output was live
  CLI-vs-SNMP cross-verified on 10.1.5.22: ports/PVIDs match, mgmt-IP is an
  exact match, every read op returns real data). False for the M4300/gsm7228ps
  SKUs: they share the same grounded FASTPATH parsers but have NOT been
  live-checked on those models, so the facade refuses to dispatch a read to
  their CLI backend until someone cross-verifies it against that hardware
  (mirroring the HTTP backend's ``reads_verified`` gate). The parsers and the
  mock CLI face are fully exercised in tests regardless of this flag.

All four registered models share ONE command set: FASTPATH's ``show`` grammar is
identical across the Fully Managed (M4300/GSM7252PS) and Smart Managed Pro
(GSM7228PS/S3300) lines.
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


# gsm7252ps: the ONE model with a real captured transcript (SSH, 10.1.5.22).
# reads_verified=True: live CLI<->SNMP cross-verified 2026-07-25 on 10.1.5.22.
_GSM7252PS = CliModelSpec(model_key="gsm7252ps", captured=True, reads_verified=True)

# INHERITED-not-captured: same FASTPATH CLI image, no SKU-specific transcript.
_M4300_24X = CliModelSpec(model_key="m4300-24x", captured=False, reads_verified=False)
_M4300_16X = CliModelSpec(model_key="m4300-16x", captured=False, reads_verified=False)
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
