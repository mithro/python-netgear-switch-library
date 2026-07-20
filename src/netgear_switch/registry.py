"""Declarative registry of known Netgear switch models."""

from __future__ import annotations

import enum
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING

from .errors import UnknownModelError

if TYPE_CHECKING:
    from collections.abc import Mapping

_FM = "1.3.6.1.4.1.4526.10"   # Fully Managed vendor subtree (M4300, GSM7252PS)
_SMP = "1.3.6.1.4.1.4526.11"  # Smart Managed Pro vendor subtree (S3300/GSM7228PS)


class Backend(enum.Enum):
    SNMP = "snmp"
    NSDP = "nsdp"
    HTTP = "http"


class SwitchClass(enum.Enum):
    FULLY_MANAGED = "fully_managed"
    SMART_MANAGED_PRO = "smart_managed_pro"
    PLUS = "plus"


@dataclass(frozen=True)
class SwitchModel:
    key: str
    display_name: str
    switch_class: SwitchClass
    port_count: int
    poe_port_count: int
    backends: frozenset[Backend]
    snmp_vendor_base: str | None
    # True (the default) for every model with a real device capture or other
    # hardware-validated prior art backing its fields. False marks a model
    # registered from spec sheets/product briefs alone, with NO capture --
    # its port/PoE counts and (for SNMP models) vendor OID family are a
    # best-effort guess, and vendor-specific reads (get_sensors, vendor PoE
    # power, etc.) are UNVERIFIED-pending-capture even though the
    # model-agnostic standard-MIB/CGI reads should still work. See the
    # UNVERIFIED-pending-capture entries below (m7300, xs748t, gs728tpp) for
    # the honesty rationale; do NOT flip this to True without a real capture.
    verified: bool = True

    @property
    def has_mac_table(self) -> bool:
        # MAC/FDB table is only reachable via SNMP (managed switches).
        return Backend.SNMP in self.backends


def _model(
    key: str,
    display_name: str,
    switch_class: SwitchClass,
    port_count: int,
    poe_port_count: int,
    backends: set[Backend],
    snmp_vendor_base: str | None,
    *,
    verified: bool = True,
) -> SwitchModel:
    return SwitchModel(
        key=key,
        display_name=display_name,
        switch_class=switch_class,
        port_count=port_count,
        poe_port_count=poe_port_count,
        backends=frozenset(backends),
        snmp_vendor_base=snmp_vendor_base,
        verified=verified,
    )


_MODELS: dict[str, SwitchModel] = {
    m.key: m
    for m in (
        _model(
            "m4300-24x",
            "M4300-24X (XSM4324CS)",
            SwitchClass.FULLY_MANAGED,
            28,
            0,
            {Backend.SNMP},
            _FM,
        ),
        _model(
            "m4300-16x",
            "M4300-16X (XSM4316)",
            SwitchClass.FULLY_MANAGED,
            16,
            16,
            {Backend.SNMP},
            _FM,
        ),
        _model(
            "gsm7252ps",
            "GSM7252PS",
            SwitchClass.FULLY_MANAGED,
            52,
            48,
            {Backend.SNMP},
            _FM,
        ),
        _model(
            "gsm7228ps",
            "GSM7228PS (S3300)",
            SwitchClass.SMART_MANAGED_PRO,
            52,
            48,
            {Backend.SNMP, Backend.HTTP},
            _SMP,
        ),
        _model(
            "gs110emx",
            "GS110EMX",
            SwitchClass.PLUS,
            10,
            0,
            {Backend.NSDP, Backend.HTTP},
            None,
        ),
        _model(
            "gs305ep",
            "GS305EP",
            SwitchClass.PLUS,
            5,
            4,
            {Backend.NSDP, Backend.HTTP},
            None,
        ),
        # --- UNVERIFIED-pending-capture below: no device capture exists for
        # any of these three models (gdoc2netcfg fleet models with no
        # prior-art fixture). Registered from spec sheets/product briefs only
        # so gdoc2netcfg can construct a SyncSwitch for them; see each
        # entry's comment for what specifically is a guess. The
        # model-agnostic standard-MIB SNMP reads (ports/vlans/lldp/PoE
        # admin/stats/mgmt-IP) should work regardless of the vendor OID
        # family guess below, but get_sensors() and vendor PoE-power
        # readings are UNVERIFIED until a real capture confirms the
        # 4526.10 vs 4526.11 subtree. Do NOT treat any of these three as a
        # source of confirmed behaviour -- confirm via hardware
        # verification before relying on anything beyond the standard MIBs.
        _model(
            "m7300",
            # M7300-24XF (24x SFP+, 0 PoE) picked as the assumed/documented
            # variant -- the M7300 family also ships non-XF and other port
            # counts; which exact SKU gdoc2netcfg's fleet actually runs is
            # UNVERIFIED. Same FASTPATH fully-managed lineage as M4300, so
            # the 4526.10 ("_FM") vendor subtree is the best spec-guess, but
            # that family assignment is itself UNVERIFIED-pending-capture.
            "M7300-24XF",
            SwitchClass.FULLY_MANAGED,
            24,
            0,
            {Backend.SNMP},
            _FM,
            verified=False,
        ),
        _model(
            "xs748t",
            # XS748T: 48x 10G copper (+ SFP+ combo), non-PoE per the
            # documented base spec -- UNVERIFIED-pending-capture. HTTP is
            # plausible for a Smart Managed Pro switch but is deliberately
            # OMITTED here (not just unverified): see gsm7228ps for the
            # SNMP+HTTP shape once a login/read flow is actually captured.
            # Until then SNMP-only avoids implying a web-UI integration that
            # does not exist in this codebase.
            "XS748T",
            SwitchClass.SMART_MANAGED_PRO,
            48,
            0,
            {Backend.SNMP},
            _SMP,
            verified=False,
        ),
        _model(
            "gs728tpp",
            # GS728TPP: 24x Gigabit PoE+ + 4x SFP combo = 28 total ports,
            # 24 PoE+ -- UNVERIFIED-pending-capture (port split assumed from
            # the product name's "28" port count and Gigabit PoE+ line
            # convention, not a capture).
            #
            # HTTP backend deliberately OMITTED even though this model's
            # web UI is real and reachable: certbot-hook-netgear-switches/
            # netgear-updater.py's GS728TPPUpdater (grounded prior art) shows
            # GS728TPP uses a THIRD, distinct login scheme -- a GET / redirect
            # to a per-session path, then GET {path}/System.xml?action=login&
            # user=...&password=... (not a POST), with userStatus/usernme/
            # sessionID cookies set from the response rather than via a
            # normal Set-Cookie login POST. That is neither MERGE_HASH_CGI,
            # GAMBIT, nor CHEETAH_FORM (registry.protocols.http.endpoints
            # .LoginScheme), and transport/http/client.py's login() only
            # knows how to drive those three. Registering Backend.HTTP here
            # without real scheme/transport support would either (a) fail
            # tests/protocols/http/test_endpoints.py::
            # test_every_http_model_has_a_spec, or (b) force picking an
            # existing (wrong) LoginScheme and have login() attempt a
            # garbage POST against a real switch -- both dishonest. Wiring
            # in a real LoginScheme.XML_API is a dedicated future slice, not
            # a registry-only change. SNMP-only here is sufficient for
            # gdoc2netcfg's SyncSwitch construction; only the SNMP vendor
            # OID family is UNVERIFIED-pending-capture.
            "GS728TPP",
            SwitchClass.SMART_MANAGED_PRO,
            28,
            24,
            {Backend.SNMP},
            _SMP,
            verified=False,
        ),
        _model(
            "gs105pe",
            # GS105PE: a real, DISTINCT SKU from gs305ep -- a 5-port Gigabit
            # "Smart Plus" switch (Gen-2 Broadcom BCM53125), per
            # ~/github/mithro/ai-shenanigans-for-netgear-smart-switches/
            # gs105pe.md. Backends {NSDP, HTTP} (no SNMP -- Plus switches
            # never expose SNMP): HTTP login uses the MERGE_HASH_CGI scheme,
            # identical to gs305ep, per netgear-smp-vlan (grounded prior art
            # -- see endpoints.py's HttpModelSpec for this model). That doc
            # also confirms a hard vendor limitation: this model exposes NO
            # MAC/FDB table over ANY interface (not NSDP, not the web UI --
            # a confirmed Netgear firmware limitation, not merely unread).
            #
            # PoE port count: the doc describes this model as having "PoE
            # pass-through" (it can itself be POWERED via PoE on port 5 and
            # pass that budget through), which is NOT the same claim as "acts
            # as a PSE delivering power to N downstream ports" -- no capture
            # or spec confirms how many (if any) of its OTHER 4 ports can
            # source PoE to a connected PD. Rather than fabricate a count
            # (unlike gs728tpp's port-count guess above, which at least had a
            # product-name convention to lean on), this is left at 0 --
            # UNVERIFIED-pending-capture, exactly like this section's other
            # spec-only entries.
            "GS105PE",
            SwitchClass.PLUS,
            5,
            0,
            {Backend.NSDP, Backend.HTTP},
            None,
            verified=False,
        ),
    )
}

MODELS: Mapping[str, SwitchModel] = MappingProxyType(_MODELS)


def get_model(key: str) -> SwitchModel:
    try:
        return _MODELS[key]
    except KeyError:
        raise UnknownModelError(f"unknown switch model: {key!r}") from None
