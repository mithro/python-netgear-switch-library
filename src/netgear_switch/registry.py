"""Declarative registry of known Netgear switch models."""

from __future__ import annotations

import enum
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING

from .errors import UnknownModelError

if TYPE_CHECKING:
    from collections.abc import Mapping

_FM = "1.3.6.1.4.1.4526.10"  # Fully Managed vendor subtree (M4300, GSM7252PS)
_SMP = "1.3.6.1.4.1.4526.11"  # Smart Managed Pro vendor subtree (S3300/GSM7228PS)


class Backend(enum.Enum):
    SNMP = "snmp"
    NSDP = "nsdp"
    HTTP = "http"
    # FASTPATH command-line interface, reachable over three transports. SSH and
    # TELNET are network backends registered on the FASTPATH models below;
    # CONSOLE is the same CLI over a physical serial line (a transport option,
    # not a network-reachable backend, so it is not registered on any model).
    SSH = "ssh"
    TELNET = "telnet"
    CONSOLE = "console"


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
    # UNVERIFIED-pending-capture entries below (m7300, xs748t) for the honesty
    # rationale; do NOT flip this to True without a real capture. (gs728tpp was
    # one of these until a real SNMP capture resolved its OID family -- see its
    # entry.)
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
            # port_count=28 is a nominal upper bound; the live XSM4324CS reports
            # only 24 physical ports (1/0/1..24; SNMP/CLI capture 2026-07-29).
            # Left at 28 because it also sizes the verified HTTP VLAN-membership
            # bitmap and SNMP/NSDP port bitmaps -- changing it risks regressing
            # those. CLI get_stats iterates the switch's ACTUAL physical ports
            # (see cli_read.CliReader.get_stats), so it does not depend on this.
            28,
            0,
            {Backend.SNMP, Backend.HTTP, Backend.SSH, Backend.TELNET},
            _FM,
        ),
        _model(
            "m4300-16x",
            "M4300-16X (XSM4316)",
            SwitchClass.FULLY_MANAGED,
            16,
            16,
            {Backend.SNMP, Backend.HTTP, Backend.SSH, Backend.TELNET},
            _FM,
        ),
        # HTTP added 2026-07-23: the XE FASTPATH web UI (login live-validated
        # on 10.1.5.22; read pages grounded in tests/fixtures/http/
        # gsm7252ps_*.html) covers EVERY read op this model supports, sensors
        # and mgmt-IP included. HTTP only joins read dispatch once the spec's
        # reads_verified flips after the live cross-verify -- see
        # protocols/http/endpoints.py's _GSM7252PS.
        _model(
            "gsm7252ps",
            "GSM7252PS",
            SwitchClass.FULLY_MANAGED,
            52,
            48,
            {Backend.SNMP, Backend.HTTP, Backend.SSH, Backend.TELNET},
            _FM,
        ),
        _model(
            "gsm7228ps",
            "GSM7228PS (S3300)",
            SwitchClass.SMART_MANAGED_PRO,
            52,
            48,
            # TELNET (not SSH): the S3300-52X's FASTPATH CLI is reachable over
            # telnet on the NON-STANDARD port 60000 (not 23) -- live-verified
            # 2026-07-30 on 10.1.5.11 (login admin+password, prompt
            # "(manage-sw-netgear-s3300-1) >"), with a full read sweep captured
            # into tests/fixtures/cli/gsm7228ps_*.txt. SSH is genuinely ABSENT:
            # the switch runs no ssh listener on any port (its SNMP tcpConnTable
            # shows only 80/443/60000). So the CLI backend is TELNET only; the
            # telnet transport dials CliModelSpec.telnet_port=60000.
            {Backend.SNMP, Backend.HTTP, Backend.TELNET},
            _SMP,
            # VERIFIED 2026-07-30 against real hardware: the S3300-52X-PoE+
            # (sw-netgear-s3300-1 @ 10.1.5.11, sysObjectID 4526.100.10.19). The
            # live capture (tests/fixtures/captures/gsm7228ps.json) CONFIRMED
            # the _SMP (4526.11) vendor family is correct here -- unlike
            # gs728tpp (which had zero 4526 OIDs), this switch's fan/temp/PoE
            # vendor data really does live under 4526.11.43, and all 9 read
            # ops cross-verified SNMP<->mock. Its sysDescr "S3300-52X-PoE+" is
            # auto-detected via SYSOBJECTID_MODELS (the OID map), since the
            # text is deliberately unmatchable (same shape as the unregistered
            # S3300-28X). Registered key is gsm7228ps; "s3300" is an alias
            # (see MODEL_ALIASES). NOTE 4526.100.10.19 is the product-ID OID,
            # distinct from the 4526.11 vendor DATA subtree.
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
        # these two models (gdoc2netcfg fleet models with no prior-art
        # fixture). Registered from spec sheets/product briefs only so
        # gdoc2netcfg can construct a SyncSwitch for them; see each entry's
        # comment for what specifically is a guess. The model-agnostic
        # standard-MIB SNMP reads (ports/vlans/lldp/PoE admin/stats/mgmt-IP)
        # should work regardless of the vendor OID family guess below, but
        # get_sensors() and vendor PoE-power readings are UNVERIFIED until a
        # real capture confirms the 4526.10 vs 4526.11 subtree. Do NOT treat
        # either of these as a source of confirmed behaviour -- confirm via
        # hardware verification before relying on anything beyond the standard
        # MIBs. (gs728tpp, once in this group, is now verified: a real SNMP
        # capture resolved its OID family to "none, standard MIBs only".)
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
            # HTTP backend NOW IMPLEMENTED (was deliberately omitted). This
            # model's web UI uses a THIRD, distinct login scheme --
            # LoginScheme.XML_API, the GoAhead ``wcd`` XML API: a GET /
            # redirect to a per-session path, then GET {path}/System.xml?
            # action=login&user=...&password=... (not a POST) yielding
            # <statusCode>0</statusCode> + a sessionID response header, with
            # userStatus/usernme/sessionID cookies set from that response.
            # Grounded in certbot-hook-netgear-switches/netgear-updater.py's
            # GS728TPPUpdater AND real captures of the live switch 10.2.5.10;
            # transport/http/client.py's login() now drives it and
            # protocols/http/endpoints.py::_GS728TPP carries the wcd read
            # queries (HtmlDialect.GOAHEAD_XML). The web reads are
            # reads_verified=True: every parse_goahead_* was run on a FRESH live
            # wcd fetch from 10.2.5.10 (via the ten64 jump host) on 2026-07-29
            # and cross-checked against the switch's actual config -- 28 ports,
            # 24 PoE, real VLAN names/PVIDs/membership, MAC table, 4 real LLDP
            # neighbours, fan/PSU sensors, mgmt-IP 10.2.5.10. (Cross-checked vs
            # the switch's ground truth, not vs SNMP, since this model's SNMP
            # OID family is itself UNVERIFIED-pending-capture.)
            #
            # SNMP now RESOLVED by a real live capture (10.2.5.10, 2026-07-29 --
            # tmp/gs728tpp_snmp_full.json): this agent implements ZERO Netgear
            # vendor OIDs -- a walk of 1.3.6.1.4.1.4526 answers noSuchObject
            # (sysObjectID 4526.100.4.27 is just an identifier value). It serves
            # EVERYTHING via standard MIBs, so snmp_vendor_base=None: per-port
            # PoE via RFC3621 pethPsePortTable, mgmt-IP via ipAddrTable, and the
            # fan/PSU sensor INVENTORY via ENTITY-MIB entPhysical (there is NO
            # live sensor value/status anywhere in SNMP on this model). The SNMP
            # reader's standard-MIB code paths (snmp_read.get_poe/get_sensors/
            # get_mgmt_ip guard on oids.has_vendor_oids) cover all three.
            # verified=True: SNMP<->HTTP parity is cross-verified for ports/
            # vlans/pvids/macs/lldp/poe(admin+detect)/mgmt-IP (see
            # tests/test_cross_backend_equivalence.py). Two honest per-backend
            # differences remain (not bugs): SNMP has no per-port PoE mW column
            # (power_mw None vs HTTP's live 0), and SNMP sensors are inventory-
            # only (no live health status the HTTP DiagnosticsUnitList reports).
            # get_stats over HTTP is honestly UnsupportedCapabilityError
            # (per-port stats are SNMP-only on this UI).
            "GS728TPP",
            SwitchClass.SMART_MANAGED_PRO,
            28,
            24,
            {Backend.SNMP, Backend.HTTP},
            None,
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
            # LIVE-VERIFIED 2026-07-21 against real GS105PE units (poe-micro2/3
            # @ 10.1.5.29/.30): NSDP reports MODEL="GS105PE", port_count=5,
            # firmware V1.6.0.x. All NSDP reads (ports/stats/VLANs/PVIDs/mgmt +
            # full get_device) confirmed live -- see seed_gs105pe() and the
            # two real NSDP bugs this model exposed (parse_device MODEL
            # requirement + variable-width PORT_MIRRORING).
            #
            # PoE port count = 0, now CONFIRMED (not merely unverified): the
            # web UI's getPoePortStatus.cgi returns HTTP 404 on the real unit,
            # i.e. it exposes no PSE PoE-status page. The product's "PoE
            # pass-through" (it can be POWERED via PoE) is not a PSE claim, so
            # it sources power to no downstream ports -> 0.
            "GS105PE",
            SwitchClass.PLUS,
            5,
            0,
            {Backend.NSDP, Backend.HTTP},
            None,
            verified=True,
        ),
    )
}

MODELS: Mapping[str, SwitchModel] = MappingProxyType(_MODELS)

# Alternate model-name keys that resolve to the same canonical SwitchModel via
# get_model(). "s3300" <-> "gsm7228ps": the model registered under the canonical
# key "gsm7228ps" is really the S3300-52X-PoE+ (its real firmware sysDescr and
# marketing name are "S3300-52X"; GSM7228PS is the ProSAFE part-number family),
# so both names must resolve to it -- inventories, the CLI's --model, and any
# caller may use either. Aliases are deliberately NOT added to MODELS, which
# stays a canonical one-key-per-model listing (what tests, the MCP model list
# and CLI iterate); they are resolved only on lookup.
MODEL_ALIASES: Mapping[str, str] = MappingProxyType(
    {
        "s3300": "gsm7228ps",
    }
)


def get_model(key: str) -> SwitchModel:
    canonical = MODEL_ALIASES.get(key, key)
    try:
        return _MODELS[canonical]
    except KeyError:
        raise UnknownModelError(f"unknown switch model: {key!r}") from None
