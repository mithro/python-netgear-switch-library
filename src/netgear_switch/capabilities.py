"""Which operation each model can perform over each backend, and why not.

This module answers one question -- *can model M do operation O over backend
B?* -- without touching a switch. It exists because that question has three
consumers who must never disagree:

* the **documentation**, whose model/backend support tables are generated from
  :func:`matrix` at build time (see ``docs/_ext/support_tables.py``) rather than
  hand-maintained, so a table can never quietly drift from the code;
* **callers**, who can ask ahead of a run whether an op is worth attempting
  (e.g. an inventory sweep that skips PoE on non-PSE models instead of
  collecting exceptions);
* the **test suite**, which pins every verdict here against what actually
  happens when the op is driven for real against the virtual switch (see
  ``tests/test_capabilities.py``).

**It derives, it does not duplicate.** Every verdict is read out of the same
objects the dispatch path consults -- ``SwitchModel`` fields, ``HTTP_SPECS``
endpoint paths, ``CLI_SPECS`` verification flags, ``scp_cert_profile`` -- and
several refusal reasons are the *literal* message constants the readers raise
(``nsdp_read._NO_POE`` and friends). Re-deriving support with a parallel
hand-written rule set would recreate exactly the failure mode principle 5 warns
about: two things that agree with each other while both disagree with the
device.

The verdicts mirror the facade's own resolution order (see
``_dispatch.resolve_backend``): a backend the model does not have is
:attr:`Support.NO_BACKEND` *before* any per-operation question is asked, because
that is the error ``SyncSwitch`` raises first.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING

from .registry import MODELS, Backend, get_model

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

    from .protocols.http.endpoints import HttpModelSpec
    from .registry import SwitchModel

__all__ = [
    "OPERATIONS",
    "READ_OPERATIONS",
    "WRITE_OPERATIONS",
    "Capability",
    "Operation",
    "OperationKind",
    "Support",
    "backends_for",
    "matrix",
    "operation",
    "support",
]


class Support(enum.Enum):
    """How a (model, backend, operation) triple is served -- or refused."""

    #: The backend implements this operation for this model.
    SUPPORTED = "supported"
    #: The model does not have this backend at all. This is what
    #: ``_dispatch.resolve_backend`` raises, before the operation is considered.
    NO_BACKEND = "no-backend"
    #: The model has the backend, but that backend cannot serve this operation
    #: -- either the protocol has no such notion (NSDP has no PoE tag) or the
    #: device genuinely lacks the hardware (no PSE ports). Never a stand-in for
    #: "not implemented yet": see principle 2 in ``CLAUDE.md``.
    UNSUPPORTED = "unsupported"
    #: Implemented, but gated off because the backend's per-model spec is not
    #: yet cross-verified against live hardware (``HttpModelSpec.reads_verified``
    #: / ``CliModelSpec.reads_verified`` / ``writes_verified``). The facade
    #: refuses to dispatch rather than return output nobody has checked.
    UNVERIFIED = "unverified"


class OperationKind(enum.Enum):
    READ = "read"
    WRITE = "write"


@dataclass(frozen=True)
class Operation:
    """One facade operation, as exposed by ``SyncSwitch``/``AsyncSwitch``."""

    #: The method name on the facade, e.g. ``"get_ports"``.
    name: str
    kind: OperationKind
    #: One-line description, reused as the table row label in the docs.
    summary: str
    #: Backends that can *ever* serve this op, for the few that bypass normal
    #: backend dispatch (``nsdp_device`` is NSDP-only; certificate upload is
    #: HTTP or CLI-over-SCP). ``None`` means "any backend the model has".
    backends: frozenset[Backend] | None = None


_CLI_BACKENDS = frozenset({Backend.SSH, Backend.TELNET, Backend.CONSOLE})

#: HTTP writes implemented by scraping the Plus dialect's CSRF token. A dialect
#: without that token cannot serve any of them -- see
#: ``endpoints.dialect_has_csrf_hash`` for the measurement.
#:
#: The XML-API dialect is exempt, and not as a special case: its writer posts an
#: XML body and never scrapes a token, so "does this UI carry an <input
#: name='hash'>" is not a question about it. Both ops are LIVE-VERIFIED there
#: (GS728TPP 10.2.5.10, VLAN 4001 created with its name, then deleted).
_CSRF_HTTP_WRITES = frozenset({"create_vlan", "delete_vlan"})

READ_OPERATIONS: tuple[Operation, ...] = (
    Operation("get_ports", OperationKind.READ, "Per-port link/admin status"),
    Operation("get_stats", OperationKind.READ, "Per-port octet/packet counters"),
    Operation(
        "get_vlans", OperationKind.READ, "VLAN list with tagged/untagged members"
    ),
    Operation("get_pvids", OperationKind.READ, "Per-port PVID"),
    Operation("get_lldp", OperationKind.READ, "LLDP neighbour table"),
    Operation("get_macs", OperationKind.READ, "MAC/FDB forwarding table"),
    Operation("get_poe", OperationKind.READ, "Per-port PoE status and power draw"),
    Operation("get_sensors", OperationKind.READ, "Fan/PSU/temperature sensors"),
    Operation("get_mgmt_ip", OperationKind.READ, "Management IP configuration"),
    Operation("get_hostname", OperationKind.READ, "The switch's host name"),
    Operation(
        "get_users",
        OperationKind.READ,
        "Local login accounts and their access level",
        # CLI and HTTP. SNMP stays out, deliberately: the S3300's vendor SNMP
        # user table holds ONE account where its own CLI lists two, so those two
        # backends do not report the same set, and claiming SNMP serves this
        # would assert an equivalence the hardware contradicts. Leaving it out
        # makes no cross-backend claim at all rather than a wrong one.
        #
        # HTTP was added 2026-08-03 off userManagement.html, live-read on
        # gsm7252ps and m4300-24x and cross-checked against each switch's own
        # `show users` (same two accounts, same order). Models whose UI has no
        # such page located -- every Plus SKU, the GS728TPP, and gsm7228ps,
        # whose host 404s that URL -- are filtered out by _http_path_for on a
        # null users_path, so the support table shows the hole instead of
        # claiming coverage.
        backends=frozenset({Backend.HTTP}) | _CLI_BACKENDS,
    ),
    Operation(
        "get_services",
        OperationKind.READ,
        "Which management services (http/https/telnet/ssh) are enabled",
        # CLI and HTTP; the SNMP/NSDP equivalents remain unlocated rather than
        # absent. HTTP was added 2026-08-03 off the four per-service config
        # pages, live cross-checked against `show ip http` / `show ip ssh` /
        # `show telnetcon` on gsm7252ps and m4300-24x -- every state agrees, and
        # so does every port the pages print.
        #
        # A model is offered this only when ALL FOUR pages are located
        # (_http_path_for defers to http_read._service_paths). gsm7228ps is the
        # reason: two of its four pages parse, the other two cannot be asked, and
        # reporting the two would read as "this switch has no SSH".
        backends=frozenset({Backend.HTTP}) | _CLI_BACKENDS,
    ),
    Operation(
        "get_syslog",
        OperationKind.READ,
        "Remote-logging configuration and collectors",
        # SNMP, HTTP and the CLI all READ this, and all three agree
        # field-for-field on live hardware.
        #
        # HTTP was added on 2026-08-03, replacing this comment's own claim that
        # "no dialect's syslog page has been located or captured yet" -- which
        # was true only of the search, not of the devices. Every managed switch
        # publishes ``syslogConfiguration.html`` in its nav JS, and all four
        # answered it live; the models WITHOUT it (the Plus SKUs and the
        # GS728TPP) are filtered out by _http_path_for on a null syslog_path.
        # NSDP genuinely has no logging tag -- that came from an exhaustive tag
        # sweep of a live GS110EMX, so it is measured absence, not an unsearched
        # one.
        backends=frozenset({Backend.SNMP, Backend.HTTP}) | _CLI_BACKENDS,
    ),
    Operation(
        "nsdp_device",
        OperationKind.READ,
        "Full NSDP device record",
        backends=frozenset({Backend.NSDP}),
    ),
)

WRITE_OPERATIONS: tuple[Operation, ...] = (
    Operation("set_port_enabled", OperationKind.WRITE, "Bring a port up or down"),
    Operation("set_poe", OperationKind.WRITE, "Enable or disable PoE on a port"),
    Operation("cycle_poe", OperationKind.WRITE, "Power-cycle a PoE port"),
    Operation("clear_poe_fault", OperationKind.WRITE, "Clear a latched PoE fault"),
    Operation(
        "set_port_description",
        OperationKind.WRITE,
        "Set or clear a port's description",
        # Every backend serves this, each grounded separately:
        #   SNMP  ifAlias -- writable, confirmed on a GS728TPP (a SET was
        #         accepted and read straight back)
        #   NSDP  tag 0xB000 PORT_NAME -- the READ encoding is measured on three
        #         GS110EMX units and the write is that same shape; the write
        #         itself is unexercised (those units were powered off), so
        #         verify-after-write is what makes it safe to offer
        #   CLI   `description '<text>'` / `no description` -- the quoted form is
        #         read off a live GSM7252PS's own running-config
        #   HTTP  interfaceDescription on the GoAhead ports page. Only that
        #         dialect: the FASTPATH XUI port pages have the column but its
        #         cell id was never captured, and the writer refuses by name
        #         rather than posting into a guessed cell.
    ),
    Operation(
        "set_port_speed",
        OperationKind.WRITE,
        "Force a port's speed/duplex, or restore auto-negotiation",
        # CLI and HTTP. The other two refuse BY NAME rather than being quietly
        # absent (see each writer's set_port_speed):
        #   SNMP  ifSpeed/ifHighSpeed report the NEGOTIATED rate; the MAU-MIB
        #         columns that would carry the setting have not been walked, so
        #         their presence is unknown rather than absent
        #   NSDP  the per-port speed byte is a LINK-STATE code (0x00 means DOWN)
        #
        # The CLI grammar is proven by execution on gsm7252ps 10.1.5.22 port
        # 1/0/8 (2026-08-03), including the switch REFUSING a forced 1000. HTTP
        # is the GoAhead XML API only, transcribed from the ports page's own
        # submit JS; _http_path_for filters every other dialect out, because the
        # FASTPATH XUI Speed control's cell id was never captured.
        #
        # The two backends deliberately DISAGREE about a forced 1000 -- the CLI
        # grammar omits it, the GoAhead dropdown offers it -- and each says so
        # for its own measured reason. That is what per-backend grounding looks
        # like when it is done properly rather than harmonised into a guess.
        backends=frozenset({Backend.HTTP}) | _CLI_BACKENDS,
    ),
    Operation(
        "set_flow_control",
        OperationKind.WRITE,
        "Turn IEEE 802.3x flow control on or off for a port",
        # CLI only, and the other three refuse by name for reasons that differ:
        #   SNMP  dot3PauseAdminMode is READ on the one model that publishes it,
        #         but no SET has ever been issued against it here
        #   NSDP  the flow-control byte is read; no write tag is identified
        #   HTTP  MEASURED absence -- the GoAhead ports page publishes
        #         flowControlAdminType/OperType but has NO control for either,
        #         and its submit builder emits no flow-control field at all
        #
        # The CLI form is a bare `flowcontrol` / `no flowcontrol` toggle,
        # round-tripped on gsm7252ps 10.1.5.22 port 1/0/8 (2026-08-03).
        backends=_CLI_BACKENDS,
    ),
    Operation("set_pvid", OperationKind.WRITE, "Set a port's PVID"),
    Operation(
        "set_vlan_membership",
        OperationKind.WRITE,
        "Set a port tagged/untagged/excluded on a VLAN",
    ),
    Operation("create_vlan", OperationKind.WRITE, "Create a VLAN"),
    Operation("delete_vlan", OperationKind.WRITE, "Delete a VLAN"),
    Operation("set_mgmt_ip", OperationKind.WRITE, "Set the management IP/mask/gateway"),
    Operation(
        "set_hostname",
        OperationKind.WRITE,
        "Set the switch's host name",
        # SNMP (sysName), NSDP (tag 0x0003) and the FASTPATH CLI (`hostname`),
        # each confirmed writable against real hardware:
        #
        #   SNMP  all five reachable switches accepted a SET of the value they
        #         already held -- a zero-impact writability probe
        #   NSDP  live round trip on gs110emx3 (10.1.5.27): recorded the prior
        #         name, wrote a throwaway, read it back, restored, re-read
        #   CLI   round-trips on all four CLI models
        #
        # That closes the Plus-model hole this restriction used to expose: every
        # registered model now has at least one backend that can rename it.
        #
        # HTTP joined them for the GoAhead XML API only (2026-08-03), where
        # DeviceBasicInfo/deviceName IS the host name -- measured reading
        # byte-for-byte what SNMP reports through sysName. The other dialects
        # are filtered out by _http_path_for.
        #
        # CORRECTION 2026-08-05: this used to say the gs110emx and gs105pe
        # identity pages carry "a switch_name field but no captured write
        # form". That is wrong -- both committed fixtures contain a complete
        # POST form around it:
        #
        #   gs110emx_sysinfo.html      <form method="post"
        #       ACTION="/iss/specific/sysInfo.html">  switch_name, dhcp_mode,
        #       IP_ADDRESS, SUBNET_MASK, GATEWAY_ADDRESS, Gambit, refreshFlag
        #   gs105pe_switch_info.html   <form method="post"
        #       action="/switch_info.cgi">  switch_name, dhcpMode, ip_address,
        #       subnet_mask, gateway_address, hash
        #
        # It is still NOT offered, for a different and better reason: that one
        # form submits the host name TOGETHER with the management IP, so a
        # rename must read-modify-write every other field back verbatim, and a
        # mistake strands the switch on an address nobody can reach. Both units
        # are powered off, so it cannot be proven -- and this is the one write
        # where shipping unproven is not acceptable. See task #67.
        backends=frozenset({Backend.SNMP, Backend.NSDP, Backend.HTTP}) | _CLI_BACKENDS,
    ),
    Operation(
        "set_syslog_enabled",
        OperationKind.WRITE,
        "Turn remote logging on or off",
        # SNMP only, and deliberately narrow. The vendor logging admin-mode
        # column was confirmed WRITABLE on m4300-24x, gsm7252ps and gsm7228ps
        # by SETting each the value it already held -- a probe that cannot
        # change device state but still separates a writable column from a
        # read-only one. A model with no 4526 vendor subtree (gs728tpp) has
        # nothing to write, and _snmp_support refuses it there by name.
        #
        # This op existed on the facade with NO entry here at all, so
        # ``support(model, backend, "set_syslog_enabled")`` raised KeyError and
        # the published support matrix simply omitted it -- an operation the
        # library offers and the capability table did not know about.
        #
        # The CLI joined it on 2026-08-05, closing a parity gap: `logging
        # syslog` is printed VERBATIM in every FASTPATH switch's own
        # running-config, so the command form was learned read-only rather than
        # probed. (The `no` negation is the standard FASTPATH form and is
        # inferred; a wrong one is rejected loudly by CliWriter._run.)
        backends=frozenset({Backend.SNMP}) | _CLI_BACKENDS,
    ),
    Operation(
        "add_syslog_collector",
        OperationKind.WRITE,
        "Add a remote syslog collector",
        # CLI only. The command form is VERBATIM from `show running-config` on
        # all four FASTPATH models (2026-08-05, read-only):
        #     logging host "10.1.5.1" ipv4 514 info
        # LIVE-VERIFIED on all four by adding and removing a TEST-NET-1 address.
        # CLI ONLY, and both other candidates refuse for MEASURED reasons:
        #   SNMP  the agent will not create a row -- five mechanisms, all
        #         refused with captured SMI errors (see SnmpWriter)
        #   HTTP  the M4300 page's template row is reachable and the body can be
        #         built, but the firmware answers "Failed to Set 'Host Address'"
        #         and the table does not change (see HttpWriter). Its DELETE on
        #         the same page works and IS offered.
        #   NSDP  no logging surface at all.
        backends=_CLI_BACKENDS,
    ),
    Operation(
        "remove_syslog_collector",
        OperationKind.WRITE,
        "Remove a remote syslog collector",
        # CLI *and* SNMP, and the asymmetry with add is the AGENT's, measured
        # rather than assumed: it refuses to CREATE a syslog host row through
        # every mechanism but honours RowStatus destroy(6) on an existing one
        # (live on m4300-24x 10.1.5.13, 2026-08-05).
        #
        # CLI: `logging host remove <index>` -- a SUBCOMMAND, not the negation
        # it looks like; `no logging host ...` is rejected in every spelling.
        # Both backends address the table's OWN Index, which is SPARSE, so both
        # read it fresh rather than counting rows.
        #
        # HTTP (M4300 XUI) needs no index at all: it marks the target row's own
        # write-only row-status cell "Delete" and clicks the page's Delete
        # button, addressing the row by its rendered fields.
        backends=frozenset({Backend.SNMP, Backend.HTTP}) | _CLI_BACKENDS,
    ),
    Operation(
        "upload_certificate",
        OperationKind.WRITE,
        "Upload an HTTPS certificate over the web UI",
        backends=frozenset({Backend.HTTP}),
    ),
    Operation(
        "upload_certificate_scp",
        OperationKind.WRITE,
        "Deploy an HTTPS certificate via FASTPATH ``copy scp://``",
        backends=_CLI_BACKENDS,
    ),
)

OPERATIONS: tuple[Operation, ...] = READ_OPERATIONS + WRITE_OPERATIONS

_BY_NAME: Mapping[str, Operation] = MappingProxyType({o.name: o for o in OPERATIONS})


def operation(name: str) -> Operation:
    """Look an :class:`Operation` up by facade method name."""
    try:
        return _BY_NAME[name]
    except KeyError:
        raise KeyError(f"unknown operation: {name!r}") from None


@dataclass(frozen=True)
class Capability:
    """The verdict for one (model, backend, operation) triple."""

    model_key: str
    backend: Backend
    operation: Operation
    support: Support
    #: Empty when :attr:`support` is :attr:`Support.SUPPORTED`; otherwise the
    #: reason, phrased the way the corresponding reader/writer phrases it.
    reason: str = ""

    @property
    def supported(self) -> bool:
        return self.support is Support.SUPPORTED


# --- per-backend derivations -------------------------------------------------
#
# Each returns (Support, reason). They read the SAME spec objects the readers
# and writers read; nothing here re-states a rule that lives elsewhere.

_POE_OPS = frozenset({"get_poe", "set_poe", "cycle_poe", "clear_poe_fault"})


def _no_pse(model: SwitchModel) -> tuple[Support, str]:
    return (
        Support.UNSUPPORTED,
        f"{model.display_name} has no PSE ports, so it has no PoE to report or set",
    )


def _snmp_support(model: SwitchModel, op: Operation) -> tuple[Support, str]:
    # SnmpReader/SnmpWriter serve almost everything from standard MIBs; the
    # model-dependent refusals are the guards they raise themselves.
    from .protocols.snmp import oids

    if op.name in _POE_OPS and model.poe_port_count == 0:
        return _no_pse(model)
    if op.name == "set_mgmt_ip" and not oids.has_vendor_oids(model):
        # SnmpWriter.set_mgmt_ip writes the vendor mgmt-IP columns, so a model
        # whose agent registers no 4526 subtree at all (the GS728TPP -- a walk
        # of 1.3.6.1.4.1.4526 answers noSuchObject) has nothing to write. The
        # READ path has a standard-MIB fallback (ipAddrTable); the write does
        # not, because no standard writable equivalent was found.
        return (
            Support.UNSUPPORTED,
            f"model {model.key!r} registers no Netgear vendor OID subtree, and "
            "the management-IP write columns are vendor-only",
        )
    if op.name in (
        "get_syslog",
        "set_syslog_enabled",
        # The RowStatus destroy writes <vendor base>.14.1.4.5.1.7, so a model
        # with no vendor subtree (gs728tpp) cannot serve it either -- and
        # SnmpWriter.remove_syslog_collector refuses it by name for that reason.
        "remove_syslog_collector",
    ) and not oids.has_vendor_oids(model):
        # Logging lives at <vendor base>.14 on both vendor families, so a model
        # whose agent registers no 4526 subtree at all (gs728tpp -- a walk of
        # 1.3.6.1.4.1.4526 answers noSuchObject) has nothing to read OR write.
        # SnmpReader.get_syslog and SnmpWriter.set_syslog_enabled both refuse by
        # name for the same reason: an empty result would be indistinguishable
        # from a switch with no collectors, and a write has no column to land in.
        return (
            Support.UNSUPPORTED,
            f"model {model.key!r} registers no Netgear vendor OID subtree, and "
            "the logging columns are vendor-only",
        )
    if op.name == "create_vlan" and not model.snmp_can_create_vlan:
        # Reuse the writer's own refusal text so the table and the code that
        # enforces it cannot drift apart.
        from .snmp_write import _NO_VLAN_CREATE

        return Support.UNSUPPORTED, f"model {model.key!r}: {_NO_VLAN_CREATE}"
    if op.name == "get_macs" and not model.has_mac_table:  # pragma: no cover
        # Unreachable today: has_mac_table IS "has an SNMP backend". Kept so the
        # rule tracks the property rather than assuming its current definition.
        return Support.UNSUPPORTED, f"model {model.key!r} has no MAC/FDB table"
    return Support.SUPPORTED, ""


def _nsdp_support(model: SwitchModel, op: Operation) -> tuple[Support, str]:
    # Reasons are the reader's/writer's own message constants, so a change to
    # what NSDP refuses updates this table in the same edit.
    from . import nsdp_read, nsdp_write

    refusals = {
        "get_macs": nsdp_read._NO_MACS,
        "get_lldp": nsdp_read._NO_LLDP,
        "get_sensors": nsdp_read._NO_SENSORS,
        "get_poe": nsdp_read._NO_POE,
        "set_poe": nsdp_write._NO_POE,
        "cycle_poe": nsdp_write._NO_POE,
        "clear_poe_fault": nsdp_write._NO_POE,
        "set_port_enabled": nsdp_write._NO_PORT_ADMIN,
    }
    reason = refusals.get(op.name)
    if reason is not None:
        return Support.UNSUPPORTED, reason
    return Support.SUPPORTED, ""


#: Writes the XML-API (GoAhead ``wcd``) writer actually implements, each with a
#: body builder GROUNDED in the page's own JavaScript. An op absent here is
#: honestly unsupported on this dialect -- not "probably works": the endpoint
#: is shared, so a missing entry means nobody has established what body that
#: operation sends, and guessing one would write something unintended.
_XML_API_WRITES = {
    "set_vlan_membership": True,
    "set_port_enabled": True,
    "set_poe": True,
    "set_pvid": True,
    "create_vlan": True,
    "delete_vlan": True,
    # No reset control exists on this UI (its PoE page has only Refresh/Cancel/
    # Apply, and Behaviour/UnitsPoe.js has no reset action), so these are an
    # admin off/on re-arm of the same field -- the mechanism SnmpWriter already
    # uses on agents with no reset column.
    "cycle_poe": True,
    "clear_poe_fault": True,
    "set_port_description": True,
    "set_hostname": True,
    # Standard802_3List's autoNegotiationAdminEnabled/speedAdmin/
    # duplexAdminMode, encoded exactly as the ports page's own submit JS does.
    "set_port_speed": True,
}


def _http_path_for(spec: HttpModelSpec, op: Operation) -> str | None:
    """The endpoint ``op`` needs, or ``None`` if this model's UI has no such page.

    The mapping mirrors ``http_read``/``http_write`` one line at a time; the two
    ops with composite conditions defer to the reader's own helpers so there is
    exactly one definition of "this UI can answer that".
    """
    from .http_read import _has_sysinfo_hostname, _mgmt_ip_path, _supports_sensors
    from .http_write import _is_xml_api_dialect
    from .protocols.http.endpoints import HtmlDialect

    if _is_xml_api_dialect(spec) and op.kind is OperationKind.WRITE:
        # On an XML-API UI every write POSTs to one endpoint and the BODY
        # selects the operation, so "is there a page for this op" is the wrong
        # question -- there is no per-op page, and answering it with the op's
        # READ path would claim support for any write whose data can be read.
        # That is not hypothetical: set_pvid was reported SUPPORTED on the
        # GS728TPP purely because pvid_path exists, while the writer would have
        # posted a Plus-class CGI form at a wcd query string.
        #
        # Certificate upload keeps its own path: it is a distinct XML flow with
        # its own grounding and its own response check.
        if op.name == "upload_certificate":
            return spec.cert_upload_path
        return spec.xml_write_path if _XML_API_WRITES.get(op.name) else None

    simple: dict[str, str | None] = {
        "get_ports": spec.dashboard_path,
        "get_stats": spec.stats_path,
        "get_poe": spec.poe_status_path,
        "get_pvids": spec.pvid_path,
        "get_vlans": spec.vlan_config_path,
        "get_macs": spec.mac_table_path,
        "get_lldp": spec.lldp_path,
        "get_syslog": spec.syslog_path,
        "get_users": spec.users_path,
        "set_poe": spec.poe_config_path,
        "cycle_poe": spec.poe_config_path,
        "clear_poe_fault": spec.poe_config_path,
        "set_pvid": spec.pvid_path,
        "set_vlan_membership": spec.vlan_membership_path,
        "create_vlan": spec.vlan_config_path,
        "delete_vlan": spec.vlan_config_path,
        "set_port_enabled": spec.port_config_path,
        # Only the XML-API dialect has a grounded description write; every other
        # dialect is handled by the branch above returning None for it.
        "set_port_description": None,
        # Same shape: the FASTPATH XUI Speed control's cell id was never
        # captured, so only the XML-API branch above answers for this op.
        "set_port_speed": None,
        # No dialect has a captured flow-control write form -- including the
        # XML-API one, whose ports page reports the field but offers no control
        # for it (the _XML_API_WRITES entry is absent for the same reason).
        "set_flow_control": None,
        # Only the M4300 XUI pages render the v_g_* template row AND inline the
        # cell metadata the write depends on; the other dialects' syslog pages
        # do neither, so they are refused rather than posted at on an
        # assumption. HttpWriter._syslog_page enforces the same rule, so there
        # is one definition of "this UI can be written".
        # The add is refused on every dialect -- the M4300 firmware rejects the
        # body (see HttpWriter.add_syslog_collector) and the others render no
        # usable template row at all.
        "add_syslog_collector": None,
        "remove_syslog_collector": (
            spec.syslog_path if spec.html_dialect is HtmlDialect.M4300 else None
        ),
        # The GS110EMX sysInfo form carries switch_name, so that dialect has a
        # grounded (and live-verified) host-name write; every other non-XML-API
        # dialect is None. gs105pe's switch_info.cgi has the same field but its
        # own CSRF-hash envelope, which has not been driven.
        "set_hostname": (
            spec.sysinfo_path if spec.html_dialect is HtmlDialect.GS110EMX else None
        ),
        "upload_certificate": spec.cert_upload_path,
    }
    if op.name == "get_sensors":
        return spec.sysinfo_path if _supports_sensors(spec) else None
    if op.name == "get_services":
        # All four pages or none -- the reader's own predicate decides, so
        # there is one definition of "this UI can be asked" rather than two.
        from .http_read import _service_paths

        paths = _service_paths(spec)
        return paths[0][1] if paths else None
    if op.name == "get_hostname":
        # Only two identity pages carry the field (gs110emx's sysInfo.html and
        # gs105pe's switch_info.cgi); the reader's own predicate decides, so
        # there is one definition rather than two that can drift.
        return spec.sysinfo_path if _has_sysinfo_hostname(spec) else None
    if op.name == "get_mgmt_ip":
        return _mgmt_ip_path(spec)
    if op.name == "set_mgmt_ip":
        # The XUI write needs the field map as well as the page.
        return spec.mgmt_ip_path if spec.mgmt_ip_fields is not None else None
    return simple[op.name]


def _http_support(model: SwitchModel, op: Operation) -> tuple[Support, str]:
    from .http_write import CERT_UPLOAD_KNOWN_UNIMPLEMENTED, _is_xml_api_dialect
    from .protocols.http.endpoints import dialect_has_csrf_hash, http_spec

    spec = http_spec(model)
    if not spec.reads_verified:
        # The facade gates BOTH reads and writes on reads_verified (see
        # sync_api._reader_for/_writer_for): output nobody has cross-verified
        # against hardware is not dispatched at all.
        return (
            Support.UNVERIFIED,
            f"model {model.key!r} HTTP reads are UNVERIFIED-pending-capture",
        )
    if op.name == "upload_certificate":
        # These models CAN take a certificate -- just not over HTTP. The facade
        # raises NotImplementedError naming the real mechanism rather than
        # UnsupportedCapabilityError, precisely so the difference is visible;
        # the table says the same thing and points at the op that does work.
        mechanism = CERT_UPLOAD_KNOWN_UNIMPLEMENTED.get(model.key)
        if mechanism is not None:
            return (
                Support.UNSUPPORTED,
                f"this model takes a certificate by {mechanism}, not over the "
                "web UI -- use upload_certificate_scp",
            )
    if (
        op.name in _CSRF_HTTP_WRITES
        and not _is_xml_api_dialect(spec)
        and not dialect_has_csrf_hash(spec.html_dialect)
    ):
        # These writers scrape an <input name="hash"> before posting, and this
        # dialect's pages do not carry one -- MEASURED on gsm7252ps and
        # gs110emx, see endpoints.dialect_has_csrf_hash. Driving them raises
        # HttpUnexpectedPageError on real hardware, so claiming support here
        # would publish a support table that contradicts the device.
        return (
            Support.UNSUPPORTED,
            f"model {model.key!r} web UI carries no CSRF 'hash' token, which "
            f"the HTTP {op.name} writer requires",
        )
    path = _http_path_for(spec, op)
    if path is None:
        return (
            Support.UNSUPPORTED,
            f"model {model.key!r} web UI has no page for {op.name} ({op.summary})",
        )
    return Support.SUPPORTED, ""


def _cli_support(model: SwitchModel, op: Operation) -> tuple[Support, str]:
    from ._dispatch import cli_reads_supported, cli_writes_supported
    from .errors import UnsupportedCapabilityError
    from .protocols.cli.commands import scp_cert_profile

    if op.kind is OperationKind.READ and not cli_reads_supported(model):
        return (
            Support.UNVERIFIED,
            f"model {model.key!r} CLI reads are UNVERIFIED-pending cross-verify",
        )
    if op.kind is OperationKind.WRITE and not cli_writes_supported(model):
        return (
            Support.UNVERIFIED,
            f"model {model.key!r} CLI writes are UNVERIFIED-pending a live write run",
        )
    if op.name == "upload_certificate_scp":
        # The facade dispatches on this exact call, so ask it rather than
        # re-listing which models have a copy-scp profile.
        try:
            scp_cert_profile(model)
        except UnsupportedCapabilityError as exc:
            return Support.UNSUPPORTED, str(exc)
        return Support.SUPPORTED, ""
    if op.name in _POE_OPS and model.poe_port_count == 0:
        return _no_pse(model)
    if op.name == "get_macs" and not model.has_mac_table:  # pragma: no cover
        return Support.UNSUPPORTED, f"model {model.key!r} CLI has no MAC/FDB table"
    return Support.SUPPORTED, ""


def support(
    model: SwitchModel | str, backend: Backend, op: Operation | str
) -> Capability:
    """The verdict for one triple. ``model``/``op`` accept keys or objects."""
    m = get_model(model) if isinstance(model, str) else model
    o = operation(op) if isinstance(op, str) else op

    if backend not in m.backends:
        have = ", ".join(sorted(b.name for b in m.backends))
        reason = f"model {m.key!r} has no {backend.name} backend (it has: {have})"
        if backend is Backend.CONSOLE:
            # Never registered on a model: the serial console is a TRANSPORT for
            # the CLI backend, not a network-reachable backend of its own (see
            # registry.Backend). Say so, rather than implying the CLI is absent.
            reason = (
                "CONSOLE is a serial transport for the CLI backend, not a "
                "network backend; a model's CLI support is its SSH/TELNET entry"
            )
        return Capability(m.key, backend, o, Support.NO_BACKEND, reason)

    if o.backends is not None and backend not in o.backends:
        allowed = ", ".join(sorted(b.name for b in o.backends))
        return Capability(
            m.key,
            backend,
            o,
            Support.UNSUPPORTED,
            f"{o.name} is served only over {allowed}",
        )

    if backend is Backend.SNMP:
        verdict, reason = _snmp_support(m, o)
    elif backend is Backend.NSDP:
        verdict, reason = _nsdp_support(m, o)
    elif backend is Backend.HTTP:
        verdict, reason = _http_support(m, o)
    else:
        verdict, reason = _cli_support(m, o)
    return Capability(m.key, backend, o, verdict, reason)


def backends_for(model: SwitchModel | str) -> tuple[Backend, ...]:
    """The model's backends in the facade's default-preference order."""
    m = get_model(model) if isinstance(model, str) else model
    order = (
        Backend.SNMP,
        Backend.NSDP,
        Backend.HTTP,
        Backend.SSH,
        Backend.TELNET,
        Backend.CONSOLE,
    )
    return tuple(b for b in order if b in m.backends)


def matrix(
    models: Iterator[str] | tuple[str, ...] | None = None,
    operations: tuple[Operation, ...] = OPERATIONS,
) -> tuple[Capability, ...]:
    """Every verdict for ``models`` x their backends x ``operations``.

    Defaults to every registered model. Only backends a model actually has are
    included, so the result never carries :attr:`Support.NO_BACKEND` rows.
    """
    keys = tuple(MODELS) if models is None else tuple(models)
    return tuple(
        support(key, backend, op)
        for key in keys
        for backend in backends_for(key)
        for op in operations
    )
