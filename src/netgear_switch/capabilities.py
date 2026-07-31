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


def _http_path_for(spec: HttpModelSpec, op: Operation) -> str | None:
    """The endpoint ``op`` needs, or ``None`` if this model's UI has no such page.

    The mapping mirrors ``http_read``/``http_write`` one line at a time; the two
    ops with composite conditions defer to the reader's own helpers so there is
    exactly one definition of "this UI can answer that".
    """
    from .http_read import _mgmt_ip_path, _supports_sensors

    simple: dict[str, str | None] = {
        "get_ports": spec.dashboard_path,
        "get_stats": spec.stats_path,
        "get_poe": spec.poe_status_path,
        "get_pvids": spec.pvid_path,
        "get_vlans": spec.vlan_config_path,
        "get_macs": spec.mac_table_path,
        "get_lldp": spec.lldp_path,
        "set_poe": spec.poe_config_path,
        "cycle_poe": spec.poe_config_path,
        "clear_poe_fault": spec.poe_config_path,
        "set_pvid": spec.pvid_path,
        "set_vlan_membership": spec.vlan_membership_path,
        "create_vlan": spec.vlan_config_path,
        "delete_vlan": spec.vlan_config_path,
        "set_port_enabled": spec.port_config_path,
        "upload_certificate": spec.cert_upload_path,
    }
    if op.name == "get_sensors":
        return spec.sysinfo_path if _supports_sensors(spec) else None
    if op.name == "get_mgmt_ip":
        return _mgmt_ip_path(spec)
    if op.name == "set_mgmt_ip":
        # The XUI write needs the field map as well as the page.
        return spec.mgmt_ip_path if spec.mgmt_ip_fields is not None else None
    return simple[op.name]


def _http_support(model: SwitchModel, op: Operation) -> tuple[Support, str]:
    from .http_write import CERT_UPLOAD_KNOWN_UNIMPLEMENTED
    from .protocols.http.endpoints import http_spec

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
