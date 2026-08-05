"""Pin ``netgear_switch.capabilities`` to what the library actually does.

The support tables in the documentation are generated from
``src/netgear_switch/capabilities.py`` (see ``docs/_ext/support_tables.py``), so
a wrong verdict there is a published lie rather than a private bug. These tests
therefore do not check the module against a second hand-written table -- that
would only prove two hand-written tables agree. They **drive every operation for
real** against the virtual switch, one backend at a time, and assert that the
static verdict predicted the outcome.

"Refused" means exactly two exceptions:

* ``UnsupportedCapabilityError`` -- this backend cannot serve this operation.
* ``NotImplementedError`` -- raised only by ``upload_certificate`` on a model
  whose certificate mechanism is SCP rather than the web UI. The distinction is
  deliberate (the hardware *can* take a certificate), and the capability table
  reports it as unsupported *for the HTTP backend* with a reason naming the
  method that does work.

Anything else -- a credential error, a verification failure, a malformed test
argument -- means the backend accepted the operation and tried, which is what
``Support.SUPPORTED`` claims.

Only seeded models are driven: ``m7300`` and ``xs748t`` are registered from
specification sheets with no capture behind them (``verified=False``), so their
mock is a blank device whose empty answers would say nothing about capability.
"""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING, Any

import pytest

from netgear_switch import (
    Backend,
    SyncSwitch,
    UnsupportedCapabilityError,
    get_model,
)
from netgear_switch.capabilities import (
    OPERATIONS,
    READ_OPERATIONS,
    WRITE_OPERATIONS,
    Capability,
    Operation,
    OperationKind,
    Support,
    backends_for,
    matrix,
    operation,
    support,
)
from netgear_switch.models import PortSpeed, VlanMode
from netgear_switch.protocols.cli.commands import CLI_BACKENDS
from netgear_switch.protocols.http import endpoints
from netgear_switch.protocols.http.endpoints import http_spec
from netgear_switch.registry import MODELS
from netgear_switch.transport.http.client import HttpClient
from netgear_switch.transport.sync.nsdp_udp import UdpNsdpClient
from netgear_switch.transport.sync.snmp_netsnmp_cli import NetsnmpCliClient
from netgear_switch.virtual.server import VirtualSwitch

if TYPE_CHECKING:
    from collections.abc import Iterator

    from netgear_switch.registry import SwitchModel

#: Models with a hand-authored seed built from a real capture (see
#: ``src/netgear_switch/virtual/server.py``'s ``_SEEDS``).
SEEDED_MODELS = (
    "gsm7252ps",
    "gsm7228ps",
    "m4300-24x",
    "m4300-16x",
    "gs110emx",
    "gs305ep",
    "gs105pe",
    "gs728tpp",
)

#: Arguments for driving each write. Values are deliberately harmless against a
#: mock: port 1, VLAN 1, and a throwaway VLAN id from the range this project
#: reserves for testing (4001-4008).
_WRITE_ARGS: dict[str, tuple[tuple[Any, ...], dict[str, Any]]] = {
    "set_port_enabled": ((1, True), {}),
    "set_port_description": ((1, "capcheck"), {}),
    # PortSpeed.auto() rather than a forced rate: auto is what every seeded port
    # already reports, so driving the capability gate cannot depend on the mock
    # accepting a particular rate on a particular model's PHY.
    "set_port_speed": ((1, PortSpeed.auto()), {}),
    # False is what every FASTPATH seed now carries (their captures all read
    # "Disable"), so this drives the gate without depending on a state change.
    "set_flow_control": ((1, False), {}),
    "set_poe": ((1, True), {}),
    "cycle_poe": ((1,), {}),
    "clear_poe_fault": ((1,), {}),
    "set_pvid": ((1, 1), {}),
    "set_vlan_membership": ((1, 1, VlanMode.UNTAGGED), {}),
    "create_vlan": ((4008, "capcheck"), {}),
    "delete_vlan": ((4008,), {}),
    "set_mgmt_ip": (("10.99.0.2", "255.255.255.0", "10.99.0.1"), {}),
    # A non-empty name: set_hostname refuses an empty one outright, because
    # `hostname` with no argument is rejected by the device itself and clearing
    # a name is a different command (`no hostname`) that is not implemented.
    "set_hostname": (("capcheck",), {}),
    "set_syslog_enabled": ((True,), {}),
    # TEST-NET-1 (RFC 5737): routes nowhere, so even a mock that grew a real
    # socket could not send anywhere. Absent from every seed, so the add's
    # duplicate guard cannot be what refuses it.
    "add_syslog_collector": (("192.0.2.1",), {}),
    # Present on every seed that has collectors at all -- the address the live
    # captures carry -- so the remove drives the write rather than the
    # not-configured precondition.
    "remove_syslog_collector": (("10.1.5.1",), {}),
}

#: Not driven. ``upload_certificate_scp`` runs a multi-command deploy sequence
#: (disable HTTPS, copy, re-enable, save) that has its own dedicated tests; its
#: capability gate is asserted directly in ``test_scp_certificate_gate`` instead.
UNDRIVEN_WRITES = frozenset({"upload_certificate_scp"})

_CERT_PEM = "-----BEGIN CERTIFICATE-----\nnot-a-real-cert\n-----END CERTIFICATE-----\n"
_KEY_PEM = "-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----\n"


@pytest.fixture(params=SEEDED_MODELS)
def seeded(
    request: pytest.FixtureRequest,
) -> Iterator[tuple[VirtualSwitch, SwitchModel]]:
    """A started mock for each seeded model, stopped even if the test fails."""
    mock = VirtualSwitch(model=request.param)
    mock.start()
    try:
        yield mock, get_model(request.param)
    finally:
        mock.stop()


def _facade(mock: VirtualSwitch, model: SwitchModel) -> SyncSwitch:
    """A ``SyncSwitch`` wired to every face this mock has bound.

    Clients are injected rather than built from a host, so each backend talks to
    the mock's actual ephemeral port -- and so no operation can reach a real
    network even if a guard were missing.
    """
    kwargs: dict[str, Any] = {}
    if Backend.SNMP in model.backends:
        snmp = NetsnmpCliClient(f"{mock.host}:{mock.port}", mock.community)
        kwargs["snmp_client"] = snmp
        kwargs["snmp_write_client"] = snmp
    if Backend.NSDP in model.backends:
        nsdp = UdpNsdpClient(
            mock.host, client_port=0, server_port=mock.port, timeout=2.0
        )
        kwargs["nsdp_client"] = nsdp
        kwargs["nsdp_write_client"] = nsdp
        kwargs["nsdp_password"] = mock.nsdp_password
    if Backend.HTTP in model.backends:
        kwargs["http_client"] = HttpClient(
            f"{mock.host}:{mock.http_port}", mock.http_password, http_spec(model)
        )
    if CLI_BACKENDS & model.backends:
        kwargs["cli_client"] = mock.cli_session()
    return SyncSwitch(model, host=mock.host, **kwargs)


def _refused(call: Any, *args: Any, **kwargs: Any) -> bool:
    """Run ``call``; True iff it refused the operation as unsupported."""
    try:
        call(*args, **kwargs)
    except (UnsupportedCapabilityError, NotImplementedError):
        return True
    except Exception:
        # Any other failure -- a credential error, a verification failure, a
        # malformed test argument -- means the backend ACCEPTED the operation
        # and tried, which is exactly what Support.SUPPORTED claims.
        return False
    return False


def _expected_refusal(cap: Capability) -> bool:
    return cap.support is not Support.SUPPORTED


def test_reads_match_reality(seeded: tuple[VirtualSwitch, SwitchModel]) -> None:
    mock, model = seeded
    switch = _facade(mock, model)
    for backend in backends_for(model):
        for op in READ_OPERATIONS:
            cap = support(model, backend, op)
            if op.backends is not None and backend not in op.backends:
                # Structurally backend-fixed (``nsdp_device``): the facade method
                # takes no ``backend`` argument at all, so there is nothing to
                # drive per-backend. Its verdict is asserted in
                # ``test_backend_fixed_operations``.
                continue
            if op.name == "nsdp_device":
                refused = _refused(switch.nsdp_device)
            else:
                refused = _refused(getattr(switch, op.name), backend=backend)
            assert refused == _expected_refusal(cap), (
                f"{model.key}/{backend.name}/{op.name}: capabilities says "
                f"{cap.support.value} ({cap.reason or 'no reason'}) but driving it "
                f"{'refused' if refused else 'ran'}"
            )


def test_writes_match_reality(seeded: tuple[VirtualSwitch, SwitchModel]) -> None:
    mock, model = seeded
    switch = _facade(mock, model)
    for backend in backends_for(model):
        for op in WRITE_OPERATIONS:
            if op.name in UNDRIVEN_WRITES:
                continue
            cap = support(model, backend, op)
            if op.backends is not None and backend not in op.backends:
                continue
            if op.name == "upload_certificate":
                refused = _refused(
                    switch.upload_certificate, _CERT_PEM, _KEY_PEM, force=True
                )
            else:
                args, kwargs = _WRITE_ARGS[op.name]
                refused = _refused(
                    getattr(switch, op.name),
                    *args,
                    force=True,
                    backend=backend,
                    **kwargs,
                )
            assert refused == _expected_refusal(cap), (
                f"{model.key}/{backend.name}/{op.name}: capabilities says "
                f"{cap.support.value} ({cap.reason or 'no reason'}) but driving it "
                f"{'refused' if refused else 'ran'}"
            )


def test_backend_fixed_operations() -> None:
    """``nsdp_device`` and the certificate uploads name their own transport."""
    for model_key in MODELS:
        model = get_model(model_key)
        for backend in backends_for(model):
            for op in OPERATIONS:
                if op.backends is None or backend in op.backends:
                    continue
                cap = support(model, backend, op)
                assert cap.support is Support.UNSUPPORTED
                assert op.name in cap.reason


def test_scp_certificate_gate() -> None:
    """The SCP cert verdict is the facade's own dispatch gate, not a copy."""
    from netgear_switch.protocols.cli.commands import scp_cert_profile

    for model_key in MODELS:
        model = get_model(model_key)
        cli = [b for b in backends_for(model) if b in CLI_BACKENDS]
        if not cli:
            continue
        try:
            scp_cert_profile(model)
        except UnsupportedCapabilityError:
            has_profile = False
        else:
            has_profile = True
        for backend in cli:
            cap = support(model, backend, "upload_certificate_scp")
            assert cap.supported is has_profile, model.key


def test_no_backend_is_reported_before_the_operation() -> None:
    """A backend the model lacks is refused first, matching ``resolve_backend``."""
    cap = support("gs110emx", Backend.SNMP, "get_ports")
    assert cap.support is Support.NO_BACKEND
    assert "no SNMP backend" in cap.reason


def test_console_is_named_as_a_transport_not_a_missing_cli() -> None:
    """CONSOLE is never registered on a model; the reason must say why.

    Reporting it as "no CLI backend" would be misleading on a FASTPATH switch
    whose CLI is perfectly present over SSH.
    """
    cap = support("gsm7252ps", Backend.CONSOLE, "get_ports")
    assert cap.support is Support.NO_BACKEND
    assert "serial transport" in cap.reason
    assert support("gsm7252ps", Backend.SSH, "get_ports").supported


def test_unverified_backend_gates_off() -> None:
    """A spec awaiting live cross-verification reports UNVERIFIED, not supported.

    Every shipped spec is currently verified, so this exercises the gate through
    the same seam the facade reads -- if the mechanism ever broke, a model could
    silently start serving unchecked data.
    """
    key = "gsm7252ps"
    original = endpoints._SPECS[key]
    endpoints._SPECS[key] = dataclasses.replace(original, reads_verified=False)
    try:
        cap = support(key, Backend.HTTP, "get_ports")
        assert cap.support is Support.UNVERIFIED
        assert "UNVERIFIED" in cap.reason
    finally:
        endpoints._SPECS[key] = original


def test_matrix_covers_every_model_and_carries_no_absent_backends() -> None:
    caps = matrix()
    assert {c.model_key for c in caps} == set(MODELS)
    assert all(c.support is not Support.NO_BACKEND for c in caps)
    expected = sum(len(backends_for(k)) * len(OPERATIONS) for k in MODELS)
    assert len(caps) == expected


def test_every_refusal_states_a_reason() -> None:
    for cap in matrix():
        if cap.supported:
            assert cap.reason == ""
        else:
            where = f"{cap.model_key}/{cap.backend.name}/{cap.operation.name}"
            assert cap.reason, where


def test_operations_are_facade_methods() -> None:
    """Every operation names a real method on both facades."""
    from netgear_switch.aio_api import AsyncSwitch

    for op in OPERATIONS:
        assert hasattr(SyncSwitch, op.name), op.name
        assert hasattr(AsyncSwitch, op.name), op.name
    assert {o.kind for o in READ_OPERATIONS} == {OperationKind.READ}
    assert {o.kind for o in WRITE_OPERATIONS} == {OperationKind.WRITE}


def test_operation_lookup() -> None:
    assert operation("get_ports").kind is OperationKind.READ
    assert isinstance(operation("get_ports"), Operation)
    with pytest.raises(KeyError, match="unknown operation"):
        operation("get_nonsense")


def test_support_accepts_keys_or_objects() -> None:
    by_key = support("gsm7252ps", Backend.SNMP, "get_ports")
    by_object = support(get_model("gsm7252ps"), Backend.SNMP, operation("get_ports"))
    assert by_key == by_object


def test_backends_are_in_facade_preference_order() -> None:
    """The order callers see matches the order the facade would resolve."""
    assert backends_for("m4300-24x") == (
        Backend.SNMP,
        Backend.HTTP,
        Backend.SSH,
        Backend.TELNET,
    )
    assert backends_for("gs110emx") == (Backend.NSDP, Backend.HTTP)


#: SyncSwitch methods that are deliberately NOT capability-gated operations:
#: connection lifecycle, backend resolution, model detection, and the aggregate
#: that simply calls the others. (Mirrors ``_NOT_CLI_EXPOSED`` in
#: tests/cli/test_op_coverage.py and ``_NOT_MCP_EXPOSED`` in
#: tests/test_mcp_server.py.)
_NOT_CAPABILITY_GATED = {"close", "identify", "resolve_backend", "snapshot"}


def test_every_switch_operation_has_a_capability_entry() -> None:
    """The forcing function that was missing.

    ``set_syslog_enabled`` shipped on the facade with no ``Operation`` entry at
    all: ``support(model, backend, "set_syslog_enabled")`` raised KeyError and
    the generated support matrix silently omitted an operation the library
    performs. The CLI and the MCP server each have a coverage guard; the
    capability table -- which the published documentation is generated FROM --
    did not, so nothing caught it.
    """
    import inspect

    from netgear_switch.sync_api import SyncSwitch

    public = {
        name
        for name, member in inspect.getmembers(SyncSwitch, predicate=inspect.isfunction)
        if not name.startswith("_")
    }
    known = {op.name for op in OPERATIONS}
    missing = public - known - _NOT_CAPABILITY_GATED
    assert not missing, (
        f"SyncSwitch operations with no capabilities.Operation entry: {sorted(missing)}"
    )


def test_no_capability_entry_without_a_facade_method() -> None:
    """The other direction: the table must not advertise an op nobody can call."""
    import inspect

    from netgear_switch.sync_api import SyncSwitch

    public = {
        name
        for name, member in inspect.getmembers(SyncSwitch, predicate=inspect.isfunction)
        if not name.startswith("_")
    }
    orphans = {op.name for op in OPERATIONS} - public
    assert not orphans, (
        f"capability entries with no SyncSwitch method: {sorted(orphans)}"
    )
