# tests/virtual/test_write_outcomes.py
"""Writes must CHANGE STATE, not merely reach a backend.

``tests/test_capabilities.py`` deliberately asserts something weaker: that the
facade dispatches an operation to the backend the table names. Its ``_refused``
counts only ``UnsupportedCapabilityError``/``NotImplementedError`` as a refusal,
so any other exception means "the backend accepted the op and tried" -- which is
exactly what ``Support.SUPPORTED`` claims there.

That is a reasonable contract, and it is why a write which reaches the right
backend and then FAILS there is invisible to it. HTTP ``create_vlan`` did that
on four FASTPATH models for as long as the operation has existed: the writer
scrapes an ``<input name="hash">`` CSRF token those pages do not carry, and the
mock hid it by emitting one anyway. 27 green capability tests coexisted with a
write that had never worked on real hardware.

This module closes that gap for the VLAN lifecycle: for every (model, backend)
the capability table claims is SUPPORTED, create a VLAN and assert it is
actually there afterwards, then delete it and assert it is actually gone.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from netgear_switch.capabilities import backends_for, operation, support
from netgear_switch.protocols.cli.commands import CLI_BACKENDS
from netgear_switch.protocols.http.endpoints import http_spec
from netgear_switch.registry import Backend, get_model
from netgear_switch.sync_api import SyncSwitch
from netgear_switch.transport.http.client import HttpClient
from netgear_switch.transport.sync.nsdp_udp import UdpNsdpClient
from netgear_switch.transport.sync.snmp_netsnmp_cli import NetsnmpCliClient
from netgear_switch.virtual.server import VirtualSwitch

if TYPE_CHECKING:
    from netgear_switch.registry import SwitchModel

#: gs105pe is expected to FAIL: its HTTP create_vlan reports
#: WriteVerificationError("VLAN 4007 was not created") against the mock. That is
#: a REAL defect this module exposed, not a test artefact -- an earlier ad-hoc
#: probe called it working only because it never deleted between backends, so
#: the HTTP check saw the VLAN NSDP had already created. Marked xfail(strict) so
#: the suite stays honest AND tells us the moment it starts passing.
XFAIL_MODELS = {"gs105pe"}

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

#: A throwaway id from the range this project reserves for testing (4001-4008).
TEST_VLAN = 4007


def _facade(mock: VirtualSwitch, model: SwitchModel) -> SyncSwitch:
    """A facade wired to every face this mock bound, so no op reaches a network."""
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


@pytest.mark.parametrize(
    "key",
    [
        pytest.param(
            k,
            marks=pytest.mark.xfail(
                strict=True,
                reason="HTTP create_vlan does not apply on this dialect; see "
                "XFAIL_MODELS",
            ),
        )
        if k in XFAIL_MODELS
        else k
        for k in SEEDED_MODELS
    ],
)
def test_claimed_vlan_writes_actually_change_state(key: str) -> None:
    model = get_model(key)
    create, delete = operation("create_vlan"), operation("delete_vlan")
    with VirtualSwitch(model=key) as mock:
        switch = _facade(mock, model)
        for backend in backends_for(model):
            if not support(model, backend, create).supported:
                continue

            def vlans(b: Backend = backend) -> set[int]:
                return {v.vlan_id for v in switch.get_vlans(backend=b)}

            before = vlans()
            assert TEST_VLAN not in before, f"{key}/{backend.name}: seed uses the id"

            switch.create_vlan(TEST_VLAN, "outcome", backend=backend)
            assert TEST_VLAN in vlans(), (
                f"{key}/{backend.name}: capabilities says create_vlan is "
                "supported, and the call returned, but the VLAN is not there"
            )

            if support(model, backend, delete).supported:
                # force=True: NSDP force-gates delete_vlan because it drops every
                # member port. The gate is a deliberate safety feature, not the
                # thing under test here.
                switch.delete_vlan(TEST_VLAN, force=True, backend=backend)
                assert TEST_VLAN not in vlans(), (
                    f"{key}/{backend.name}: delete_vlan returned but the VLAN "
                    "is still present"
                )
                assert vlans() == before, (
                    f"{key}/{backend.name}: VLAN set not restored after the "
                    "create/delete round trip"
                )
