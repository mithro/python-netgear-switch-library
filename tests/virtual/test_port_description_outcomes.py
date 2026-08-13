# tests/virtual/test_port_description_outcomes.py
"""``set_port_description`` must CHANGE STATE, on every backend that claims it.

``tests/test_capabilities.py`` deliberately asserts something weaker -- that the
operation reached the backend and was attempted -- so a write that dispatches
correctly and then fails to apply is invisible there. This module closes that
gap the same way ``test_write_outcomes`` does for the VLAN lifecycle: for every
(model, backend) the table says is SUPPORTED, set a description and assert it is
really there afterwards, then clear it and assert it is really gone.

Clearing is half the point. ``snmpset ... s ""`` is rejected by the net-snmp CLI
itself, so an empty description could be set and never removed until the
transport learned to send it as an empty hex string -- a defect found on live
hardware, with a port left labelled.
"""

from __future__ import annotations

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

PORT = 1
LABEL = "ngsw-outcome"


def _facade(mock: VirtualSwitch, model) -> SyncSwitch:
    kwargs: dict[str, object] = {}
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


@pytest.mark.parametrize("key", SEEDED_MODELS)
def test_claimed_description_writes_actually_change_state(key: str) -> None:
    model = get_model(key)
    op = operation("set_port_description")
    with VirtualSwitch(model=key) as mock:
        switch = _facade(mock, model)
        for backend in backends_for(model):
            if not support(model, backend, op).supported:
                continue
            # The FASTPATH CLI is read back through a DIFFERENT command: its
            # `show port all` table has no description column, so get_ports over
            # SSH/telnet reports None by design (see cli/parse.parse_port_status).
            # The write still verifies itself against the device -- through
            # `show port description <iface>` -- so a CLI write that did not
            # apply still fails, just from inside the writer rather than here.
            reads_back = backend not in CLI_BACKENDS

            def described(b: Backend = backend) -> str | None:
                rows = switch.get_ports(backend=b)
                return next((p.description for p in rows if p.port == PORT), None)

            before = described() if reads_back else None

            switch.set_port_description(PORT, LABEL, force=True, backend=backend)
            if reads_back:
                assert described() == LABEL, (
                    f"{key}/{backend.name}: capabilities says "
                    "set_port_description is supported, and the call returned, "
                    "but the label is not there"
                )

            # Clearing is the half that needed transport work, so it is asserted
            # separately rather than folded into the restore.
            switch.set_port_description(PORT, "", force=True, backend=backend)
            if reads_back:
                assert described() is None, (
                    f"{key}/{backend.name}: the description was set but could "
                    "not be cleared -- exactly the empty-value defect this guards"
                )

            # Put the seed's own label back (several models ship one) so the
            # next backend in this loop starts from the state it expects.
            if before is not None:
                switch.set_port_description(PORT, before, force=True, backend=backend)
                assert described() == before, f"{key}/{backend.name}: not restored"
