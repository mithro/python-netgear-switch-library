# tests/virtual/test_syslog_fidelity.py
"""The fake must answer ``get_syslog`` exactly as the real switches did.

Every expected value below was READ OFF A LIVE DEVICE on 2026-08-02 and
cross-checked against that switch's own ``show logging`` / ``show logging
hosts``. They are transcribed here, not computed: a mock that derived them with
the same code under test could only ever agree with itself (principle 5).

The gs728tpp row is the important one. It has no Netgear vendor subtree at all,
the logging columns are vendor-only, and the reader refuses BY NAME rather than
returning an empty config -- because "no collectors configured" and "this
backend cannot tell you" are different answers and must not collapse into one.
"""

from __future__ import annotations

import pytest

from netgear_switch.errors import UnsupportedCapabilityError
from netgear_switch.registry import get_model
from netgear_switch.snmp_read import SnmpReader
from netgear_switch.transport.sync.snmp_netsnmp_cli import NetsnmpCliClient
from netgear_switch.virtual.server import VirtualSwitch

#: model -> (enabled, local_port, [(host, port, severity, active)])
#: transcribed from the live reads.
MEASURED = {
    # 10.1.5.13, `show logging hosts`: 1  10.1.5.1  info  514  Active
    "m4300-24x": (True, 514, [("10.1.5.1", 514, 6, True)]),
    # 10.1.5.22, same row (its host table prints five columns, not eight)
    "gsm7252ps": (True, 514, [("10.1.5.1", 514, 6, True)]),
    # 10.1.5.11: admin-mode column reads 2, and the host table is empty.
    #
    # NOTE this is a SNAPSHOT of that switch on 2026-08-02, and the switch has
    # since moved on: a live read on 2026-08-03 returned enabled=True with one
    # collector. That is an operator changing the switch, not the parser
    # breaking, and the seed stays as recorded -- the mock's job is to reproduce
    # a state that was really observed, not to track a production device. Do not
    # "fix" this row to match a later live read without capturing that read.
    "gsm7228ps": (False, 514, []),
}


def _reader(mock: VirtualSwitch, key: str) -> SnmpReader:
    client = NetsnmpCliClient(f"{mock.host}:{mock.port}", mock.community)
    return SnmpReader(client, get_model(key))


@pytest.mark.parametrize("key", sorted(MEASURED))
def test_fake_matches_the_live_switch(key: str) -> None:
    enabled, local_port, collectors = MEASURED[key]
    with VirtualSwitch(model=key) as mock:
        cfg = _reader(mock, key).get_syslog()
    assert cfg.enabled is enabled
    assert cfg.local_port == local_port
    assert [(s.host, s.port, s.severity, s.active) for s in cfg.servers] == collectors


def test_severity_is_the_device_number_not_a_label() -> None:
    """6 is what the column holds where the CLI prints "info".

    Pinned separately because it is the one value a future refactor might be
    tempted to "improve" into an enum name, breaking agreement with the wire.
    """
    with VirtualSwitch(model="m4300-24x") as mock:
        cfg = _reader(mock, "m4300-24x").get_syslog()
    assert cfg.servers[0].severity == 6


def test_a_model_with_no_vendor_subtree_refuses_rather_than_answering_empty() -> None:
    with (
        VirtualSwitch(model="gs728tpp") as mock,
        pytest.raises(UnsupportedCapabilityError, match="vendor"),
    ):
        _reader(mock, "gs728tpp").get_syslog()
