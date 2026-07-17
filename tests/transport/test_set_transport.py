from __future__ import annotations

import pytest

from netgear_switch.protocols.snmp.client import SnmpError
from netgear_switch.protocols.snmp.write import SetVarbind
from netgear_switch.transport.sync.snmp_netsnmp_cli import NetsnmpCliClient


class _Proc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_set_builds_snmpset_argv_with_type_letters():
    captured: list[list[str]] = []

    def runner(argv, **kwargs):
        captured.append(argv)
        # snmpset echoes the varbind back on success.
        return _Proc(stdout="1.3.6.1.2.1.2.2.1.7.5 = INTEGER: 2\n")

    client = NetsnmpCliClient("host", "writecomm", runner=runner)
    client.set(SetVarbind("1.3.6.1.2.1.2.2.1.7.5", 2, "i"))

    argv = captured[0]
    assert argv[0].endswith("snmpset")
    assert "-c" in argv
    assert "writecomm" in argv
    # trailing: <host> <oid> <type> <value>
    assert argv[-4:] == ["host", "1.3.6.1.2.1.2.2.1.7.5", "i", "2"]


def test_set_many_is_one_pdu_with_hex_for_x_type():
    captured: list[list[str]] = []

    def runner(argv, **kwargs):
        captured.append(argv)
        return _Proc(stdout="")

    client = NetsnmpCliClient("host", "w", runner=runner)
    client.set_many([
        SetVarbind("1.3.6.1.2.1.17.7.1.4.5.1.1.5", 90, "u"),
        SetVarbind("1.3.6.1.2.1.17.7.1.4.3.1.2.90", bytes([0xC0, 0x00]), "x"),
    ])
    assert len(captured) == 1  # single snmpset invocation = atomic PDU
    argv = captured[0]
    assert argv[-6:] == [
        "1.3.6.1.2.1.17.7.1.4.5.1.1.5", "u", "90",
        "1.3.6.1.2.1.17.7.1.4.3.1.2.90", "x", "c000",
    ]


def test_set_raises_snmperror_on_commit_failed():
    def runner(argv, **kwargs):
        return _Proc(returncode=1, stderr="Error in packet.\nReason: commitFailed")

    client = NetsnmpCliClient("host", "w", runner=runner)
    with pytest.raises(SnmpError) as exc:
        client.set(SetVarbind("1.3.6.1.2.1.2.2.1.7.5", 2, "i"))
    assert "commitFailed" in str(exc.value)
