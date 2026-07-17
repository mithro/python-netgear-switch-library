from __future__ import annotations

from dataclasses import dataclass

import pytest

from netgear_switch.protocols.snmp.client import SnmpError, SnmpRow
from netgear_switch.transport.sync.snmp_netsnmp_cli import (
    NetsnmpCliClient,
    parse_netsnmp_lines,
)

_WHICH = "netgear_switch.transport.sync.snmp_netsnmp_cli._which"


def test_parse_integer_gauge_counter():
    text = (
        ".1.3.6.1.2.1.2.2.1.8.1 = INTEGER: 1\n"
        ".1.3.6.1.2.1.31.1.1.1.15.1 = Gauge32: 1000\n"
        ".1.3.6.1.2.1.31.1.1.1.6.1 = Counter64: 12345\n"
    )
    rows = parse_netsnmp_lines(text)
    assert rows[0] == SnmpRow("1.3.6.1.2.1.2.2.1.8.1", 1, "INTEGER")
    assert rows[1] == SnmpRow("1.3.6.1.2.1.31.1.1.1.15.1", 1000, "Gauge32")
    assert rows[2] == SnmpRow("1.3.6.1.2.1.31.1.1.1.6.1", 12345, "Counter64")


def test_parse_string_ip_oid_timeticks():
    text = (
        '.1.3.6.1.2.1.31.1.1.1.1.1 = STRING: "eth1"\n'
        ".1.3.6.1.2.1.4.20.1.1.10.1.5.20 = IpAddress: 10.1.5.20\n"
        ".1.3.6.1.2.1.1.2.0 = OID: .1.3.6.1.4.1.4526\n"
        ".1.3.6.1.2.1.1.3.0 = Timeticks: (12345) 0:02:03.45\n"
    )
    rows = parse_netsnmp_lines(text)
    assert rows[0] == SnmpRow("1.3.6.1.2.1.31.1.1.1.1.1", "eth1", "STRING")
    assert rows[1] == SnmpRow(
        "1.3.6.1.2.1.4.20.1.1.10.1.5.20", "10.1.5.20", "IpAddress"
    )
    assert rows[2].value == "1.3.6.1.4.1.4526"
    assert rows[2].snmp_type == "OID"
    assert rows[3] == SnmpRow("1.3.6.1.2.1.1.3.0", 12345, "Timeticks")


def test_parse_hex_string_multiline():
    text = (
        ".1.3.6.1.2.1.17.7.1.4.3.1.2.5 = Hex-STRING: C0 00 00 00\n"
        "00 00 00 01\n"
    )
    rows = parse_netsnmp_lines(text)
    assert len(rows) == 1
    assert rows[0].snmp_type == "Hex-STRING"
    assert rows[0].value == bytes([0xC0, 0, 0, 0, 0, 0, 0, 1])


def test_parse_no_such_object_raises():
    with pytest.raises(SnmpError):
        parse_netsnmp_lines(
            ".1.3.6.1.2.1.99 = No Such Object available on this agent at this OID\n"
        )


def test_parse_no_such_instance_raises():
    with pytest.raises(SnmpError):
        parse_netsnmp_lines(".1.3.6.1.2.1.2.2.1.8.99 = No Such Instance\n")


def test_parse_walk_end_of_mib_terminator_is_not_an_error():
    # snmpbulkwalk appends this benign line once it reaches the end of the
    # agent's MIB tree. It must not discard the rows already parsed.
    text = (
        ".1.3.6.1.2.1.2.2.1.8.1 = INTEGER: 1\n"
        ".1.3.6.1.2.1.2.2.1.8.2 = INTEGER: 2\n"
        ".1.3.6.1.6.3.16.1.5.2.1.6.6.1.5.4.1.2 = "
        "No more variables left in this MIB View "
        "(It is past the end of the MIB tree)\n"
    )
    rows = parse_netsnmp_lines(text)
    assert rows == [
        SnmpRow("1.3.6.1.2.1.2.2.1.8.1", 1, "INTEGER"),
        SnmpRow("1.3.6.1.2.1.2.2.1.8.2", 2, "INTEGER"),
    ]


def test_parse_no_such_object_names_oid_in_error():
    with pytest.raises(SnmpError, match=r"1\.3\.6\.1\.2\.1\.99"):
        parse_netsnmp_lines(
            ".1.3.6.1.2.1.99 = No Such Object available on this agent at this OID\n"
        )


def test_parse_no_such_instance_at_oid_raises():
    with pytest.raises(SnmpError):
        parse_netsnmp_lines(
            ".1.3.6.1.2.1.2.2.1.8.99 = "
            "No Such Instance currently exists at this OID\n"
        )


def test_parse_string_containing_marker_words_is_not_an_error():
    # A legitimate STRING value that merely contains the words "no such
    # object" must be parsed normally, not mistaken for the absent marker.
    text = '.1.3.6.1.2.1.31.1.1.1.1.1 = STRING: "port no such object test"\n'
    rows = parse_netsnmp_lines(text)
    assert rows == [
        SnmpRow(
            "1.3.6.1.2.1.31.1.1.1.1.1", "port no such object test", "STRING"
        )
    ]


@dataclass
class _FakeProc:
    returncode: int
    stdout: str
    stderr: str = ""


def test_get_builds_argv_and_parses(monkeypatch):
    captured: dict[str, list[str]] = {}

    def fake_runner(argv, **_kw):
        captured["argv"] = argv
        return _FakeProc(0, ".1.3.6.1.2.1.2.2.1.8.1 = INTEGER: 1\n")

    monkeypatch.setattr(_WHICH, lambda b: f"/usr/bin/{b}")
    c = NetsnmpCliClient("10.1.5.20", "public", runner=fake_runner)
    rows = c.get(["1.3.6.1.2.1.2.2.1.8.1"])
    assert rows == [SnmpRow("1.3.6.1.2.1.2.2.1.8.1", 1, "INTEGER")]
    argv = captured["argv"]
    assert argv[0] == "/usr/bin/snmpget"
    assert "-v2c" in argv
    assert "-c" in argv
    assert "public" in argv
    for flag in ("-On", "-Oe", "-OU", "-Ln"):
        assert flag in argv
    assert "10.1.5.20" in argv
    assert argv[-1] == "1.3.6.1.2.1.2.2.1.8.1"


def test_walk_builds_bulkwalk_argv(monkeypatch):
    captured: dict[str, list[str]] = {}

    def fake_runner(argv, **_kw):
        captured["argv"] = argv
        return _FakeProc(
            0,
            ".1.3.6.1.2.1.2.2.1.8.1 = INTEGER: 1\n"
            ".1.3.6.1.2.1.2.2.1.8.2 = INTEGER: 2\n",
        )

    monkeypatch.setattr(_WHICH, lambda b: f"/usr/bin/{b}")
    c = NetsnmpCliClient("10.1.5.20", "public", runner=fake_runner)
    rows = c.walk("1.3.6.1.2.1.2.2.1.8")
    assert captured["argv"][0] == "/usr/bin/snmpbulkwalk"
    assert captured["argv"][-1] == "1.3.6.1.2.1.2.2.1.8"
    assert [r.value for r in rows] == [1, 2]


def test_nonzero_exit_raises_with_stderr(monkeypatch):
    def fake_runner(argv, **_kw):
        return _FakeProc(1, "", "Timeout: No Response from 10.1.5.20")

    monkeypatch.setattr(_WHICH, lambda b: f"/usr/bin/{b}")
    c = NetsnmpCliClient("10.1.5.20", "public", runner=fake_runner)
    with pytest.raises(SnmpError, match="Timeout"):
        c.walk("1.3.6.1.2.1.2.2.1.8")


def test_which_guard_raises_when_binary_missing(monkeypatch):
    import netgear_switch.transport.sync.snmp_netsnmp_cli as mod

    monkeypatch.setattr(mod.shutil, "which", lambda _b: None)
    c = mod.NetsnmpCliClient("10.1.5.20", "public")
    with pytest.raises(SnmpError, match="net-snmp not installed"):
        c.get(["1.3.6.1.2.1.2.2.1.8.1"])


def test_import_does_not_require_binaries():
    # Importing the module must not shell out or need net-snmp on PATH.
    import netgear_switch.transport.sync.snmp_netsnmp_cli  # noqa: F401
