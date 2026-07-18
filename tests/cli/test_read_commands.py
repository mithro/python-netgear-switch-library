from __future__ import annotations

import io
import json

from netgear_switch.cli import context
from netgear_switch.cli.main import main
from netgear_switch.errors import UnsupportedCapabilityError
from netgear_switch.models import (
    IpMode,
    LLDPNeighbor,
    MacEntry,
    MgmtIpConfig,
    PoEDetect,
    PoEStatus,
    PortStats,
    PortStatus,
    Sensor,
    SwitchData,
    VLANInfo,
)
from netgear_switch.registry import get_model


class FakeSwitch:
    """A stand-in SyncSwitch that returns canned model objects (no network)."""

    def __init__(self, model: str = "gsm7252ps", host: str = "10.0.0.1") -> None:
        self.model = get_model(model)
        self.host = host

    def get_ports(self) -> list[PortStatus]:
        return [PortStatus(1, "1/0/1", True, True, 1000)]

    def get_vlans(self) -> list[VLANInfo]:
        return [VLANInfo(90, "iot", frozenset({10}), frozenset(), frozenset({10}))]

    def get_pvids(self) -> list[tuple[int, int]]:
        return [(1, 90)]

    def get_lldp(self) -> list[LLDPNeighbor]:
        return [LLDPNeighbor(1, "peer", "Gi1", "aa:bb")]

    def get_macs(self) -> list[MacEntry]:
        return [MacEntry("C8:00:84:89:71:70", 110, 90)]

    def get_sensors(self) -> list[Sensor]:
        return [Sensor("fan1", "fan", 4200.0, "rpm")]

    def snapshot(self) -> SwitchData:
        return SwitchData(
            model="gsm7252ps",
            host=self.host,
            ports=(PortStatus(1, "1/0/1", True, True, 1000),),
            poe=(PoEStatus(1, True, PoEDetect.DELIVERING, 12800),),
            stats=(PortStats(1, 1, 2, 3, 4, 0, 0),),
            mgmt_ip=MgmtIpConfig(
                IpMode.STATIC, "10.1.5.20", "255.255.255.0", "10.1.5.1"
            ),
        )


def run(argv: list[str], switch: object) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main(argv, switch_factory=lambda a, c: switch, stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def test_ports_prints_table() -> None:
    code, out, _ = run(["ports"], FakeSwitch())
    assert code == context.EXIT_OK
    assert "1/0/1" in out
    assert "Port" in out


def test_ports_json_shape() -> None:
    code, out, _ = run(["--json", "ports"], FakeSwitch())
    assert code == context.EXIT_OK
    data = json.loads(out)
    assert data[0]["port"] == 1
    assert data[0]["speed_mbps"] == 1000


def test_ports_json_flag_after_subcommand() -> None:
    """``--json`` placed after the subcommand must behave the same as before it."""
    code, out, _ = run(["ports", "--json"], FakeSwitch())
    assert code == context.EXIT_OK
    data = json.loads(out)
    assert data[0]["port"] == 1
    assert data[0]["speed_mbps"] == 1000


def test_vlans_pvids_lldp() -> None:
    assert run(["vlans"], FakeSwitch())[0] == context.EXIT_OK
    assert run(["pvids"], FakeSwitch())[0] == context.EXIT_OK
    assert run(["lldp"], FakeSwitch())[0] == context.EXIT_OK


def test_macs_and_sensors_and_show() -> None:
    assert run(["macs"], FakeSwitch())[0] == context.EXIT_OK
    assert run(["sensors"], FakeSwitch())[0] == context.EXIT_OK
    code, out, _ = run(["show"], FakeSwitch())
    assert code == context.EXIT_OK
    assert "## Ports" in out


def test_vlans_prints_vlan_specific_fields() -> None:
    """Distinguishes the vlans handler from one that (wrongly) called get_pvids."""

    class VlansFake(FakeSwitch):
        def get_vlans(self) -> list[VLANInfo]:
            return [
                VLANInfo(
                    777,
                    "camnet",
                    frozenset({5, 6, 23}),
                    frozenset({23}),
                    frozenset({5, 6}),
                )
            ]

    code, out, _ = run(["vlans"], VlansFake())
    assert code == context.EXIT_OK
    assert "777" in out
    assert "camnet" in out
    assert "5,6" in out  # untagged ports
    assert "23" in out  # tagged port


def test_pvids_prints_port_pvid_mapping() -> None:
    """Distinguishes the pvids handler from one that (wrongly) called get_vlans."""

    class PvidsFake(FakeSwitch):
        def get_pvids(self) -> list[tuple[int, int]]:
            return [(3, 555)]

    code, out, _ = run(["pvids"], PvidsFake())
    assert code == context.EXIT_OK
    assert "555" in out
    assert "PVID" in out


def test_lldp_prints_neighbor_fields() -> None:
    class LldpFake(FakeSwitch):
        def get_lldp(self) -> list[LLDPNeighbor]:
            return [LLDPNeighbor(9, "core-switch-9", "Gi0/9", "de:ad:be:ef:00:09")]

    code, out, _ = run(["lldp"], LldpFake())
    assert code == context.EXIT_OK
    assert "core-switch-9" in out
    assert "de:ad:be:ef:00:09" in out


def test_macs_prints_mac_port_vlan() -> None:
    class MacsFake(FakeSwitch):
        def get_macs(self) -> list[MacEntry]:
            return [MacEntry("11:22:33:44:55:66", 17, 200)]

    code, out, _ = run(["macs"], MacsFake())
    assert code == context.EXIT_OK
    assert "11:22:33:44:55:66" in out
    assert "200" in out


def test_sensors_prints_sensor_name_value_unit() -> None:
    class SensorsFake(FakeSwitch):
        def get_sensors(self) -> list[Sensor]:
            return [Sensor("psu-temp", "temperature", 57.5, "C")]

    code, out, _ = run(["sensors"], SensorsFake())
    assert code == context.EXIT_OK
    assert "psu-temp" in out
    assert "57.5" in out


def test_stats_prints_distinct_rx_tx_columns() -> None:
    """Distinct values in every column so a column swap fails this."""

    class StatsFake(FakeSwitch):
        def get_stats(self) -> list[PortStats]:
            return [
                PortStats(
                    port=1,
                    rx_bytes=1001,
                    tx_bytes=2002,
                    rx_packets=3003,
                    tx_packets=4004,
                    rx_errors=5,
                    tx_errors=6,
                )
            ]

    code, out, _ = run(["stats"], StatsFake())
    assert code == context.EXIT_OK
    lines = out.splitlines()
    assert lines[0].split() == [
        "Port",
        "RxBytes",
        "TxBytes",
        "RxPackets",
        "TxPackets",
        "RxErrors",
        "TxErrors",
    ]
    assert lines[1].split() == ["1", "1001", "2002", "3003", "4004", "5", "6"]


def test_stats_json_shape() -> None:
    class StatsFake(FakeSwitch):
        def get_stats(self) -> list[PortStats]:
            return [
                PortStats(
                    port=2,
                    rx_bytes=10,
                    tx_bytes=20,
                    rx_packets=1,
                    tx_packets=2,
                    rx_errors=0,
                    tx_errors=0,
                )
            ]

    code, out, _ = run(["--json", "stats"], StatsFake())
    assert code == context.EXIT_OK
    data = json.loads(out)
    assert data[0]["port"] == 2
    assert data[0]["rx_bytes"] == 10
    assert data[0]["tx_bytes"] == 20
    assert data[0]["rx_packets"] == 1
    assert data[0]["tx_packets"] == 2


def test_unsupported_capability_is_clean_message_not_traceback() -> None:
    class Unsupported(FakeSwitch):
        def get_ports(self) -> list[PortStatus]:
            raise UnsupportedCapabilityError("model 'gs305ep' has no SNMP backend")

    code, out, err = run(["ports"], Unsupported())
    assert code == context.EXIT_ERROR
    assert "error:" in err
    assert "no SNMP backend" in err
    assert "Traceback" not in err
    assert out == ""


def test_unsupported_capability_verbose_prints_traceback() -> None:
    class Unsupported(FakeSwitch):
        def get_ports(self) -> list[PortStatus]:
            raise UnsupportedCapabilityError("model 'gs305ep' has no SNMP backend")

    code, _out, err = run(["-v", "ports"], Unsupported())
    assert code == context.EXIT_ERROR
    assert "Traceback (most recent call last)" in err
    assert "error:" in err
