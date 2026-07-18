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
