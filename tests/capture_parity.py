# tests/capture_parity.py
"""Reusable capture -> seed parity harness.

``tests/fixtures/captures/*.json`` are committed real-hardware SNMP captures
(one JSON object per model, with a ``snapshot`` dict of already-parsed public
API values -- see ``cli/capture.py``'s writer). ``assert_seed_matches_capture``
checks that a hand-authored ``seed_*()`` builder's ``VirtualSwitchState``
reproduces, for every port/VLAN/PVID/PoE-port/sensor the SEED itself defines,
the corresponding real value from one of these captures.

Deliberately a ONE-WAY check: the seed may cover only a representative SUBSET
of a large real device (e.g. the M4300 seeds intentionally transcribe only a
slice of the real 128 mostly-identical LAG placeholder ifIndexes -- see
``virtual/seed.py``'s module docstring), so this only requires that whatever
the seed DOES claim is literally true of the capture, never that every row of
the capture appears in the seed. A seed key absent from the capture entirely
(a port/VLAN/etc. the mock invented that the real device never reported) is a
fabrication and fails loudly.

Deliberately EXCLUDES the MAC/FDB table, LLDP neighbours, and per-port
byte/packet counters: a live device's learned MACs, discovered neighbours and
traffic counters are inherently volatile point-in-time facts (they legitimately
differ capture-to-capture, even on the same device), not durable ground truth
a mock seed should be pinned to. This harness pins structural facts (port
identity/state, VLAN membership, PoE capability, sensor readings, the
management-IP/base-MAC identity), not volatile counters.

This harness assumes the seed IS a transcription of the exact capture passed
in. ``seed_m4300_24x``/``seed_m4300_16x`` and ``seed_gsm7252ps`` are all such
transcriptions and all satisfy this strict per-key equality (the gsm7252ps
seed's ports/PVIDs/all 14 VLANs/48 PoE ports/SNMP sensors/mgmt-IP are literal
copies of ``captures/gsm7252ps.json`` -- see ``test_gsm7252ps_seed.py``). The
one-way subset rule still applies: a seed may transcribe only a slice of a
large device, so the check requires only that whatever the seed claims is true
of the capture. Note the SENSOR check covers the SNMP face's ``sensors`` only;
a model whose web UI exposes a DIFFERENT sensor set (the gsm7252ps: SNMP fans+
watts vs sysInfo temps+health) carries that second set in ``http_sensors``,
validated against its own HTTP capture elsewhere, not here.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from netgear_switch.models import PoEDetect
from netgear_switch.protocols.snmp.parse import DETECT_MAP

if TYPE_CHECKING:
    from netgear_switch.virtual.state import VirtualSwitchState


def load_capture_snapshot(capture_json_path: str | Path) -> dict[str, Any]:
    """Load one committed capture's ``snapshot`` dict."""
    return json.loads(Path(capture_json_path).read_text())["snapshot"]  # type: ignore[no-any-return]


def assert_seed_matches_capture(
    seed: VirtualSwitchState, capture_json_path: str | Path
) -> None:
    """Assert ``seed`` reproduces ``capture_json_path``'s real snapshot.

    See the module docstring for exactly what is (ports/PoE/VLANs/PVIDs/
    sensors/mgmt-IP/base-MAC) and is NOT (MACs/LLDP/stats) checked, and why.
    """
    capture = load_capture_snapshot(capture_json_path)
    _assert_ports_match(seed, capture)
    _assert_poe_matches(seed, capture)
    _assert_vlans_match(seed, capture)
    _assert_pvids_match(seed, capture)
    _assert_sensors_match(seed, capture)
    _assert_mgmt_matches(seed, capture)


def _assert_ports_match(seed: VirtualSwitchState, capture: dict[str, Any]) -> None:
    real_by_port = {p["port"]: p for p in capture["ports"]}
    for port, sim in seed.ports.items():
        real = real_by_port.get(port)
        assert real is not None, f"seed port {port} absent from capture"
        assert sim.name == real["name"], f"port {port} name"
        assert sim.admin == real["admin_enabled"], f"port {port} admin"
        assert sim.link == real["link_up"], f"port {port} link"
        assert (sim.speed or None) == (real["speed_mbps"] or None), f"port {port} speed"
        assert sim.description == real["description"], f"port {port} description"


def _assert_poe_matches(seed: VirtualSwitchState, capture: dict[str, Any]) -> None:
    if not seed.poe:
        assert capture["poe"] == [], "seed has no PoE but the capture does"
        return
    real_by_port = {p["port"]: p for p in capture["poe"]}
    for port, psim in seed.poe.items():
        real = real_by_port.get(port)
        assert real is not None, f"seed PoE port {port} absent from capture"
        assert psim.admin == real["admin_enabled"], f"PoE port {port} admin"
        # Mirror parse_poe exactly: a detect code outside RFC3621's 1-4 (e.g.
        # the gsm7252ps's "Other Fault" code 6 on port 6) maps to UNKNOWN, not
        # a KeyError. The capture records that port's detect as "unknown".
        assert DETECT_MAP.get(psim.detect, PoEDetect.UNKNOWN).value == real["detect"], (
            f"PoE port {port} detect"
        )
        assert (psim.power_mw or 0) == real["power_mw"], f"PoE port {port} power_mw"


def _assert_vlans_match(seed: VirtualSwitchState, capture: dict[str, Any]) -> None:
    real_by_id = {v["vlan_id"]: v for v in capture["vlans"]}
    for vid, vsim in seed.vlans.items():
        real = real_by_id.get(vid)
        assert real is not None, f"seed VLAN {vid} absent from capture"
        assert vsim.name == real["name"], f"VLAN {vid} name"
        # The capture is an SNMP walk, so its member_ports came from
        # dot1qVlanStaticEgressPorts -- the STATIC (configured) table. Compare it
        # against the seed's CONFIGURED set, not its current ``member`` set: on
        # the real GSM7252PS, VLAN 1's static bitmap includes 1/0/50 and 1/0/51
        # while ``show vlan 1`` reports them Current: Exclude, so the two views
        # differ by exactly those ports (see VlanSim.configured_only).
        assert vsim.configured == set(real["member_ports"]), f"VLAN {vid} member_ports"
        assert vsim.untagged == set(real["untagged_ports"]), (
            f"VLAN {vid} untagged_ports"
        )
        assert (vsim.configured - vsim.untagged) == set(real["tagged_ports"]), (
            f"VLAN {vid} tagged_ports"
        )


def _assert_pvids_match(seed: VirtualSwitchState, capture: dict[str, Any]) -> None:
    real_pvids = dict(capture["pvids"])
    for port, pvid in seed.pvids.items():
        assert real_pvids.get(port) == pvid, f"port {port} pvid"


def _assert_sensors_match(seed: VirtualSwitchState, capture: dict[str, Any]) -> None:
    # capture sensor "name" is "{kind}{instance}" (see cli/capture.py); strip
    # the kind prefix back off to key by (kind, instance), matching SensorSim.
    real = {
        (s["kind"], s["name"][len(s["kind"]) :]): s["value"] for s in capture["sensors"]
    }
    for ssim in seed.sensors:
        key = (ssim.kind, ssim.instance)
        if ssim.raw == "Not Supported":
            assert key not in real, f"sensor {key} seeded unsupported but captured"
            continue
        assert key in real, f"seed sensor {key} absent from capture"
        assert float(ssim.raw) == real[key], f"sensor {key} value"


def _assert_mgmt_matches(seed: VirtualSwitchState, capture: dict[str, Any]) -> None:
    real = capture["mgmt_ip"]
    expected_base_mac = ":".join(f"{b:02X}" for b in seed.nsdp_mac)
    assert expected_base_mac == real["base_mac"], "base_mac"
    if real["address"] is None:
        # No real static address was ever discovered on this capture; the
        # seed's default blank MgmtSim is an honest placeholder, not a claim
        # to reproduce a specific real address (see e.g. seed_m4300_16x's
        # module docstring) -- nothing further to check.
        return
    assert seed.mgmt.address == real["address"], "mgmt address"
    if real["netmask"] is not None:
        assert seed.mgmt.netmask == real["netmask"], "mgmt netmask"
    if real["gateway"] is not None:
        assert seed.mgmt.gateway == real["gateway"], "mgmt gateway"
