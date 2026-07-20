# tests/virtual/test_m4300_seeds.py
"""Ground the M4300-24X/16X virtual-mock seeds in the committed real-hardware
captures (``tests/fixtures/captures/m4300-*.json``): the headline capability
contrast (24X has NO PoE, 16X has PoE on all 16 ports) plus port/VLAN/sensor/
mgmt-IP fidelity, cross-checked directly against the capture JSON so a future
edit to either seed or fixture that drifts them apart is caught here.

Ports/PoE/VLANs/PVIDs/sensors/mgmt-IP/base-MAC parity is delegated to the
reusable ``assert_seed_matches_capture`` harness (see ``tests/capture_parity.py``)
-- both M4300 seeds are literal transcriptions of their capture, so this
strict per-key equality check holds exactly. What that harness deliberately
does NOT cover (MAC table, LLDP, per-port stats/counters -- see its own
docstring) is still checked here directly, plus the model-specific quirks
(no-PoE noSuchObject-shape proof, the M4300-24X's ASCII-text base-MAC wire
quirk) that need the raw ``oid_map()``/parser layer, not just the seed's
plain dataclass fields.
"""
from __future__ import annotations

import json
from pathlib import Path

from capture_parity import assert_seed_matches_capture
from netgear_switch.protocols.snmp import oids, parse
from netgear_switch.protocols.snmp.client import SnmpRow
from netgear_switch.registry import get_model
from netgear_switch.virtual.seed import seed_m4300_16x, seed_m4300_24x

_FIXTURES = Path(__file__).parent.parent / "fixtures" / "captures"


def _capture(name: str) -> dict:
    return json.loads((_FIXTURES / f"{name}.json").read_text())["snapshot"]


def _rows(m: dict[str, tuple[str, str]], base: str) -> list[SnmpRow]:
    return [
        SnmpRow(k, v[1], v[0])
        for k, v in m.items()
        if k == base or k.startswith(base + ".")
    ]


# --- M4300-24X: non-PoE ------------------------------------------------------


def test_m4300_24x_seed_matches_capture():
    """Ports/PoE(absent)/VLANs/PVIDs/sensors/mgmt-IP/base-MAC all pinned to
    the real capture in one pass -- see
    ``capture_parity.assert_seed_matches_capture``."""
    assert_seed_matches_capture(
        seed_m4300_24x(), _FIXTURES / "m4300-24x.json"
    )


def test_m4300_24x_has_no_poe_and_wire_projects_empty_table():
    """Ground truth (also checked structurally above): the real device's
    capture has poe=[]. This additionally proves the seed's oid_map() ->
    parse_poe() round-trip agrees, not just the raw ``state.poe`` dict."""
    capture = _capture("m4300-24x")
    assert capture["poe"] == []

    state = seed_m4300_24x()
    assert state.poe == {}
    m = state.oid_map()
    poe = parse.parse_poe(
        _rows(m, oids.PETH_PSE_PORT_TABLE),
        _rows(m, oids.vendor_oids(get_model("m4300-24x")).poe_power_mw),
    )
    assert poe == []


def test_m4300_24x_ascii_base_mac_wire_quirk_matches_capture():
    """CRUCIAL: this model's dot1dBaseBridgeAddress is VERIFIED to come back
    as ASCII colon-hex TEXT on real hardware (see parse.py's
    _mac_from_ascii_text) -- prove that quirk round-trips end-to-end through
    the mock's wire projection, not just via a synthetic unit-test row (the
    parsed VALUE equality is already covered by assert_seed_matches_capture
    above; this is the wire-shape proof that helper doesn't reach)."""
    capture = _capture("m4300-24x")
    state = seed_m4300_24x()
    m = state.oid_map()

    wire_type, wire_value = m[f"{oids.DOT1D_BASE_BRIDGE_ADDRESS}.0"]
    assert wire_type == "OCTETSTR"
    assert wire_value == capture["mgmt_ip"]["base_mac"]
    assert len(wire_value) == 17


# --- M4300-16X: PoE on all 16 ports ------------------------------------------


def test_m4300_16x_seed_matches_capture():
    """Ports/PoE/VLANs/PVIDs/sensors/base-MAC all pinned to the real capture
    in one pass -- see ``capture_parity.assert_seed_matches_capture``. (This
    model's captured mgmt_ip.address is None -- the helper honestly skips the
    address/netmask/gateway checks in that case; see its own docstring.)"""
    assert_seed_matches_capture(
        seed_m4300_16x(), _FIXTURES / "m4300-16x.json"
    )


def test_m4300_16x_has_poe_on_all_16_ports_with_two_delivering():
    """Ground truth (also checked structurally above): all 16 ports are
    PoE-capable, with ports 11+12 the two verified-live delivering ports."""
    capture = _capture("m4300-16x")
    assert len(capture["poe"]) == 16

    state = seed_m4300_16x()
    assert len(state.poe) == 16
    m = state.oid_map()
    v = oids.vendor_oids(get_model("m4300-16x"))
    poe = parse.parse_poe(_rows(m, oids.PETH_PSE_PORT_TABLE), _rows(m, v.poe_power_mw))
    delivering = [p for p in poe if p.delivering]
    assert len(delivering) == 2
    assert {p.port for p in delivering} == {11, 12}


def test_m4300_16x_base_mac_matches_capture_raw_bytes_form():
    """Unlike the 24X, no ASCII-text quirk is captured for this model --
    the standard raw-6-bytes encoding must still parse to the same real MAC
    (the parsed VALUE equality is already covered by assert_seed_matches_capture
    above; this additionally proves the wire ENCODING is the plain form)."""
    state = seed_m4300_16x()
    assert state.dot1d_base_mac_ascii is False
    m = state.oid_map()
    wire_type, wire_value = m[f"{oids.DOT1D_BASE_BRIDGE_ADDRESS}.0"]
    assert wire_type == "OCTETSTR"
    assert len(wire_value) == 6  # raw bytes, not the 17-char ASCII form
