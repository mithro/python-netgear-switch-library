# tests/virtual/test_gsm7228ps_seed.py
"""Ground the GSM7228PS / S3300-52X-PoE+ virtual-mock seed in its first real
capture (``tests/fixtures/captures/gsm7228ps.json``, SNMP host 10.1.5.11,
captured 2026-07-30).

Ports/PoE/VLANs/PVIDs/sensors/mgmt-IP/base-MAC parity is delegated to the
reusable ``assert_seed_matches_capture`` harness (see ``tests/capture_parity.py``);
the seed is a literal transcription of the capture, so the strict per-key
equality check holds exactly. What that harness deliberately does not cover
(the model-specific PoE quirk, the vendor sensor OID FAMILY, and the
sysObjectID that drives auto-detection) is checked here directly through the
raw ``oid_map()``/parser layer.
"""

from __future__ import annotations

import json
from pathlib import Path

from capture_parity import assert_seed_matches_capture
from netgear_switch.protocols.snmp import oids, parse
from netgear_switch.protocols.snmp.client import SnmpRow
from netgear_switch.registry import MODELS, get_model
from netgear_switch.virtual.seed import seed_gsm7228ps

_FIXTURES = Path(__file__).parent.parent / "fixtures" / "captures"
_CAPTURE = _FIXTURES / "gsm7228ps.json"


def _capture() -> dict:
    return json.loads(_CAPTURE.read_text())["snapshot"]


def _rows(m: dict[str, tuple[str, str]], base: str) -> list[SnmpRow]:
    return [
        SnmpRow(k, v[1], v[0])
        for k, v in m.items()
        if k == base or k.startswith(base + ".")
    ]


def test_gsm7228ps_seed_matches_capture():
    """Ports/PoE/VLANs/PVIDs/sensors/mgmt-IP/base-MAC all pinned to the real
    S3300-52X capture in one pass -- see
    ``capture_parity.assert_seed_matches_capture``."""
    assert_seed_matches_capture(seed_gsm7228ps(), _CAPTURE)


def test_gsm7228ps_poe_48_ports_two_delivering_one_fault():
    """Ground truth (also checked structurally above): 48 PoE ports, with two
    ports actually delivering power (400/700 mW) and one in fault -- proven
    through the seed's oid_map() -> parse_poe() round-trip, not just the raw
    ``state.poe`` dict."""
    capture = _capture()
    assert len(capture["poe"]) == 48

    state = seed_gsm7228ps()
    assert len(state.poe) == 48
    m = state.oid_map()
    v = oids.vendor_oids(get_model("gsm7228ps"))
    poe = parse.parse_poe(_rows(m, oids.PETH_PSE_PORT_TABLE), _rows(m, v.poe_power_mw))
    delivering = [p for p in poe if p.delivering]
    assert {p.port for p in delivering} == {
        p["port"] for p in capture["poe"] if p["power_mw"] > 0
    }
    assert sorted(p.power_mw for p in delivering) == [400, 700]


def test_gsm7228ps_sensors_live_under_4526_11_vendor_family():
    """The whole vendor-family question this live capture settled: unlike
    gs728tpp (zero 4526 OIDs), the S3300-52X's fan/temp sensors really do live
    under the _SMP 4526.11 subtree. Prove the seed emits them there and that
    parse_box_sensors round-trips all 5 (3 fan + PSU watts + temperature)
    value-for-value against the capture."""
    state = seed_gsm7228ps()
    m = state.oid_map()
    v = oids.vendor_oids(get_model("gsm7228ps"))
    assert v.box_fan.startswith("1.3.6.1.4.1.4526.11.43.")
    # fan RPM rows are actually present under the 4526.11 vendor base.
    assert any(k.startswith(v.box_fan + ".") for k in m)

    def rows(base: str) -> list[SnmpRow]:
        return [
            SnmpRow(k, val[1], val[0])
            for k, val in m.items()
            if k == base or k.startswith(base + ".")
        ]

    sensors = parse.parse_box_sensors(
        [
            ("fan", "RPM", rows(v.box_fan)),
            ("power", "W", rows(v.box_psu_power)),
            ("temperature", "C", rows(v.box_temp)),
        ]
    )
    got = {(s.kind, s.name): s.value for s in sensors}
    want = {(s["kind"], s["name"]): s["value"] for s in _capture()["sensors"]}
    assert got == want


def test_gsm7228ps_seed_sysobjectid_auto_detects_the_model():
    """End-to-end tie between the seed and the detection fix: the seed carries
    the REAL sysObjectID, which SYSOBJECTID_MODELS maps back to gsm7228ps (the
    sysDescr text alone cannot, being the same shape as the unregistered
    S3300-28X)."""
    state = seed_gsm7228ps()
    assert state.sys_object_id == "1.3.6.1.4.1.4526.100.10.19"
    assert (
        parse.detect_model_from_sysobjectid(state.sys_object_id, MODELS) == "gsm7228ps"
    )
    assert parse.detect_model_from_sysdescr(state.sys_descr, MODELS) is None
