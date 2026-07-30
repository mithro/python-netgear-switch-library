import pytest

from netgear_switch.errors import UnknownModelError
from netgear_switch.registry import (
    MODEL_ALIASES,
    MODELS,
    Backend,
    SwitchClass,
    get_model,
)

_VERIFIED_KEYS = (
    "m4300-24x", "m4300-16x", "gsm7252ps", "gs110emx", "gs305ep",
    "gs105pe", "gs728tpp",
)
# gsm7228ps is UNVERIFIED-pending-capture (no real capture exists; _SMP vendor
# family is an unconfirmed spec-guess) -- honesty flag matches m7300/xs748t.
_UNVERIFIED_KEYS = ("m7300", "xs748t", "gsm7228ps")


def test_known_models_present():
    for key in _VERIFIED_KEYS + _UNVERIFIED_KEYS:
        assert key in MODELS


def test_managed_switch_has_snmp_and_vendor_base():
    m = get_model("gsm7252ps")
    assert Backend.SNMP in m.backends
    assert m.poe_port_count == 48
    assert m.snmp_vendor_base == "1.3.6.1.4.1.4526.10"
    assert m.has_mac_table is True


def test_smart_managed_pro_uses_4526_11():
    assert get_model("gsm7228ps").snmp_vendor_base == "1.3.6.1.4.1.4526.11"


def test_plus_switch_no_snmp_no_mac_table():
    p = get_model("gs110emx")
    assert Backend.SNMP not in p.backends
    assert Backend.NSDP in p.backends
    assert Backend.HTTP in p.backends
    assert p.snmp_vendor_base is None
    assert p.has_mac_table is False
    assert p.switch_class is SwitchClass.PLUS


def test_unknown_model_raises():
    with pytest.raises(UnknownModelError):
        get_model("nonesuch")


def test_s3300_and_gsm7228ps_are_aliases_for_each_other():
    # The model registered as "gsm7228ps" is really the S3300-52X-PoE+; both
    # names must resolve to the exact same SwitchModel (inventories/CLI use
    # either). get_model("s3300") returns the canonical gsm7228ps model.
    assert MODEL_ALIASES["s3300"] == "gsm7228ps"
    assert get_model("s3300") is get_model("gsm7228ps")
    assert get_model("s3300").key == "gsm7228ps"


def test_aliases_are_not_listed_as_separate_models():
    # MODELS stays a canonical one-key-per-model listing -- aliases resolve on
    # lookup but must NOT appear as extra entries (else CLI/MCP double-count).
    for alias in MODEL_ALIASES:
        assert alias not in MODELS, alias


def test_verified_defaults_true_for_existing_models():
    for key in _VERIFIED_KEYS:
        assert get_model(key).verified is True, key


def test_unverified_models_are_honestly_flagged():
    for key in _UNVERIFIED_KEYS:
        assert get_model(key).verified is False, key


def test_m7300_registered_fully_managed_snmp_only():
    m = get_model("m7300")
    assert m.switch_class is SwitchClass.FULLY_MANAGED
    assert m.backends == frozenset({Backend.SNMP})
    assert m.snmp_vendor_base == "1.3.6.1.4.1.4526.10"
    assert m.port_count == 24
    assert m.poe_port_count == 0
    assert m.verified is False


def test_xs748t_registered_smart_managed_pro_snmp_only():
    m = get_model("xs748t")
    assert m.switch_class is SwitchClass.SMART_MANAGED_PRO
    assert m.backends == frozenset({Backend.SNMP})
    assert m.snmp_vendor_base == "1.3.6.1.4.1.4526.11"
    assert m.port_count == 48
    assert m.poe_port_count == 0
    assert m.verified is False


def test_gs728tpp_registered_smart_managed_pro_snmp_http():
    # SNMP OID family RESOLVED by a real live capture (10.2.5.10): this agent
    # implements ZERO Netgear vendor OIDs and serves everything via standard
    # MIBs, so snmp_vendor_base is None (NOT the old _SMP guess). verified=True:
    # SNMP<->HTTP parity is cross-verified (see test_cross_backend_equivalence).
    m = get_model("gs728tpp")
    assert m.switch_class is SwitchClass.SMART_MANAGED_PRO
    assert m.backends == frozenset({Backend.SNMP, Backend.HTTP})
    assert Backend.HTTP in m.backends
    assert m.snmp_vendor_base is None
    assert m.port_count == 28
    assert m.poe_port_count == 24
    assert m.verified is True


def test_gs105pe_registered_plus_nsdp_http_verified():
    """gs105pe (a real, DISTINCT SKU from gs305ep) is now LIVE-VERIFIED
    (poe-micro2/3 @ 10.1.5.29/.30, 2026-07-21): NSDP MODEL="GS105PE",
    port_count=5. verified=True; PoE=0 confirmed (getPoePortStatus.cgi 404s)."""
    m = get_model("gs105pe")
    assert m.switch_class is SwitchClass.PLUS
    assert m.backends == frozenset({Backend.NSDP, Backend.HTTP})
    assert Backend.SNMP not in m.backends
    assert m.snmp_vendor_base is None
    assert m.port_count == 5
    assert m.poe_port_count == 0
    assert m.verified is True


def test_gs105pe_virtual_seed_matches_live_capture():
    """VirtualSwitch("gs105pe") is seeded from the real live capture (host
    10.1.5.30): ports 3 (100M) and 5 (1G) up, VLANs 1/41/90, real PVIDs, and
    the real base MAC -- never blank, never fabricated."""
    from netgear_switch.virtual.server import VirtualSwitch

    sw = VirtualSwitch(model="gs105pe")
    st = sw.state
    assert st.model_name == "GS105PE"
    assert st.nsdp_mac == b"\x38\x94\xed\xb7\xcd\xe0"
    assert {p: (s.link, s.speed) for p, s in st.ports.items()} == {
        1: (False, 0), 2: (False, 0), 3: (True, 100), 4: (False, 0), 5: (True, 1000)
    }
    assert set(st.vlans) == {1, 41, 90}
    assert st.pvids == {1: 41, 2: 41, 3: 90, 4: 41, 5: 1}
    # Plus family: no PoE PSE, no MAC/FDB
    assert st.poe == {}
    assert st.macs == []


def test_registry_has_no_duplicate_keys_and_valid_enums():
    keys = [m.key for m in MODELS.values()]
    assert len(keys) == len(set(keys))
    for key, model in MODELS.items():
        assert model.key == key
        assert isinstance(model.switch_class, SwitchClass)
        assert all(isinstance(b, Backend) for b in model.backends)
        assert model.backends, f"{key} has no backends"
