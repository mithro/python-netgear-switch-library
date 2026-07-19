# tests/protocols/snmp/test_parse_system_info.py
"""Pure unit tests for sysDescr/sysObjectID model detection (Task 2).

Two layers are tested independently, on purpose:

* ``parse_system_info``: dumb row -> (sys_descr, sys_object_id) extraction
  from a combined exact-OID GET result. No model matching at all here.
* ``detect_model_from_sysdescr``: the matching heuristic, tested against
  plain strings -- no SnmpRow/client machinery needed. This is where the
  HONESTY constraint (never guess; unregistered/ambiguous -> None) is proven.
"""
from __future__ import annotations

import re

import pytest

from netgear_switch.protocols.snmp import oids, parse
from netgear_switch.protocols.snmp.client import SnmpError, SnmpRow
from netgear_switch.registry import MODELS

# --- parse_system_info: pure row extraction ---------------------------------


def test_parse_system_info_extracts_both_scalars():
    rows = [
        SnmpRow(oids.SYS_DESCR, "NETGEAR GSM7252PS", "STRING"),
        SnmpRow(oids.SYS_OBJECT_ID, "1.3.6.1.4.1.4526.10.100.14", "OID"),
    ]
    descr, object_id = parse.parse_system_info(rows)
    assert descr == "NETGEAR GSM7252PS"
    assert object_id == "1.3.6.1.4.1.4526.10.100.14"


def test_parse_system_info_absent_scalars_are_honestly_none():
    descr, object_id = parse.parse_system_info([])
    assert descr is None
    assert object_id is None


def test_parse_system_info_decodes_bytes_octetstring():
    rows = [SnmpRow(oids.SYS_DESCR, b"NETGEAR M4300-24X", "OCTETSTR")]
    descr, object_id = parse.parse_system_info(rows)
    assert descr == "NETGEAR M4300-24X"
    assert object_id is None


def test_parse_system_info_malformed_value_raises_snmp_error():
    # Present-but-wrong-type (e.g. an int where text is required) is drift,
    # not absence, and must raise SnmpError naming the offending OID.
    rows = [SnmpRow(oids.SYS_DESCR, 12345, "INTEGER")]
    with pytest.raises(SnmpError, match=re.escape(oids.SYS_DESCR)):
        parse.parse_system_info(rows)


def test_parse_system_info_ignores_unrelated_rows():
    rows = [
        SnmpRow("1.3.6.1.2.1.1.5.0", "some-hostname", "STRING"),  # sysName, unrelated
        SnmpRow(oids.SYS_OBJECT_ID, "1.3.6.1.4.1.4526.11.100.1", "OID"),
    ]
    descr, object_id = parse.parse_system_info(rows)
    assert descr is None
    assert object_id == "1.3.6.1.4.1.4526.11.100.1"


# --- detect_model_from_sysdescr: the matching heuristic ---------------------

# One realistic-looking sysDescr string per registered model, each proven to
# resolve to that model's own registry key.
_REALISTIC_SYSDESCR_BY_KEY = {
    "m4300-24x": "NETGEAR M4300-24X, Software 12.0.11.9, Linux 3.6.5",
    "m4300-16x": "NETGEAR M4300-16X, Software 12.0.11.9",
    "gsm7252ps": "NETGEAR GSM7252PS Managed Switch, firmware 8.0.6.6",
    "gsm7228ps": "NETGEAR GSM7228PS Managed Switch, firmware 6.4.2.9",
    "gs110emx": "NETGEAR GS110EMX",
    "gs305ep": "NETGEAR GS305EP",
    # UNVERIFIED-pending-capture models (registry.py) -- these are
    # illustrative strings, not captured firmware sysDescr text; they only
    # need to contain the registered display_name/key tokens.
    "m7300": "NETGEAR M7300-24XF, Software 12.0.4.5",
    "xs748t": "NETGEAR XS748T Managed Switch",
    "gs728tpp": "NETGEAR GS728TPP Managed Switch, firmware 6.4.2.9",
}


@pytest.mark.parametrize(("key", "sys_descr"), _REALISTIC_SYSDESCR_BY_KEY.items())
def test_detect_model_from_sysdescr_matches_every_registered_model(key, sys_descr):
    assert parse.detect_model_from_sysdescr(sys_descr, MODELS) == key


def test_detect_model_from_sysdescr_is_case_insensitive():
    assert (
        parse.detect_model_from_sysdescr("netgear gsm7252ps switch", MODELS)
        == "gsm7252ps"
    )
    assert (
        parse.detect_model_from_sysdescr("Netgear M4300-24X", MODELS) == "m4300-24x"
    )


def test_detect_model_from_sysdescr_matches_s3300_alias_for_gsm7228ps():
    # display_name "GSM7228PS (S3300)": the parenthesized alias must ALSO
    # resolve to the same registry key, since real Netgear sysDescr text may
    # use either name.
    #
    # NOTE: this used to assert on "NETGEAR S3300-52X-PoE+" (a fabricated,
    # never-verified SKU string). That string is UNSAFE to accept: it has
    # the exact same shape ("S3300" + "-" + 2 digits + "X" + suffix) as the
    # real, unregistered "S3300-28X"/"S3300-28X-PoE+" SKUs that must return
    # None (see test_detect_model_from_sysdescr_rejects_unregistered_s3300_skus
    # below) -- no textual rule can accept one shape and reject the other,
    # since the only difference is the specific digits, which carry no
    # generic textual meaning. So the alias match is now proven against a
    # bare, unsuffixed occurrence of the alias token instead, which is the
    # only form that is unambiguously safe to match.
    assert parse.detect_model_from_sysdescr(
        "NETGEAR S3300 Managed Switch, firmware 6.4.2.9", MODELS
    ) == "gsm7228ps"


def test_detect_model_from_sysdescr_matches_xsm_alias_for_m4300_24x():
    assert (
        parse.detect_model_from_sysdescr("NETGEAR XSM4324CS", MODELS) == "m4300-24x"
    )


def test_detect_model_from_sysdescr_unregistered_netgear_model_is_none():
    # GS752TP is a real-looking Netgear model NAME that is NOT in the
    # registry. This must NEVER be coerced onto some other, wrong,
    # registered model -- honestly None.
    assert parse.detect_model_from_sysdescr("NETGEAR GS752TP switch", MODELS) is None


def test_detect_model_from_sysdescr_rejects_m7300_28g_extension_of_m7300():
    # CRITICAL safety regression (same shape as GS305EPP/S3300-28X below):
    # "m7300" IS now registered (UNVERIFIED-pending-capture), but M7300-28G
    # is a distinct, unregistered M7300-family SKU suffix, not the bare
    # registered token. Must honestly return None, never "m7300".
    assert parse.detect_model_from_sysdescr("NETGEAR M7300-28G", MODELS) is None


def test_detect_model_from_sysdescr_matches_unverified_models():
    # The three UNVERIFIED-pending-capture models (registry.py) are matched
    # by both their bare registered key and their full display-name/SKU
    # token, exactly like the verified models above.
    assert parse.detect_model_from_sysdescr("NETGEAR M7300 switch", MODELS) == "m7300"
    assert (
        parse.detect_model_from_sysdescr("NETGEAR M7300-24XF switch", MODELS)
        == "m7300"
    )
    assert (
        parse.detect_model_from_sysdescr("NETGEAR XS748T switch", MODELS) == "xs748t"
    )
    assert (
        parse.detect_model_from_sysdescr("NETGEAR GS728TPP switch", MODELS)
        == "gs728tpp"
    )


def test_detect_model_from_sysdescr_non_netgear_garbage_is_none():
    assert parse.detect_model_from_sysdescr("Cisco IOS Software, C2960", MODELS) is None
    assert parse.detect_model_from_sysdescr("", MODELS) is None
    assert parse.detect_model_from_sysdescr(None, MODELS) is None


def test_detect_model_from_sysdescr_distinguishes_m4300_16x_from_24x():
    # Neither model's tokens may be a substring of the other's -- otherwise a
    # 16X switch could be misidentified as a 24X (or vice versa).
    assert (
        parse.detect_model_from_sysdescr("NETGEAR M4300-16X", MODELS) == "m4300-16x"
    )
    assert (
        parse.detect_model_from_sysdescr("NETGEAR M4300-24X", MODELS) == "m4300-24x"
    )


def test_detect_model_from_sysdescr_distinguishes_gsm7252ps_from_gsm7228ps():
    assert (
        parse.detect_model_from_sysdescr("NETGEAR GSM7252PS", MODELS) == "gsm7252ps"
    )
    assert (
        parse.detect_model_from_sysdescr("NETGEAR GSM7228PS", MODELS) == "gsm7228ps"
    )


def test_detect_model_from_sysdescr_rejects_gs305epp_extension_of_gs305ep():
    # CRITICAL safety regression: GS305EPP is a real, distinct, unregistered
    # 123W model -- NOT the registered 63W GS305EP. Bare substring matching
    # used to wrongly return "gs305ep" here because "GS305EP" is a prefix of
    # "GS305EPP" with no word boundary check. Must honestly return None.
    assert parse.detect_model_from_sysdescr(
        "NETGEAR GS305EPP Managed Switch", MODELS
    ) is None


def test_detect_model_from_sysdescr_rejects_unregistered_s3300_skus():
    # CRITICAL safety regression: S3300-28X (and its -PoE+ variant) are
    # real, distinct, unregistered S3300 SKUs -- NOT the registered 52-port
    # GSM7228PS (alias "S3300"). Bare substring matching used to wrongly
    # return "gsm7228ps" here since "S3300" is a substring/prefix of
    # "S3300-28X" separated only by a hyphen. Must honestly return None.
    assert parse.detect_model_from_sysdescr("NETGEAR S3300-28X", MODELS) is None
    assert parse.detect_model_from_sysdescr(
        "NETGEAR S3300-28X-PoE+ Managed Switch", MODELS
    ) is None


def test_detect_model_from_sysdescr_ambiguous_match_is_none():
    # Defence-in-depth: if a sysDescr text happened to contain TWO different
    # registered models' tokens, this must return None (never pick one
    # arbitrarily) -- proven here with a deliberately-constructed pair of
    # tiny fake models whose tokens both appear in one string, since the real
    # registry currently has no such collision.
    from netgear_switch.registry import Backend, SwitchClass, SwitchModel

    fake_models = {
        "fake-a": SwitchModel(
            key="fake-a", display_name="FAKEA", switch_class=SwitchClass.PLUS,
            port_count=1, poe_port_count=0, backends=frozenset({Backend.SNMP}),
            snmp_vendor_base=None,
        ),
        "fake-b": SwitchModel(
            key="fake-b", display_name="FAKEB", switch_class=SwitchClass.PLUS,
            port_count=1, poe_port_count=0, backends=frozenset({Backend.SNMP}),
            snmp_vendor_base=None,
        ),
    }
    assert (
        parse.detect_model_from_sysdescr("NETGEAR FAKEA FAKEB switch", fake_models)
        is None
    )
