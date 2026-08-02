# tests/virtual/test_hostname.py
"""Host name reads and writes, pinned against the virtual switch.

The behaviour worth protecting here is not that a setter sets. It is that the
CLI and SNMP backends report the **same** host name for the same switch, which
on real hardware depends entirely on the CLI reader parsing `show hosts` rather
than `show running-config`.

Measured 2026-08-02 on m4300-16x (10.1.5.20): `show hosts` reports
"sw-netgear-m4300-16x-poe-s2" while `show running-config | include hostname`
reports "manage-sw-netgear-m4300-16x-poe-s2", and on gsm7252ps (10.1.5.22)
running-config carries no hostname line at all while `show hosts` still answers.
A reader written against running-config would therefore disagree with SNMP about
the same device, and the equivalence tests would be right to fail.
"""

from __future__ import annotations

import pytest

from netgear_switch.cli_read import CliReader
from netgear_switch.cli_write import CliWriter
from netgear_switch.errors import CliCommandError
from netgear_switch.protocols.cli import parse as cli_parse
from netgear_switch.protocols.snmp import oids
from netgear_switch.registry import get_model
from netgear_switch.virtual import seed
from netgear_switch.virtual.server import VirtualSwitch

CLI_MODELS = ("m4300-24x", "m4300-16x", "gsm7252ps", "gsm7228ps")
SNMP_MODELS = ("m4300-24x", "m4300-16x", "gsm7252ps", "gsm7228ps", "gs728tpp")


def _seed(key: str):
    return getattr(seed, "seed_" + key.replace("-", "_"))()


@pytest.mark.parametrize("key", SNMP_MODELS)
def test_snmp_projects_sysname(key: str):
    """Every SNMP model answers sysName, as all five real switches do.

    Including gs728tpp, which publishes no Netgear vendor subtree at all --
    sysName is standard MIB-II, which is exactly why it is the hostname source.
    """
    entry = _seed(key).oid_map().get(oids.SYS_NAME)
    assert entry is not None, f"{key} does not project sysName"
    kind, value = entry
    assert kind == "OCTETSTR"
    assert value, f"{key} projects an empty sysName; no real switch here does"


@pytest.mark.parametrize("key", CLI_MODELS)
def test_cli_and_snmp_agree(key: str):
    """`show hosts` and sysName report the same name for one switch."""
    with VirtualSwitch(model=key) as mock:
        cli_name = CliReader(mock.cli_session(), get_model(key)).get_hostname()
    _, snmp_name = _seed(key).oid_map()[oids.SYS_NAME]
    assert cli_name == snmp_name


@pytest.mark.parametrize("key", CLI_MODELS)
def test_cli_hostname_round_trip(key: str):
    with VirtualSwitch(model=key) as mock:
        model = get_model(key)
        session = mock.cli_session()
        reader, writer = CliReader(session, model), CliWriter(session, model)

        original = reader.get_hostname()
        assert original, (
            "seed carries no host name; no real FASTPATH switch is nameless"
        )

        writer.set_hostname("ngsw-test-name")
        assert reader.get_hostname() == "ngsw-test-name"

        writer.set_hostname(original)
        assert reader.get_hostname() == original


def test_empty_hostname_is_refused_not_sent():
    """`hostname` with no argument is rejected by the device itself.

    Sending it would surface as a confusing CliCommandError from inside the
    config-mode helper. Clearing a name is `no hostname`, which is deliberately
    not implemented because it has not been driven against real hardware.
    """
    with VirtualSwitch(model="m4300-24x") as mock:
        writer = CliWriter(mock.cli_session(), get_model("m4300-24x"))
        with pytest.raises(ValueError, match="must not be empty"):
            writer.set_hostname("   ")


def test_parse_hostname_raises_when_the_field_is_absent():
    """An absent "Host name" is a failure to report, not an empty name."""
    with pytest.raises(CliCommandError, match="Host name"):
        cli_parse.parse_hostname("Default domain....... not configured\n")
