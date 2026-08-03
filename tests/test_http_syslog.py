# tests/test_http_syslog.py
"""HTTP ``get_syslog`` against the REAL captured pages, and against the fake.

``syslogConfiguration.html`` was fetched live on 2026-08-03 from all four
managed switches and committed under ``tests/fixtures/http/``. Every expectation
here is transcribed from those pages, never computed.

The point of parametrising all four is the claim the parser rests on: the two
web-UI families are NOT the same page -- the M4300s are Cheetah and add a
trailing ``<!-- baselogCfg_* -->`` comment per cell plus two scalars the GSMs do
not emit -- yet every COORDINATE the reader addresses is identical, which is why
one parser serves both. If a firmware ever moves one, exactly one row fails.
"""

from __future__ import annotations

import pathlib

import pytest

from netgear_switch._dispatch import build_sync_http_client
from netgear_switch.errors import HttpUnexpectedPageError, UnsupportedCapabilityError
from netgear_switch.http_read import HttpReader
from netgear_switch.protocols.http.parse import parse_xui_syslog
from netgear_switch.registry import get_model
from netgear_switch.snmp_read import SnmpReader
from netgear_switch.transport.sync.snmp_netsnmp_cli import NetsnmpCliClient
from netgear_switch.virtual.server import VirtualSwitch

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "http"

#: The page each switch really served, and what it said. All four carry the
#: SAME configuration -- enabled, local port 514, one Active IPv4 collector
#: 10.1.5.1:514 at severity "Info" (6) -- which is what the fleet is set to.
CAPTURES = {
    "gsm7252ps": "gsm7252ps_syslog_configuration.html",
    "gsm7228ps": "gsm7228ps_syslog_configuration.html",
    "m4300-24x": "m4300_24x_syslog_configuration.html",
    "m4300-16x": "m4300_16x_syslog_configuration.html",
}


@pytest.mark.parametrize("key", sorted(CAPTURES))
def test_parses_every_managed_switchs_real_page(key: str) -> None:
    cfg = parse_xui_syslog((FIXTURES / CAPTURES[key]).read_text())

    assert cfg.enabled is True
    assert cfg.local_port == 514
    assert len(cfg.servers) == 1
    server = cfg.servers[0]
    assert server.host == "10.1.5.1"
    assert server.port == 514
    # The page prints the WORD "Info"; SNMP's column reads 6 on the same switch.
    assert server.severity == 6
    assert server.active is True


def test_severity_word_is_translated_not_defaulted() -> None:
    """A severity the library has not measured must RAISE, not read as 0.

    0 is "emergency" -- a real, plausible level -- so defaulting to it would
    report the switch as forwarding emergencies only, wrongly and invisibly.
    """
    html = (
        (FIXTURES / CAPTURES["gsm7252ps"])
        .read_text()
        .replace('VALUE="Info"', 'VALUE="Verbose"')
    )
    with pytest.raises(ValueError, match="unknown syslog severity 'Verbose'"):
        parse_xui_syslog(html)


def test_a_page_without_the_admin_field_is_refused() -> None:
    """A fetch that landed somewhere else must not read as "logging disabled"."""
    with pytest.raises(HttpUnexpectedPageError, match="no Admin Status field"):
        parse_xui_syslog("<html><body>login required</body></html>")


def _http_reader(mock: VirtualSwitch, key: str) -> HttpReader:
    model = get_model(key)
    return HttpReader(
        build_sync_http_client(f"{mock.host}:{mock.http_port}", "password", model),
        model,
    )


@pytest.mark.parametrize("key", ["gsm7252ps", "gsm7228ps", "m4300-24x"])
def test_fake_serves_the_page_and_agrees_with_its_own_snmp(key: str) -> None:
    """The fake must answer get_syslog IDENTICALLY over HTTP and SNMP.

    gsm7228ps is the load-bearing row: its seed has NO collectors, so this also
    proves the page's blank ``g_2_1_*`` template row -- which real firmware
    emits and the mock reproduces -- is not parsed as a phantom collector with
    an empty host.
    """
    model = get_model(key)
    with VirtualSwitch(model=key) as mock:
        over_http = _http_reader(mock, key).get_syslog()
        over_snmp = SnmpReader(
            NetsnmpCliClient(f"{mock.host}:{mock.port}", mock.community), model
        ).get_syslog()

    assert over_http == over_snmp
    assert over_http.local_port == 514


def test_a_model_with_no_syslog_page_refuses_by_name() -> None:
    """The Plus/GoAhead UIs have no such page -- that must raise, not read empty."""
    model = get_model("gs305ep")
    with VirtualSwitch(model="gs305ep") as mock:
        reader = HttpReader(
            build_sync_http_client(f"{mock.host}:{mock.http_port}", "password", model),
            model,
        )
        with pytest.raises(UnsupportedCapabilityError, match="remote-logging"):
            reader.get_syslog()
