# tests/test_port_speed_http.py
"""``set_port_speed`` over the GoAhead XML API, and the read that pairs with it.

Grounded in ``tests/fixtures/http/gs728tpp_ports.xml``, captured from the live
GS728TPP (10.2.5.10, firmware 6.0.1.30). That file carries BOTH halves of the
specification -- the page's own JavaScript and a real ``Standard802_3List``
response -- so nothing here is inferred from a MIB or a convention.

The submit builder, verbatim from the capture::

    var autoNegAdmin = (speedAdmin == "0") ? "1" : "2";
    if (speedAdmin == "")       duplexAdmin = "";
    else if (speedAdmin == "0") duplexAdmin = "3";
    else { duplexAdmin = (last char == "H") ? "2" : "3";
           speedAdmin = parseInt(speedAdmin, 10); }

and the display decoder::

    if (field.autoNegotiationAdminEnabled == "1") str = "Auto";
    else str = field.speedAdmin + "M" + (duplexAdminMode=="3" ? " Full" : " Half");

The dropdown that feeds the first is ``slctPortSpeed``, whose options are
10H/10F/100H/100F/1000F/0(Auto). Note what that means: this UI offers a FORCED
1000 that the FASTPATH CLI's grammar does not, and offers no 1000 half-duplex
at all.
"""

from __future__ import annotations

import pathlib
import re

import pytest

from netgear_switch._dispatch import build_sync_http_client
from netgear_switch.errors import UnsupportedCapabilityError, WriteVerificationError
from netgear_switch.http_read import HttpReader
from netgear_switch.http_write import HttpWriter
from netgear_switch.models import PortSpeed
from netgear_switch.protocols.http import goahead
from netgear_switch.protocols.http.parse import parse_goahead_ports
from netgear_switch.registry import get_model
from netgear_switch.virtual.server import VirtualSwitch

_MODEL = "gs728tpp"
FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "http"


# --- the write body ----------------------------------------------------------


def test_auto_sends_what_the_pages_js_sends() -> None:
    """Dropdown "0": autoNeg 1, speedAdmin 0, duplex 3.

    The zero matters -- the JS sets ``speedAdmin`` to "0" rather than leaving
    it undefined, so the field IS sent on an auto write.
    """
    body = goahead.port_speed_body("g8", 8, PortSpeed.auto())
    assert "<autoNegotiationAdminEnabled>1</autoNegotiationAdminEnabled>" in body
    assert "<speedAdmin>0</speedAdmin>" in body
    assert "<duplexAdminMode>3</duplexAdminMode>" in body
    assert '<Standard802_3List action="set">' in body


@pytest.mark.parametrize(
    ("speed", "rate", "duplex"),
    [
        # One per non-Auto option the page's own dropdown lists.
        (PortSpeed.forced(10, full_duplex=False), "10", "2"),
        (PortSpeed.forced(10, full_duplex=True), "10", "3"),
        (PortSpeed.forced(100, full_duplex=False), "100", "2"),
        (PortSpeed.forced(100, full_duplex=True), "100", "3"),
        (PortSpeed.forced(1000, full_duplex=True), "1000", "3"),
    ],
)
def test_forced_sends_autoneg_off_with_the_parsed_rate(
    speed: PortSpeed, rate: str, duplex: str
) -> None:
    body = goahead.port_speed_body("g8", 8, speed)
    assert "<autoNegotiationAdminEnabled>2</autoNegotiationAdminEnabled>" in body
    assert f"<speedAdmin>{rate}</speedAdmin>" in body
    assert f"<duplexAdminMode>{duplex}</duplexAdminMode>" in body


def test_the_offered_set_is_the_pages_own_option_list() -> None:
    """Read straight off ``slctPortSpeed`` in the captured page.

    Pinned against the fixture rather than restated, so a re-capture that
    changes the switch's offering fails here instead of drifting silently.
    """
    html = (FIXTURES / "gs728tpp_ports.xml").read_text()
    for value in ("10H", "10F", "100H", "100F", "1000F"):
        assert f'<option value="{value}">' in html
    assert '<option value="1000H">' not in html  # no gigabit half-duplex

    assert frozenset(
        {(10, False), (10, True), (100, False), (100, True), (1000, True)}
    ) == goahead.GOAHEAD_FORCED_SPEEDS


# --- the read ----------------------------------------------------------------


def test_autoneg_wins_over_the_rate_beside_it() -> None:
    """The trap this decoder exists to avoid, settled by the capture itself.

    All 28 ports of the live switch report ``speedAdmin`` 1000 and
    ``duplexAdminMode`` 3 -- IDENTICALLY. The only field that differs is
    ``autoNegotiationAdminEnabled``: 1 on the 24 copper ports, 2 on the four
    SFP uplinks. So the flag is not merely authoritative in principle, it is
    the ONLY thing distinguishing the two states in real data, and a decoder
    reading the rate would report the whole switch as forced to 1000.

    (Those four forced-1000 SFP ports are also the concrete reason a forced
    1000 is not refused on this backend: 1000BASE-X has no auto-negotiation
    requirement, and this switch really is configured that way in production.)
    """
    ports = {
        p.port: p
        for p in parse_goahead_ports((FIXTURES / "gs728tpp_ports.xml").read_text())
    }
    assert len(ports) == 28

    copper = [p for n, p in ports.items() if n <= 24]
    sfp = [p for n, p in ports.items() if n > 24]
    assert all(p.speed_config == PortSpeed.auto() for p in copper)
    assert all(p.speed_config == PortSpeed.forced(1000, full_duplex=True) for p in sfp)


def test_the_capture_distinguishes_them_by_the_flag_alone() -> None:
    """Guards the claim above: the other two fields really are identical.

    Read from the raw XML rather than through the parser, so this cannot be
    satisfied by the decoder agreeing with itself.
    """
    body = (FIXTURES / "gs728tpp_ports.xml").read_text()

    def field(entry: str, tag: str) -> str | None:
        m = re.search(rf"<{tag}>(.*?)</{tag}>", entry)
        return m.group(1) if m else None

    entries = re.findall(r"<Entry>(.*?)</Entry>", body, re.S)
    # 36 rows: the 28 physical ports plus 8 LAG pseudo-interfaces, which the
    # parser drops. The LAGs carry speedAdmin 0 -- a reminder that this list is
    # not all ports.
    assert len(entries) == 36
    physical = [
        e for e in entries if re.fullmatch(r"g\d+", field(e, "interfaceName") or "")
    ]
    assert len(physical) == 28

    assert {field(e, "speedAdmin") for e in physical} == {"1000"}
    assert {field(e, "duplexAdminMode") for e in physical} == {"3"}
    assert {field(e, "autoNegotiationAdminEnabled") for e in physical} == {"1", "2"}


@pytest.mark.parametrize(
    ("autoneg", "rate", "duplex", "expected"),
    [
        ("1", "1000", "3", PortSpeed.auto()),
        ("2", "100", "3", PortSpeed.forced(100, full_duplex=True)),
        ("2", "10", "2", PortSpeed.forced(10, full_duplex=False)),
        # Neither code the page knows about, and a duplex code it does not use:
        # honestly unknown rather than a fabricated guess.
        ("4", "100", "3", None),
        ("2", "100", "9", None),
    ],
)
def test_decodes_each_field_combination(
    autoneg: str, rate: str, duplex: str, expected: PortSpeed | None
) -> None:
    body = (
        "<?xml version='1.0' encoding='utf-8'?><DeviceConfiguration>"
        '<Standard802_3List type="section"><Entry>'
        "<interfaceName>g1</interfaceName><interfaceType>1</interfaceType>"
        "<adminState>1</adminState><linkState>1</linkState>"
        "<speedOper>1000</speedOper><duplexOperMode>2</duplexOperMode>"
        f"<speedAdmin>{rate}</speedAdmin>"
        f"<duplexAdminMode>{duplex}</duplexAdminMode>"
        f"<autoNegotiationAdminEnabled>{autoneg}</autoNegotiationAdminEnabled>"
        "</Entry></Standard802_3List></DeviceConfiguration>"
    )
    assert parse_goahead_ports(body)[0].speed_config == expected


# --- the writer, against the fake --------------------------------------------


def _rw(mock: VirtualSwitch) -> tuple[HttpReader, HttpWriter]:
    model = get_model(_MODEL)
    client = build_sync_http_client(
        f"{mock.host}:{mock.http_port}", mock.http_password, model
    )
    return HttpReader(client, model), HttpWriter(client, model)


def _config(reader: HttpReader, port: int) -> PortSpeed | None:
    return next(p.speed_config for p in reader.get_ports() if p.port == port)


def test_forcing_and_restoring_round_trips() -> None:
    with VirtualSwitch(model=_MODEL) as mock:
        reader, writer = _rw(mock)
        before = _config(reader, 8)
        assert before == PortSpeed.auto()

        writer.set_port_speed(8, PortSpeed.forced(100, full_duplex=True), force=True)
        assert _config(reader, 8) == PortSpeed.forced(100, full_duplex=True)

        writer.set_port_speed(8, PortSpeed.auto(), force=True)
        assert _config(reader, 8) == before


def test_a_forced_1000_is_accepted_here_unlike_the_cli() -> None:
    """The two backends genuinely disagree, and each is right about its device.

    The FASTPATH CLI refuses a forced 1000 because its grammar has none; this
    UI's own dropdown offers "1000M Full Duplex". Harmonising the two into one
    rule would have made one of them wrong about real hardware.
    """
    with VirtualSwitch(model=_MODEL) as mock:
        reader, writer = _rw(mock)
        writer.set_port_speed(8, PortSpeed.forced(1000, full_duplex=True), force=True)
        assert _config(reader, 8) == PortSpeed.forced(1000, full_duplex=True)


def test_a_choice_the_page_does_not_offer_is_refused() -> None:
    with VirtualSwitch(model=_MODEL) as mock:
        _reader, writer = _rw(mock)
        # No 1000 HALF option exists on this page.
        with pytest.raises(UnsupportedCapabilityError, match="offers no"):
            writer.set_port_speed(
                8, PortSpeed.forced(1000, full_duplex=False), force=True
            )
        # Nor 10G: this SKU's page lists nothing above 1000.
        with pytest.raises(UnsupportedCapabilityError, match="offers no"):
            writer.set_port_speed(
                8, PortSpeed.forced(10000, full_duplex=True), force=True
            )


def test_forcing_a_speed_does_not_invent_a_negotiated_rate() -> None:
    """speedOper/linkState stay put; only the admin fields move."""
    with VirtualSwitch(model=_MODEL) as mock:
        reader, writer = _rw(mock)
        was = next(p for p in reader.get_ports() if p.port == 8)
        writer.set_port_speed(8, PortSpeed.forced(10, full_duplex=False), force=True)
        now = next(p for p in reader.get_ports() if p.port == 8)

        assert now.speed_config == PortSpeed.forced(10, full_duplex=False)
        assert (now.link_up, now.speed_mbps) == (was.link_up, was.speed_mbps)


def test_a_deaf_switch_is_caught() -> None:
    """Verify-after-write, the rail that makes this safe to offer."""
    with VirtualSwitch(model=_MODEL) as mock:
        _reader, writer = _rw(mock)
        writer._goahead_write = lambda body, what: None  # type: ignore[method-assign]
        with pytest.raises(WriteVerificationError, match="did not read back"):
            writer.set_port_speed(
                8, PortSpeed.forced(100, full_duplex=True), force=True
            )


def test_another_dialect_refuses_by_name() -> None:
    """Only the XML-API UI has a captured speed form; the XUI cell id does not."""
    model = get_model("gsm7252ps")
    with VirtualSwitch(model="gsm7252ps") as mock:
        writer = HttpWriter(
            build_sync_http_client(
                f"{mock.host}:{mock.http_port}", mock.http_password, model
            ),
            model,
        )
        with pytest.raises(UnsupportedCapabilityError, match="no HTTP speed/duplex"):
            writer.set_port_speed(8, PortSpeed.auto(), force=True)
