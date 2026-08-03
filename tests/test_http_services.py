# tests/test_http_services.py
"""HTTP ``get_services`` against the REAL captured pages, and against the fake.

All four service pages were fetched live on 2026-08-03 and committed under
``tests/fixtures/http/``. The readings were cross-checked against each switch's
own ``show ip http`` / ``show ip ssh`` / ``show telnetcon``, every state and
every printed port agreeing.

Two page SHAPES exist and they are mixed WITHIN a model, which is why the
parser is keyed per service rather than per model or per html_dialect:

    gsm7252ps  http https ssh telnet   all XUI labelled scalars
    m4300-24x  http https              plain named form (radios + text inputs)
               ssh telnet              XUI
"""

from __future__ import annotations

import pathlib

import pytest

from netgear_switch._dispatch import build_sync_http_client
from netgear_switch.errors import HttpUnexpectedPageError, UnsupportedCapabilityError
from netgear_switch.http_read import HttpReader
from netgear_switch.protocols.http.parse import parse_service_page
from netgear_switch.registry import get_model
from netgear_switch.virtual.server import VirtualSwitch

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "http"

#: (model, service) -> (fixture, expected enabled, expected port). Transcribed
#: from the live pages; the ports are only those the page itself prints.
REAL = {
    ("gsm7252ps", "http"): ("gsm7252ps_http_configuration.html", True, None),
    ("gsm7252ps", "https"): ("gsm7252ps_https_configuration.html", True, 443),
    ("gsm7252ps", "ssh"): ("gsm7252ps_ssh_configuration.html", True, None),
    # Telnet really is off on 10.1.5.22 -- independently confirmed by TCP 23
    # being refused there, while it is open on the m4300.
    ("gsm7252ps", "telnet"): ("gsm7252ps_telnet.html", False, None),
    ("m4300-24x", "http"): ("m4300_24x_http_configuration.html", True, 80),
    ("m4300-24x", "https"): ("m4300_24x_https_configuration.html", True, 443),
    ("m4300-24x", "ssh"): ("m4300_24x_ssh_configuration.html", True, 22),
    # The telnet page prints NO port on either switch. `show telnetcon` reports
    # 23 here, the page does not carry it, so None is the honest answer -- never
    # defaulted to 23.
    ("m4300-24x", "telnet"): ("m4300_24x_telnet.html", True, None),
}


@pytest.mark.parametrize(("model", "service"), sorted(REAL))
def test_parses_the_real_service_page(model: str, service: str) -> None:
    fixture, enabled, port = REAL[(model, service)]
    status = parse_service_page((FIXTURES / fixture).read_text(), service)

    assert status.name == service
    assert status.enabled is enabled
    assert status.port == port


def test_the_last_checked_radio_wins() -> None:
    """Both radios of a plain-form group carry a checked attribute.

    Verbatim from m4300-24x httpConfiguration.html, spelled two ways:

        <INPUT ... id="httpAdminDisable" value="Disable" ... checked="checked" ...>
        <INPUT ... id="httpAdminEnable"  value="Enable"  ... CHECKED>

    A browser applies them in order, so Enable is what the page shows -- and
    that must be the reading, since the page was fetched OVER HTTP. A parser
    taking the FIRST match would report HTTP disabled on every such switch.
    """
    html = (FIXTURES / "m4300_24x_http_configuration.html").read_text()
    assert 'checked="checked"' in html  # the Disable radio
    assert "CHECKED>" in html  # the Enable radio, bare + uppercase
    assert parse_service_page(html, "http").enabled is True


def test_a_page_without_the_control_is_refused() -> None:
    """The S3300's httpConfiguration.html has no admin control at all.

    It must raise rather than read as "HTTP disabled": the page not carrying
    the control says nothing about whether the service is running -- and it
    plainly is, since the page came back over it.
    """
    html = (FIXTURES / "gsm7228ps_http_configuration.html").read_text()
    with pytest.raises(HttpUnexpectedPageError, match="no admin-state control"):
        parse_service_page(html, "http")


def _reader(mock: VirtualSwitch, key: str) -> HttpReader:
    model = get_model(key)
    return HttpReader(
        build_sync_http_client(f"{mock.host}:{mock.http_port}", "password", model),
        model,
    )


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        (
            "gsm7252ps",
            [
                ("http", True, None),
                ("https", True, 443),
                ("ssh", True, None),
                ("telnet", False, None),
            ],
        ),
        (
            "m4300-24x",
            [
                ("http", True, 80),
                ("https", True, 443),
                ("ssh", True, 22),
                ("telnet", True, None),
            ],
        ),
    ],
)
def test_fake_serves_all_four_pages(
    key: str, expected: list[tuple[str, bool, int | None]]
) -> None:
    """The fake reproduces the SHAPE SPLIT too: the m4300 rows only pass if its
    http/https pages are served as plain named forms, since a parser reading
    them as XUI would find no admin coordinate and raise."""
    with VirtualSwitch(model=key) as mock:
        services = _reader(mock, key).get_services()

    assert [(s.name, s.enabled, s.port) for s in services] == expected


def test_a_model_missing_any_page_refuses_the_whole_op() -> None:
    """gsm7228ps: https and telnet parse, http has no control, ssh 404s.

    All-or-nothing -- returning the two that work would read as "this switch
    has no SSH", a confident wrong answer.
    """
    with (
        VirtualSwitch(model="gsm7228ps") as mock,
        pytest.raises(UnsupportedCapabilityError, match="management-service state"),
    ):
        _reader(mock, "gsm7228ps").get_services()
