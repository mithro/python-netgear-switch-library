# tests/test_http_users.py
"""HTTP ``get_users`` against the REAL captured pages, and against the fake.

``userManagement.html`` was fetched live on 2026-08-03 from gsm7252ps
(10.1.5.22) and m4300-24x (10.1.5.13) and committed under
``tests/fixtures/http/``. Both list the same two accounts.

The load-bearing fact these tests pin is that the ACCESS-MODE WORDING is
per-face, not per-switch. Cross-checked live, each backend driven directly:

    switch      HTTP userManagement   CLI `show users`
    gsm7252ps   Super User            Read/Write
    m4300-24x   Super User            Privilege-15

Same accounts, same order, same ``privileged`` verdict -- different words. That
is why ``SwitchUser.access_mode`` keeps the raw text and only ``privileged``
normalises.
"""

from __future__ import annotations

import pathlib

import pytest

from netgear_switch._dispatch import build_sync_http_client
from netgear_switch.errors import HttpUnexpectedPageError, UnsupportedCapabilityError
from netgear_switch.http_read import HttpReader
from netgear_switch.protocols.http.parse import parse_xui_users
from netgear_switch.registry import get_model
from netgear_switch.virtual.server import VirtualSwitch

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "http"

CAPTURES = {
    "gsm7252ps": "gsm7252ps_user_management.html",
    "m4300-24x": "m4300_24x_user_management.html",
}


@pytest.mark.parametrize("key", sorted(CAPTURES))
def test_parses_the_real_user_management_page(key: str) -> None:
    users = parse_xui_users((FIXTURES / CAPTURES[key]).read_text())

    assert [u.name for u in users] == ["admin", "guest"]
    # This PAGE's wording, on both switches -- not either CLI's.
    assert [u.access_mode for u in users] == ["Super User", "Read Only"]
    assert [u.privileged for u in users] == [True, False]


def test_the_snmpv3_page_is_not_mistaken_for_login_accounts() -> None:
    """``userConfiguration.html`` sounds like the accounts page and is not.

    On every managed switch it is the SNMPv3 user page. It must not yield
    users: reporting SNMPv3 credentials as login accounts would be a confident
    wrong answer, which is worse than refusing.
    """
    snmpv3_page = (FIXTURES / "gsm7252ps_user_configuration.html").read_text()
    with pytest.raises(HttpUnexpectedPageError, match="no user rows"):
        parse_xui_users(snmpv3_page)


def test_a_page_with_no_rows_is_refused() -> None:
    """A switch always has at least the account the request authenticated as."""
    with pytest.raises(HttpUnexpectedPageError, match="no user rows"):
        parse_xui_users("<html><body>login required</body></html>")


def _reader(mock: VirtualSwitch, key: str) -> HttpReader:
    model = get_model(key)
    return HttpReader(
        build_sync_http_client(f"{mock.host}:{mock.http_port}", "password", model),
        model,
    )


@pytest.mark.parametrize("key", sorted(CAPTURES))
def test_fake_serves_the_page(key: str) -> None:
    with VirtualSwitch(model=key) as mock:
        users = _reader(mock, key).get_users()

    assert [(u.name, u.access_mode, u.privileged) for u in users] == [
        ("admin", "Super User", True),
        ("guest", "Read Only", False),
    ]


def test_a_model_whose_switch_404s_the_page_refuses_by_name() -> None:
    """gsm7228ps really does answer 404 for /userManagement.html (measured
    2026-08-03), so its spec has no path and the reader must say so rather than
    return an empty account list."""
    with (
        VirtualSwitch(model="gsm7228ps") as mock,
        pytest.raises(UnsupportedCapabilityError, match="local user accounts"),
    ):
        _reader(mock, "gsm7228ps").get_users()
