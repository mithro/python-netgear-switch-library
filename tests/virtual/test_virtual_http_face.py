from __future__ import annotations

import httpx
import pytest

from netgear_switch.models import PoEDetect
from netgear_switch.protocols.http.endpoints import http_spec
from netgear_switch.registry import get_model
from netgear_switch.transport.http.client import HttpClient
from netgear_switch.virtual.faces.http import VirtualHttpFace
from netgear_switch.virtual.seed import seed_gs305ep

_SPEC = http_spec(get_model("gs305ep"))


@pytest.fixture
def face():
    state = seed_gs305ep()
    f = VirtualHttpFace(state, _SPEC, password="password")
    port = f.start()
    try:
        yield f, port, state
    finally:
        f.stop()


def test_login_read_write_reread(face) -> None:
    _f, port, state = face
    client = HttpClient(f"127.0.0.1:{port}", "password", _SPEC)
    try:
        client.login()
        poe = client.get_page("/getPoePortStatus.cgi")
        from netgear_switch.protocols.http import parse
        assert parse.parse_poe_status(poe)[0].detect is PoEDetect.DELIVERING
        # Turn PoE port 2 off via the CGI, then re-read.
        page = client.get_page("/PoEPortConfig.cgi")
        h = parse.parse_csrf_hash(page)
        client.post_form(
            "/PoEPortConfig.cgi",
            {"ACTION": "Apply", "portID": "1", "ADMIN_MODE": "0", "hash": h},
        )
        assert state.poe[2].admin is False
    finally:
        client.close()


def test_wrong_password_rejected(face) -> None:
    _f, port, _ = face
    from netgear_switch.errors import HttpAuthError

    client = HttpClient(f"127.0.0.1:{port}", "wrong", _SPEC)
    with pytest.raises(HttpAuthError):
        client.login()
    client.close()


def test_unsupported_path_404s(face) -> None:
    """A path this model's spec doesn't advertise must 404, not fabricate a
    generic 200 OK page (the gs110emx dashboard path, not one of gs305ep's
    populated spec fields)."""
    _f, port, _ = face
    resp = httpx.get(f"http://127.0.0.1:{port}/iss/specific/sysInfo.html")
    assert resp.status_code == 404
