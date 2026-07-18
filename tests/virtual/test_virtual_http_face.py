from __future__ import annotations

import httpx
import pytest

from netgear_switch.models import PoEDetect
from netgear_switch.protocols.http.endpoints import http_spec
from netgear_switch.registry import get_model
from netgear_switch.transport.http.client import HttpClient
from netgear_switch.virtual.faces.http import VirtualHttpFace
from netgear_switch.virtual.seed import seed_gs305ep
from netgear_switch.virtual.server import VirtualSwitch

# Fail this module's tests if they leak a socket/thread ResourceWarning, and
# also (belt-and-suspenders) if pytest re-emits a leaked-resource finalizer
# warning as PytestUnraisableExceptionWarning -- see
# test_stop_closes_listening_socket_deterministically below for why the
# ResourceWarning filter alone is not a reliable leak detector for this face.
pytestmark = pytest.mark.filterwarnings(
    "error::ResourceWarning", "error::pytest.PytestUnraisableExceptionWarning"
)

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


def test_stop_closes_listening_socket_deterministically(face) -> None:
    """``stop()`` must close the listening socket synchronously, not leave it
    for GC to finalize.

    A reviewer proved that ``-W error::ResourceWarning`` does NOT reliably
    catch this leak: CPython reports an unclosed socket via a GC finalizer,
    which pytest re-emits as ``PytestUnraisableExceptionWarning`` (a
    ``UserWarning`` subclass, not a ``ResourceWarning``) -- the
    ``error::ResourceWarning`` filter never matches it, so a run with
    ``server_close()`` deleted from ``stop()`` still passed. This assertion
    is deterministic instead: it inspects the real OS-level file descriptor
    on the server's listening socket and fails immediately if it is still
    open after ``stop()`` returns, regardless of whether/when GC runs or
    which warning category (if any) a finalizer happens to raise.
    """
    f, _port, _state = face
    server = f._server
    assert server is not None
    assert server.socket.fileno() != -1  # sanity: open while running
    f.stop()
    assert server.socket.fileno() == -1


def test_gs110emx_has_its_own_bindable_http_face() -> None:
    """gs110emx's registry entry is ``{NSDP, HTTP}`` (see registry.py), not
    NSDP-only, and its HTTP face has never been exercised by a test of its
    own -- only gs305ep's. Prove the gs110emx face binds, serves its login
    page, gates its known paths, and (since its login scheme resolves
    through the same rand/merge-hash code path as MERGE_HASH_CGI -- only
    CHEETAH_FORM differs -- see transport/http/client.py::_login_body and
    VirtualHttpFace._login_response) can complete a full HttpClient login."""
    spec = http_spec(get_model("gs110emx"))
    sw = VirtualSwitch(model="gs110emx")
    sw.start()
    try:
        assert sw.http_port != 0

        resp = httpx.get(f"http://127.0.0.1:{sw.http_port}{spec.login_path}")
        assert resp.status_code == 200

        # gs110emx (EMx, no PoE) leaves poe_config_path None -- gs305ep's PoE
        # CGI path is not in gs110emx's known-path set, so it must 404.
        assert spec.poe_config_path is None
        resp = httpx.get(f"http://127.0.0.1:{sw.http_port}/PoEPortConfig.cgi")
        assert resp.status_code == 404

        client = HttpClient(f"127.0.0.1:{sw.http_port}", "password", spec)
        try:
            client.login()
            page = client.get_page(spec.dashboard_path)
            assert page
        finally:
            client.close()
    finally:
        sw.stop()
