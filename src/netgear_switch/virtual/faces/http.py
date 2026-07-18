"""A real ``http.server`` web-UI face serving a ``VirtualSwitchState``.

Binds a ``ThreadingHTTPServer`` to an ephemeral TCP port on ``127.0.0.1`` and
serves the login CGI + read/write CGI pages from device state via
``virtual.web``. Both httpx transport clients (sync + async) are exercised
end-to-end against it with no hardware.

A real switch never fabricates a 200 for a capability it doesn't have, so
this face 404s any request whose path is not one of this model's *populated*
``HttpModelSpec`` fields, before ever calling into ``virtual.web`` — that
module's ``render_page`` has a deliberately permissive catch-all (see its
docstring) that is only safe to reach for a path this spec actually
advertises.

Teardown is deterministic: ``stop()`` calls ``shutdown()`` (unblocks
``serve_forever``), joins the server thread, then ``server_close()`` closes the
listening socket — so nothing leaks under ``-W error::ResourceWarning``.
"""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING
from urllib.parse import parse_qs

from ...protocols.http.crypt import merge_hash_md5
from ...protocols.http.endpoints import LoginScheme
from .. import web

if TYPE_CHECKING:
    from ...protocols.http.endpoints import HttpModelSpec
    from ..state import VirtualSwitchState

# Every path-shaped field an HttpModelSpec may populate, other than
# login_path (handled separately as the login handshake). A model that
# leaves one of these None does not serve that endpoint at all.
_PATH_FIELDS = (
    "dashboard_path",
    "stats_path",
    "poe_config_path",
    "poe_status_path",
    "vlan_config_path",
    "vlan_membership_path",
    "pvid_path",
    "reboot_path",
    "logout_path",
)


def _known_paths(spec: HttpModelSpec) -> set[str]:
    """The set of paths ``spec`` actually serves (populated fields only)."""
    return {
        value
        for name in _PATH_FIELDS
        if (value := getattr(spec, name)) is not None
    }


class VirtualHttpFace:
    """A ``ThreadingHTTPServer`` web-UI face serving a ``VirtualSwitchState``."""

    def __init__(
        self,
        state: VirtualSwitchState,
        spec: HttpModelSpec,
        *,
        host: str = "127.0.0.1",
        password: str = "password",
        rand: str = "1234",
    ) -> None:
        self.state = state
        self.spec = spec
        self.host = host
        self.password = password
        self.rand = rand
        self._known_paths = _known_paths(spec)
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._cookie = f"{spec.cookie_name}=virtualsid"

    def start(self) -> int:
        face = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args: object) -> None:  # silence stderr
                return

            def _body(self) -> dict[str, str]:
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length).decode() if length else ""
                return {k: v[0] for k, v in parse_qs(raw).items()}

            def _send(
                self, text: str, status: int = 200, *, cookie: bool = False
            ) -> None:
                data = text.encode()
                self.send_response(status)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(data)))
                if cookie:
                    self.send_header("Set-Cookie", f"{face._cookie}; path=/")
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self) -> None:
                path = self.path.split("?", 1)[0]
                if path == face.spec.login_path:
                    self._send(web.render_login(face.rand))
                    return
                if path not in face._known_paths:
                    self._send("<html><body>Not Found</body></html>", 404)
                    return
                self._send(web.render_page(face.state, face.spec, path, {}))

            def do_POST(self) -> None:
                path = self.path.split("?", 1)[0]
                form = self._body()
                if path == face.spec.login_path:
                    ok = face._login_response(form) == "OK"
                    self._send("OK" if ok else "Login failed", cookie=ok)
                    return
                if path not in face._known_paths:
                    self._send("<html><body>Not Found</body></html>", 404)
                    return
                web.apply_form(face.state, face.spec, path, form)
                self._send(web.render_page(face.state, face.spec, path, form))

        server = ThreadingHTTPServer((self.host, 0), Handler)
        self._server = server
        self._thread = threading.Thread(
            target=server.serve_forever, name="virtual-http-face", daemon=True
        )
        self._thread.start()
        return int(server.server_address[1])

    def _login_response(self, form: dict[str, str]) -> str:
        field = self.spec.password_field
        supplied = form.get(field, "")
        if self.spec.scheme is LoginScheme.CHEETAH_FORM:
            ok = supplied == self.password
        else:
            ok = supplied == merge_hash_md5(self.password, self.rand)
        return "OK" if ok else "Login failed"

    def stop(self) -> None:
        """Stop the serve thread and close the listening socket deterministically."""
        if self._server is not None:
            self._server.shutdown()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        if self._server is not None:
            self._server.server_close()
            self._server = None
