# src/netgear_switch/virtual/server.py
"""``VirtualSwitch``: a mock switch server binding protocol faces to a state.

Constructed from a model key, it seeds (or defaults) a ``VirtualSwitchState``
and, on ``start()``, binds whichever protocol faces the model's registry
entry supports: SNMP for managed switches, NSDP and/or HTTP for Plus
switches. Each supported backend is bound in its own independent ``if``
block, so a ``{NSDP, HTTP}`` model binds both an NSDP face (``self.port``)
and an HTTP face (``self.http_port``) concurrently.
"""

from __future__ import annotations

import contextlib
import threading
from typing import TYPE_CHECKING

from ..errors import UnsupportedCapabilityError
from ..protocols.http.endpoints import http_spec
from ..registry import Backend, get_model
from .faces.cli import VirtualCliFace
from .faces.http import VirtualHttpFace
from .faces.mibview import StateMibView
from .faces.nsdp import VirtualNsdpFace
from .faces.snmp import VirtualSnmpFace
from .seed import (
    seed_gs105pe,
    seed_gs110emx,
    seed_gs305ep,
    seed_gs728tpp,
    seed_gsm7228ps,
    seed_gsm7252ps,
    seed_m4300_16x,
    seed_m4300_24x,
)
from .state import VirtualSwitchState

if TYPE_CHECKING:
    from collections.abc import Sequence
    from typing import TextIO

# Model key -> hand-authored seed builder. Models without a seed here get a
# blank (but valid) VirtualSwitchState — every VirtualSwitchState field has a
# default, so construction never fails even for a model no one has seeded yet.
_SEEDS = {
    "gsm7252ps": seed_gsm7252ps,
    "gsm7228ps": seed_gsm7228ps,
    "gs110emx": seed_gs110emx,
    "gs305ep": seed_gs305ep,
    "gs105pe": seed_gs105pe,
    "m4300-24x": seed_m4300_24x,
    "m4300-16x": seed_m4300_16x,
    "gs728tpp": seed_gs728tpp,
}


def _build_state(model: str) -> VirtualSwitchState:
    seed = _SEEDS.get(model)
    return seed() if seed is not None else VirtualSwitchState(model_key=model)


class VirtualSwitch:
    """A virtual switch server: a seeded state plus its bound protocol faces.

    ``host`` defaults to loopback (``127.0.0.1``); pass another address (e.g.
    ``0.0.0.0`` to expose the mock to other hosts) to bind elsewhere. The
    ``port``/``http_port`` arguments pin the UDP (SNMP *or* NSDP) and HTTP
    listen ports respectively; the default of ``0`` asks the OS for an
    ephemeral port, whose actual value is readable off ``self.port`` /
    ``self.http_port`` after ``start()``.
    """

    def __init__(
        self,
        model: str,
        community: str = "public",
        http_password: str = "password",
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        http_port: int = 0,
    ) -> None:
        self._model_info = get_model(model)  # raises UnknownModelError early
        self.model = model
        self.community = community
        self.http_password = http_password
        self.host = host
        self.state: VirtualSwitchState = _build_state(model)
        self.nsdp_password = self.state.nsdp_password
        # Requested ports (0 = ephemeral); rewritten to the actually-bound
        # ports by ``start()``.
        self.port: int = port
        self.http_port: int = http_port
        self._snmp_face: VirtualSnmpFace | None = None
        self._nsdp_face: VirtualNsdpFace | None = None
        self._http_face: VirtualHttpFace | None = None

    def start(self) -> None:
        """Bind every protocol face this model's registry entry supports."""
        if Backend.SNMP in self._model_info.backends:
            view = StateMibView(self.state)
            face = VirtualSnmpFace(
                view, community=self.community, host=self.host, port=self.port
            )
            self.port = face.start()
            self._snmp_face = face
        if Backend.NSDP in self._model_info.backends:
            nsdp_face = VirtualNsdpFace(self.state, host=self.host, port=self.port)
            self.port = nsdp_face.start()
            self._nsdp_face = nsdp_face
        if Backend.HTTP in self._model_info.backends:
            http_face = VirtualHttpFace(
                self.state,
                http_spec(self._model_info),
                host=self.host,
                password=self.http_password,
                port=self.http_port,
            )
            self.http_port = http_face.start()
            self._http_face = http_face
        if (
            self._snmp_face is None
            and self._nsdp_face is None
            and self._http_face is None
        ):
            raise UnsupportedCapabilityError(
                f"model {self.model!r} has no bindable protocol face"
            )

    def cli_session(self) -> VirtualCliFace:
        """Return an in-process mock FASTPATH CLI session over this switch's state.

        Unlike the SNMP/NSDP/HTTP faces (real sockets bound in ``start()``), the
        CLI face is an in-process ``CliSession`` needing no socket -- see
        ``virtual.faces.cli``. Raises ``UnsupportedCapabilityError`` (via
        ``cli_spec``) for a model with no CLI backend.
        """
        from ..protocols.cli.commands import cli_spec

        return VirtualCliFace(self.state, cli_spec(self._model_info))

    def stop(self) -> None:
        """Stop every bound face. Safe to call if start() failed or never ran."""
        if self._snmp_face is not None:
            self._snmp_face.stop()
            self._snmp_face = None
        if self._nsdp_face is not None:
            self._nsdp_face.stop()
            self._nsdp_face = None
        if self._http_face is not None:
            self._http_face.stop()
            self._http_face = None
        self.port = 0
        self.http_port = 0

    @property
    def bound_endpoints(self) -> list[tuple[str, str, int]]:
        """The faces this switch has actually bound, as ``(protocol, l4, port)``.

        ``protocol`` is the upper-case backend name (``SNMP``/``NSDP``/``HTTP``),
        ``l4`` the transport (``udp``/``tcp``), and ``port`` the actually-bound
        port. Empty until ``start()`` has run (and again after ``stop()``).
        """
        out: list[tuple[str, str, int]] = []
        if self._snmp_face is not None:
            out.append(("SNMP", "udp", self.port))
        if self._nsdp_face is not None:
            out.append(("NSDP", "udp", self.port))
        if self._http_face is not None:
            out.append(("HTTP", "tcp", self.http_port))
        return out

    def __enter__(self) -> VirtualSwitch:
        self.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.stop()


def serve_forever(
    switches: Sequence[VirtualSwitch],
    *,
    out: TextIO,
    stop: threading.Event | None = None,
    ready: threading.Event | None = None,
) -> int:
    """Start ``switches``, print where each is reachable, and block until ``stop``.

    Each switch is ``start()``ed independently; a switch that cannot bind any
    face (``UnsupportedCapabilityError``) or otherwise fails to start is
    reported on ``out`` and skipped, so one bad model never takes the rest of
    the fleet down. For every switch that does come up, its model, host, bound
    port(s) (with transport), SNMP community and HTTP password are printed so an
    external tool knows exactly where and how to connect.

    Blocks on ``stop.wait()`` (a fresh ``Event`` is created if none is passed —
    in that case only a ``KeyboardInterrupt`` unblocks it) until signalled, then
    ``stop()``s every switch it started, in reverse order, even on exception.
    Returns the number of switches successfully served (0 means nothing bound,
    and the function returns immediately without blocking).

    ``ready``, if given, is set once every switch has been started and its
    endpoints printed — a test hook so a caller can wait for "fully up" before
    connecting, without racing the startup prints.
    """
    if stop is None:
        stop = threading.Event()
    started: list[VirtualSwitch] = []
    try:
        for sw in switches:
            try:
                sw.start()
            except Exception as exc:  # one bad model must not sink the fleet
                print(f"error: cannot serve {sw.model!r}: {exc}", file=out)
                continue
            started.append(sw)
            _print_switch(sw, out)
        if ready is not None:
            ready.set()
        if not started:
            print("error: no switches could be served", file=out)
            return 0
        print(
            f"serving {len(started)} mock switch(es); press Ctrl-C to stop",
            file=out,
            flush=True,
        )
        # A bare Ctrl-C with no signal handler installed surfaces here.
        with contextlib.suppress(KeyboardInterrupt):
            stop.wait()
    finally:
        for sw in reversed(started):
            sw.stop()
    return len(started)


def _print_switch(sw: VirtualSwitch, out: TextIO) -> None:
    """Print one served switch's model, host, bound endpoints, and credentials."""
    print(f"[{sw.model}] host={sw.host}", file=out)
    for protocol, l4, port in sw.bound_endpoints:
        print(f"    {protocol:<4} {l4}/{port}", file=out)
    print(
        f"    community={sw.community!r} http_password={sw.http_password!r}",
        file=out,
        flush=True,
    )
