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
    """A virtual switch server: a seeded state plus its bound protocol faces."""

    host: str = "127.0.0.1"

    def __init__(
        self, model: str, community: str = "public", http_password: str = "password"
    ) -> None:
        self._model_info = get_model(model)  # raises UnknownModelError early
        self.model = model
        self.community = community
        self.http_password = http_password
        self.state: VirtualSwitchState = _build_state(model)
        self.nsdp_password = self.state.nsdp_password
        self.port: int = 0
        self.http_port: int = 0
        self._snmp_face: VirtualSnmpFace | None = None
        self._nsdp_face: VirtualNsdpFace | None = None
        self._http_face: VirtualHttpFace | None = None

    def start(self) -> None:
        """Bind every protocol face this model's registry entry supports."""
        if Backend.SNMP in self._model_info.backends:
            view = StateMibView(self.state)
            face = VirtualSnmpFace(view, community=self.community, host=self.host)
            self.port = face.start()
            self._snmp_face = face
        if Backend.NSDP in self._model_info.backends:
            nsdp_face = VirtualNsdpFace(self.state, host=self.host)
            self.port = nsdp_face.start()
            self._nsdp_face = nsdp_face
        if Backend.HTTP in self._model_info.backends:
            http_face = VirtualHttpFace(
                self.state,
                http_spec(self._model_info),
                host=self.host,
                password=self.http_password,
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

    def __enter__(self) -> VirtualSwitch:
        self.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.stop()
