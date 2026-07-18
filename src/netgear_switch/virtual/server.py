# src/netgear_switch/virtual/server.py
"""``VirtualSwitch``: a mock switch server binding protocol faces to a state.

Constructed from a model key, it seeds (or defaults) a ``VirtualSwitchState``
and, on ``start()``, binds whichever protocol faces the model's registry
entry supports (Task 15: SNMP for managed switches; NSDP/HTTP for Plus
switches come in later slices and are not bound here).
"""
from __future__ import annotations

from ..errors import UnsupportedCapabilityError
from ..registry import Backend, get_model
from .faces.mibview import StateMibView
from .faces.nsdp import VirtualNsdpFace
from .faces.snmp import VirtualSnmpFace
from .seed import seed_gs110emx, seed_gsm7252ps
from .state import VirtualSwitchState

# Model key -> hand-authored seed builder. Models without a seed here get a
# blank (but valid) VirtualSwitchState — every VirtualSwitchState field has a
# default, so construction never fails even for a model no one has seeded yet.
_SEEDS = {"gsm7252ps": seed_gsm7252ps, "gs110emx": seed_gs110emx}


def _build_state(model: str) -> VirtualSwitchState:
    seed = _SEEDS.get(model)
    return seed() if seed is not None else VirtualSwitchState(model_key=model)


class VirtualSwitch:
    """A virtual switch server: a seeded state plus its bound protocol faces."""

    host: str = "127.0.0.1"

    def __init__(self, model: str, community: str = "public") -> None:
        self._model_info = get_model(model)  # raises UnknownModelError early
        self.model = model
        self.community = community
        self.state: VirtualSwitchState = _build_state(model)
        self.nsdp_password = self.state.nsdp_password
        self.port: int = 0
        self._snmp_face: VirtualSnmpFace | None = None
        self._nsdp_face: VirtualNsdpFace | None = None

    def start(self) -> None:
        """Bind this model's supported protocol face(s) to ``self.state``."""
        if Backend.SNMP in self._model_info.backends:
            view = StateMibView(self.state)
            face = VirtualSnmpFace(view, community=self.community, host=self.host)
            self.port = face.start()
            self._snmp_face = face
        elif Backend.NSDP in self._model_info.backends:
            nsdp_face = VirtualNsdpFace(self.state, host=self.host)
            self.port = nsdp_face.start()
            self._nsdp_face = nsdp_face
        else:
            raise UnsupportedCapabilityError(
                f"model {self.model!r} has no SNMP or NSDP backend to bind"
            )

    def stop(self) -> None:
        """Stop every bound face. Safe to call if start() failed or never ran."""
        if self._snmp_face is not None:
            self._snmp_face.stop()
            self._snmp_face = None
        if self._nsdp_face is not None:
            self._nsdp_face.stop()
            self._nsdp_face = None
        self.port = 0

    def __enter__(self) -> VirtualSwitch:
        self.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.stop()
