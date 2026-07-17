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
from .faces.snmp import VirtualSnmpFace
from .seed import seed_gsm7252ps
from .state import VirtualSwitchState

# Model key -> hand-authored seed builder. Models without a seed here get a
# blank (but valid) VirtualSwitchState — every VirtualSwitchState field has a
# default, so construction never fails even for a model no one has seeded yet.
_SEEDS = {"gsm7252ps": seed_gsm7252ps}


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
        self.port: int = 0
        self._snmp_face: VirtualSnmpFace | None = None

    def start(self) -> None:
        """Bind this model's supported protocol faces to ``self.state``."""
        if Backend.SNMP not in self._model_info.backends:
            raise UnsupportedCapabilityError(
                f"model {self.model!r} has no SNMP backend in this slice"
            )
        view = StateMibView(self.state)
        face = VirtualSnmpFace(view, community=self.community, host=self.host)
        self.port = face.start()
        self._snmp_face = face

    def stop(self) -> None:
        """Stop every bound face.

        Safe to call even if ``start()`` failed or was never called.
        """
        if self._snmp_face is not None:
            self._snmp_face.stop()
            self._snmp_face = None
        self.port = 0

    def __enter__(self) -> VirtualSwitch:
        self.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.stop()
