"""Python Netgear Switch Interface Library.

Query and control Netgear switches over SNMP, NSDP and the HTTP web UI
behind one model-driven API.
"""

from .config import (
    SwitchConfig,
    ensure_secure_file,
    load_inventory,
    resolve_secret,
)
from .errors import (
    ConfigError,
    CredentialError,
    NetgearSwitchError,
    UnknownModelError,
    UnsupportedCapabilityError,
    WriteVerificationError,
)
from .models import (
    LLDPNeighbor,
    MacEntry,
    PoEDetect,
    PoEStatus,
    PortStatus,
    Sensor,
    SwitchData,
    VLANInfo,
    VlanMode,
)
from .registry import MODELS, Backend, SwitchClass, SwitchModel, get_model

__version__: str = "0.1.0"

__all__ = [  # noqa: RUF022 -- grouped by source module below, not alphabetical
    "__version__",
    # errors
    "NetgearSwitchError",
    "ConfigError",
    "CredentialError",
    "UnknownModelError",
    "UnsupportedCapabilityError",
    "WriteVerificationError",
    # models
    "PortStatus",
    "PoEStatus",
    "PoEDetect",
    "VLANInfo",
    "VlanMode",
    "LLDPNeighbor",
    "MacEntry",
    "Sensor",
    "SwitchData",
    # registry
    "Backend",
    "SwitchClass",
    "SwitchModel",
    "MODELS",
    "get_model",
    # config
    "SwitchConfig",
    "resolve_secret",
    "load_inventory",
    "ensure_secure_file",
]
