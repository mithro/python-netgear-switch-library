"""Python Netgear Switch Interface Library.

Query and control Netgear switches over SNMP, NSDP and the HTTP web UI
behind one model-driven API.
"""

from .aio_api import AsyncSwitch
from .config import (
    SwitchConfig,
    ensure_secure_file,
    load_inventory,
    resolve_secret,
)
from .errors import (
    ConfigError,
    CredentialError,
    HttpAuthError,
    HttpError,
    HttpUnexpectedPageError,
    NetgearSwitchError,
    ProtectedPortError,
    UnknownModelError,
    UnsupportedCapabilityError,
    WriteVerificationError,
)
from .models import (
    IpMode,
    LLDPNeighbor,
    MacEntry,
    MgmtIpConfig,
    PoEDetect,
    PoEStatus,
    PortStats,
    PortStatus,
    Sensor,
    SwitchData,
    VLANInfo,
    VlanMode,
)
from .registry import MODELS, Backend, SwitchClass, SwitchModel, get_model
from .sync_api import SyncSwitch

try:
    # Normal case: the package is installed (editable or wheel) and its
    # dist-info carries the version hatch-vcs derived from git at build time.
    from importlib.metadata import PackageNotFoundError
    from importlib.metadata import version as _pkg_version

    __version__: str = _pkg_version("python-netgear-switch-library")
except PackageNotFoundError:  # pragma: no cover - only hit outside an installed env
    # Fallback for running straight out of a source checkout with no install
    # metadata available: read the file hatch-vcs generates at build time.
    try:
        from ._version import __version__
    except ImportError:
        __version__ = "0.0.dev0+unknown"

__all__ = [  # noqa: RUF022 -- grouped by source module below, not alphabetical
    "__version__",
    # errors
    "NetgearSwitchError",
    "ConfigError",
    "CredentialError",
    "UnknownModelError",
    "UnsupportedCapabilityError",
    "WriteVerificationError",
    "ProtectedPortError",
    "HttpError",
    "HttpAuthError",
    "HttpUnexpectedPageError",
    # models
    "PortStatus",
    "PoEStatus",
    "PoEDetect",
    "VLANInfo",
    "VlanMode",
    "IpMode",
    "LLDPNeighbor",
    "MacEntry",
    "PortStats",
    "MgmtIpConfig",
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
    # facades
    "SyncSwitch",
    "AsyncSwitch",
]
