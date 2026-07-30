"""Python Netgear Switch Interface Library.

Query and control Netgear switches over SNMP, NSDP and the HTTP web UI
behind one model-driven API.
"""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

from .aio_api import AsyncSwitch, async_detect_model
from .config import (
    SwitchConfig,
    ensure_secure_file,
    load_inventory,
    resolve_secret,
)
from .errors import (
    CliCommandError,
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
    DetectedModel,
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
from .protocols.nsdp.types import (
    LinkSpeed as NsdpLinkSpeed,
)
from .protocols.nsdp.types import (
    NsdpDevice,
    NsdpIgmpSnooping,
    NsdpPortMirroring,
    NsdpPortPvid,
    NsdpPortStatistics,
    NsdpPortStatus,
    NsdpVlanMembership,
)
from .protocols.nsdp.types import (
    VLANEngine as NsdpVlanEngine,
)
from .registry import MODELS, Backend, SwitchClass, SwitchModel, get_model
from .sync_api import SyncSwitch, detect_model

try:
    # Normal case: the package is installed (editable or wheel) and its
    # dist-info carries the version hatch-vcs derived from git at build time.
    __version__: str = _pkg_version("python-netgear-switch-library")
except PackageNotFoundError:  # pragma: no cover - only hit outside an installed env
    # Fallback for running with no install metadata available at all (e.g. a
    # bare source checkout added straight to sys.path without an install).
    # Deliberately does NOT import the hatch-vcs-generated `_version.py`: that
    # file is gitignored and absent on a fresh checkout, and importing it here
    # would make `mypy --strict` fail in that state (import-not-found) while
    # a `# type: ignore` on the import would itself be flagged unused
    # (no-redef) once the file exists after a build. Every installed/editable
    # environment (dev, CI, wheel) already resolves the metadata version
    # above, so this branch is unreachable there.
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
    "CliCommandError",
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
    "DetectedModel",
    # NSDP full-device types (SyncSwitch.nsdp_device()/AsyncSwitch.nsdp_device())
    "NsdpDevice",
    "NsdpPortStatus",
    "NsdpPortStatistics",
    "NsdpVlanMembership",
    "NsdpPortPvid",
    "NsdpPortMirroring",
    "NsdpIgmpSnooping",
    "NsdpLinkSpeed",
    "NsdpVlanEngine",
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
    # model detection (Task 2)
    "detect_model",
    "async_detect_model",
]
