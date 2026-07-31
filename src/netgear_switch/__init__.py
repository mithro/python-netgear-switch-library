"""Python Netgear Switch Interface Library.

Query and control Netgear switches over SNMP, NSDP, the HTTP web UI and the CLI
behind one model-driven API.

Design principles (non-negotiable -- see ``CLAUDE.md`` at the repository root for
the rationale and the real-world violation behind each one):

1. **Fail fast and loud.** An operation that cannot be performed as asked raises,
   with the detail needed to debug it. Nothing is papered over, and a request for
   one backend is NEVER silently served by another -- switching protocol
   mid-operation is forbidden.
2. **Backends have parity.** Every backend a model supports offers the same
   functionality, so the CALLER can choose one (e.g. when SNMP writes are locked
   down). A missing operation is a missing implementation, not a device
   limitation, unless captured device output proves otherwise.
3. **Models have parity.** A feature is done when it works on every registered
   model, verified per model. Firmware differs between SKUs of the same family --
   never extrapolate from one to another.
4. **A failure is a bug here first.** Not flaky hardware, not a timeout. Check
   credentials, prerequisite settings, value types and operation ordering before
   even considering a device limitation.
5. **The virtual switch must behave like the real hardware,** including its
   refusals, quirks and ordering requirements. Where the fake differs from a real
   device, the fake is what gets fixed.
"""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

from .aio_api import AsyncSwitch, async_detect_model
from .capabilities import (
    OPERATIONS,
    Capability,
    Operation,
    OperationKind,
    Support,
    backends_for,
    matrix,
    support,
)
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
    # capabilities (which model can do what, over which backend)
    "Support",
    "Operation",
    "OperationKind",
    "Capability",
    "OPERATIONS",
    "support",
    "matrix",
    "backends_for",
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
