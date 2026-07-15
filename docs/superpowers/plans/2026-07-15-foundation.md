# Foundation: Package, Device Model, Registry & Config — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the `python-netgear-switch-library` package with its shared, I/O-free foundation: the public device-data model, the switch-model registry, the exception hierarchy, and the TOML inventory + credential-resolution layer.

**Architecture:** Pure-Python, zero-I/O foundation layer that every later plan builds on. Frozen dataclasses are the public return types shared by the (future) sync and async APIs; the registry is a declarative table of switch models driving backend selection; config loads a TOML inventory and resolves credentials from literal / env / command / prompt sources. No network code, no protocol backends — those arrive in later plans.

**Tech Stack:** Python ≥3.11, `uv` + `hatchling`, `pytest`, `ruff`, stdlib `tomllib`. src-layout package.

## Global Constraints

- Python ≥ 3.11 (uses `tomllib`, PEP 604 unions, `frozen` dataclasses).
- Distribution name: `python-netgear-switch-library`. Import name: `netgear_switch`. CLI: `ngsw` (no CLI in this plan).
- License: **Apache 2.0**.
- Package manager: **`uv`** — every Python invocation is `uv run …` / `uv pip …`, never bare `python`/`pip`.
- src-layout: code under `src/netgear_switch/`, tests under `tests/`.
- All public data types are **frozen** dataclasses (`@dataclass(frozen=True)`), hashable and comparable — the future cross-check compares them with `==`.
- Never `git add -A` in this repo: the working tree contains overlay-mount character-device dotfiles (`.bashrc`, `.gitconfig`, `.mcp.json`, …) that must never be staged. Always `git add` explicit paths.
- Small, focused files — one responsibility each.

---

## File Structure

- `pyproject.toml` — distribution metadata, deps, extras, tool config (ruff, pytest).
- `LICENSE` — Apache 2.0 text.
- `README.md` — project intro + install/dev instructions.
- `.gitignore` — Python + the overlay char-device dotfiles.
- `src/netgear_switch/__init__.py` — version + public re-exports.
- `src/netgear_switch/errors.py` — exception hierarchy.
- `src/netgear_switch/models.py` — frozen dataclasses (public return types) + small enums.
- `src/netgear_switch/registry.py` — `Backend`, `SwitchClass`, `SwitchModel`, the `MODELS` table, `get_model()`.
- `src/netgear_switch/config.py` — secret resolution + `SwitchConfig` + `load_inventory()`.
- `tests/test_errors.py`, `tests/test_models.py`, `tests/test_registry.py`, `tests/test_config.py`.

---

### Task 1: Repository scaffold

**Files:**
- Create: `pyproject.toml`, `LICENSE`, `README.md`, `.gitignore`
- Create: `src/netgear_switch/__init__.py`
- Test: `tests/test_import.py`

**Interfaces:**
- Consumes: nothing.
- Produces: an installable package importable as `netgear_switch`, exposing `__version__: str`.

- [ ] **Step 1: Write the failing test**

`tests/test_import.py`:
```python
def test_package_imports_and_has_version():
    import netgear_switch

    assert isinstance(netgear_switch.__version__, str)
    assert netgear_switch.__version__
```

- [ ] **Step 2: Create `.gitignore`**

```gitignore
# Python
__pycache__/
*.py[cod]
*.egg-info/
.eggs/
build/
dist/
.venv/
venv/

# Tooling caches
.pytest_cache/
.ruff_cache/
.mypy_cache/
.cache/

# Project-local scratch
tmp/

# Overlay-mount character-device dotfiles present in this repo's working tree —
# never track these.
/.bash_profile
/.bashrc
/.gitconfig
/.gitmodules
/.idea
/.mcp.json
/.profile
/.ripgreprc
/.vscode
/.zprofile
/.zshrc
```

- [ ] **Step 3: Create `LICENSE` (Apache 2.0)**

Run: `curl -fsSL https://www.apache.org/licenses/LICENSE-2.0.txt -o LICENSE` (sandbox network is restricted; if it fails, run with the network available or paste the standard Apache-2.0 text). Verify it starts with `Apache License` and is ~11 KB:

Run: `head -1 LICENSE`
Expected: `                                 Apache License`

- [ ] **Step 4: Create `pyproject.toml`**

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "python-netgear-switch-library"
version = "0.1.0"
description = "Python library and CLI to query and control Netgear switches over SNMP, NSDP and HTTP."
readme = "README.md"
requires-python = ">=3.11"
license = "Apache-2.0"
license-files = ["LICENSE"]
authors = [{ name = "Tim Ansell", email = "me@mith.ro" }]
dependencies = []

[project.optional-dependencies]
sync = ["ezsnmp~=1.1"]
async = ["pysnmp>=7.0"]
http = ["httpx>=0.27"]
testing = ["pysnmp>=7.0"]

[project.scripts]
ngsw = "netgear_switch.cli.main:main"

[tool.hatch.build.targets.wheel]
packages = ["src/netgear_switch"]

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-ra"

[tool.ruff]
target-version = "py311"
src = ["src", "tests"]

[tool.ruff.lint]
select = ["E", "F", "I", "UP", "B"]
```

Note: the `ngsw` entry point references `netgear_switch.cli.main:main`, delivered in a later plan. It is declared now so packaging is stable; it is not imported by any test in this plan.

- [ ] **Step 5: Create `src/netgear_switch/__init__.py`**

```python
"""Python Netgear Switch Interface Library.

Query and control Netgear switches over SNMP, NSDP and the HTTP web UI
behind one model-driven API.
"""

__version__ = "0.1.0"
```

- [ ] **Step 6: Create `README.md`**

```markdown
# Python Netgear Switch Interface Library

Query and control all your Netgear switches — SNMP (managed), NSDP and HTTP
web-UI (Plus) — behind one model-driven Python API and the `ngsw` CLI.

Status: **early development.** See `docs/superpowers/specs/` for the design and
`docs/superpowers/plans/` for the implementation plans.

## Development

```sh
uv sync --all-extras
uv run pytest
uv run ruff check
```

## License

Apache-2.0.
```

- [ ] **Step 7: Run the test to verify it passes**

Run: `uv run --extra testing pytest tests/test_import.py -v`
Expected: PASS (1 passed).

- [ ] **Step 8: Verify lint is clean**

Run: `uv run ruff check`
Expected: `All checks passed!`

- [ ] **Step 9: Commit**

```bash
git add pyproject.toml LICENSE README.md .gitignore src/netgear_switch/__init__.py tests/test_import.py
git commit -m "feat: scaffold python-netgear-switch-library package"
```

---

### Task 2: Exception hierarchy

**Files:**
- Create: `src/netgear_switch/errors.py`
- Test: `tests/test_errors.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `NetgearSwitchError(Exception)` — base for all library errors.
  - `ConfigError(NetgearSwitchError)` — invalid inventory/config.
  - `CredentialError(NetgearSwitchError)` — a secret could not be resolved.
  - `UnknownModelError(NetgearSwitchError)` — model key not in the registry.
  - `UnsupportedCapability(NetgearSwitchError)` — operation not available on this model/backend (e.g. MAC table on a Plus switch).
  - `WriteVerificationError(NetgearSwitchError)` — a write did not read back as expected; carries `.before` and `.after`.

- [ ] **Step 1: Write the failing test**

`tests/test_errors.py`:
```python
import pytest

from netgear_switch import errors


def test_all_errors_subclass_base():
    for name in (
        "ConfigError",
        "CredentialError",
        "UnknownModelError",
        "UnsupportedCapability",
        "WriteVerificationError",
    ):
        cls = getattr(errors, name)
        assert issubclass(cls, errors.NetgearSwitchError)


def test_write_verification_error_carries_before_after():
    err = errors.WriteVerificationError("mismatch", before=1, after=2)
    assert err.before == 1
    assert err.after == 2
    assert "mismatch" in str(err)


def test_base_is_catchable():
    with pytest.raises(errors.NetgearSwitchError):
        raise errors.UnsupportedCapability("no MAC table on Plus switches")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_errors.py -v`
Expected: FAIL (ModuleNotFoundError: no module named `netgear_switch.errors`).

- [ ] **Step 3: Write the implementation**

`src/netgear_switch/errors.py`:
```python
"""Exception hierarchy for netgear_switch."""

from __future__ import annotations


class NetgearSwitchError(Exception):
    """Base class for every error raised by this library."""


class ConfigError(NetgearSwitchError):
    """The inventory/config file is malformed or invalid."""


class CredentialError(NetgearSwitchError):
    """A required secret could not be resolved from any source."""


class UnknownModelError(NetgearSwitchError):
    """A switch references a model key that is not in the registry."""


class UnsupportedCapability(NetgearSwitchError):
    """The requested operation is not available on this model/backend."""


class WriteVerificationError(NetgearSwitchError):
    """A write did not read back as expected.

    Carries the observed state before and after the write attempt so callers
    can report exactly what diverged.
    """

    def __init__(self, message: str, *, before: object, after: object) -> None:
        super().__init__(message)
        self.before = before
        self.after = after
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_errors.py -v`
Expected: PASS (3 passed).

- [ ] **Step 5: Commit**

```bash
git add src/netgear_switch/errors.py tests/test_errors.py
git commit -m "feat: add exception hierarchy"
```

---

### Task 3: Device data model

**Files:**
- Create: `src/netgear_switch/models.py`
- Test: `tests/test_models.py`

**Interfaces:**
- Consumes: nothing.
- Produces (all `@dataclass(frozen=True)` unless noted):
  - `class PoEDetect(enum.Enum)` — `DISABLED`, `SEARCHING`, `DELIVERING`, `FAULT`, `UNKNOWN`.
  - `class VlanMode(enum.Enum)` — `UNTAGGED`, `TAGGED`, `EXCLUDED`.
  - `PortStatus(port: int, name: str | None, admin_enabled: bool, link_up: bool, speed_mbps: int | None)`.
  - `PoEStatus(port: int, admin_enabled: bool, detect: PoEDetect, power_mw: int | None)` with property `delivering: bool`.
  - `VLANInfo(vlan_id: int, name: str | None, member_ports: frozenset[int], tagged_ports: frozenset[int], untagged_ports: frozenset[int])`.
  - `LLDPNeighbor(local_port: int, remote_sys_name: str | None, remote_port_desc: str | None, remote_chassis_id: str | None)`.
  - `MacEntry(mac: str, port: int, vlan_id: int | None)`.
  - `Sensor(name: str, kind: str, value: float, unit: str)` — `kind` in `{"temperature", "fan", "power"}`.
  - `SwitchData(model: str, host: str, ports: tuple[PortStatus, ...] = (), poe: tuple[PoEStatus, ...] = (), vlans: tuple[VLANInfo, ...] = (), pvids: Mapping[int, int] = {}, lldp: tuple[LLDPNeighbor, ...] = (), macs: tuple[MacEntry, ...] = (), sensors: tuple[Sensor, ...] = ())` — aggregate snapshot; uses tuples so it stays frozen/hashable.

- [ ] **Step 1: Write the failing test**

`tests/test_models.py`:
```python
from netgear_switch.models import (
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


def test_frozen_and_equatable():
    a = PortStatus(port=1, name="eth1", admin_enabled=True, link_up=True, speed_mbps=1000)
    b = PortStatus(port=1, name="eth1", admin_enabled=True, link_up=True, speed_mbps=1000)
    assert a == b
    assert hash(a) == hash(b)
    import dataclasses
    import pytest

    with pytest.raises(dataclasses.FrozenInstanceError):
        a.port = 2  # type: ignore[misc]


def test_poe_delivering_property():
    on = PoEStatus(port=3, admin_enabled=True, detect=PoEDetect.DELIVERING, power_mw=6400)
    off = PoEStatus(port=3, admin_enabled=True, detect=PoEDetect.SEARCHING, power_mw=0)
    assert on.delivering is True
    assert off.delivering is False


def test_vlan_and_neighbor_and_sensor_and_mac():
    v = VLANInfo(
        vlan_id=10,
        name="int",
        member_ports=frozenset({1, 2}),
        tagged_ports=frozenset({2}),
        untagged_ports=frozenset({1}),
    )
    assert 1 in v.untagged_ports
    n = LLDPNeighbor(local_port=1, remote_sys_name="ap1", remote_port_desc="eth0", remote_chassis_id="aa:bb")
    assert n.remote_sys_name == "ap1"
    s = Sensor(name="fan1", kind="fan", value=3200.0, unit="RPM")
    assert s.kind == "fan"
    m = MacEntry(mac="aa:bb:cc:dd:ee:ff", port=5, vlan_id=10)
    assert m.port == 5
    assert VlanMode.UNTAGGED.value == "untagged"


def test_switchdata_defaults_empty():
    sd = SwitchData(model="m4300-24x", host="10.1.5.19")
    assert sd.ports == ()
    assert sd.pvids == {}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_models.py -v`
Expected: FAIL (ImportError from `netgear_switch.models`).

- [ ] **Step 3: Write the implementation**

`src/netgear_switch/models.py`:
```python
"""Public device-data model: frozen dataclasses returned by both APIs."""

from __future__ import annotations

import enum
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType


class PoEDetect(enum.Enum):
    DISABLED = "disabled"
    SEARCHING = "searching"
    DELIVERING = "delivering"
    FAULT = "fault"
    UNKNOWN = "unknown"


class VlanMode(enum.Enum):
    UNTAGGED = "untagged"
    TAGGED = "tagged"
    EXCLUDED = "excluded"


@dataclass(frozen=True)
class PortStatus:
    port: int
    name: str | None
    admin_enabled: bool
    link_up: bool
    speed_mbps: int | None


@dataclass(frozen=True)
class PoEStatus:
    port: int
    admin_enabled: bool
    detect: PoEDetect
    power_mw: int | None

    @property
    def delivering(self) -> bool:
        return self.detect is PoEDetect.DELIVERING


@dataclass(frozen=True)
class VLANInfo:
    vlan_id: int
    name: str | None
    member_ports: frozenset[int]
    tagged_ports: frozenset[int]
    untagged_ports: frozenset[int]


@dataclass(frozen=True)
class LLDPNeighbor:
    local_port: int
    remote_sys_name: str | None
    remote_port_desc: str | None
    remote_chassis_id: str | None


@dataclass(frozen=True)
class MacEntry:
    mac: str
    port: int
    vlan_id: int | None


@dataclass(frozen=True)
class Sensor:
    name: str
    kind: str  # "temperature" | "fan" | "power"
    value: float
    unit: str


_EMPTY_PVIDS: Mapping[int, int] = MappingProxyType({})


@dataclass(frozen=True)
class SwitchData:
    model: str
    host: str
    ports: tuple[PortStatus, ...] = ()
    poe: tuple[PoEStatus, ...] = ()
    vlans: tuple[VLANInfo, ...] = ()
    pvids: Mapping[int, int] = field(default=_EMPTY_PVIDS)
    lldp: tuple[LLDPNeighbor, ...] = ()
    macs: tuple[MacEntry, ...] = ()
    sensors: tuple[Sensor, ...] = ()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_models.py -v`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit**

```bash
git add src/netgear_switch/models.py tests/test_models.py
git commit -m "feat: add public device-data model"
```

---

### Task 4: Switch-model registry

**Files:**
- Create: `src/netgear_switch/registry.py`
- Test: `tests/test_registry.py`

**Interfaces:**
- Consumes: `netgear_switch.errors.UnknownModelError`.
- Produces:
  - `class Backend(enum.Enum)` — `SNMP`, `NSDP`, `HTTP`.
  - `class SwitchClass(enum.Enum)` — `FULLY_MANAGED`, `SMART_MANAGED_PRO`, `PLUS`.
  - `SwitchModel(key: str, display_name: str, switch_class: SwitchClass, port_count: int, poe_port_count: int, backends: frozenset[Backend], snmp_vendor_base: str | None)` — frozen; property `has_mac_table: bool` (True iff `Backend.SNMP in backends`).
  - `MODELS: Mapping[str, SwitchModel]` — the fleet table.
  - `get_model(key: str) -> SwitchModel` — raises `UnknownModelError` on miss.

- [ ] **Step 1: Write the failing test**

`tests/test_registry.py`:
```python
import pytest

from netgear_switch.errors import UnknownModelError
from netgear_switch.registry import MODELS, Backend, SwitchClass, get_model


def test_known_models_present():
    for key in ("m4300-24x", "m4300-16x", "gsm7252ps", "gsm7228ps", "gs110emx", "gs305ep"):
        assert key in MODELS


def test_managed_switch_has_snmp_and_vendor_base():
    m = get_model("gsm7252ps")
    assert Backend.SNMP in m.backends
    assert m.poe_port_count == 48
    assert m.snmp_vendor_base == "1.3.6.1.4.1.4526.10"
    assert m.has_mac_table is True


def test_smart_managed_pro_uses_4526_11():
    assert get_model("gsm7228ps").snmp_vendor_base == "1.3.6.1.4.1.4526.11"


def test_plus_switch_no_snmp_no_mac_table():
    p = get_model("gs110emx")
    assert Backend.SNMP not in p.backends
    assert Backend.NSDP in p.backends
    assert Backend.HTTP in p.backends
    assert p.snmp_vendor_base is None
    assert p.has_mac_table is False
    assert p.switch_class is SwitchClass.PLUS


def test_unknown_model_raises():
    with pytest.raises(UnknownModelError):
        get_model("nonesuch")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_registry.py -v`
Expected: FAIL (ImportError from `netgear_switch.registry`).

- [ ] **Step 3: Write the implementation**

`src/netgear_switch/registry.py`:
```python
"""Declarative registry of known Netgear switch models."""

from __future__ import annotations

import enum
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from .errors import UnknownModelError

_FM = "1.3.6.1.4.1.4526.10"   # Fully Managed vendor subtree (M4300, GSM7252PS)
_SMP = "1.3.6.1.4.1.4526.11"  # Smart Managed Pro vendor subtree (S3300/GSM7228PS)


class Backend(enum.Enum):
    SNMP = "snmp"
    NSDP = "nsdp"
    HTTP = "http"


class SwitchClass(enum.Enum):
    FULLY_MANAGED = "fully_managed"
    SMART_MANAGED_PRO = "smart_managed_pro"
    PLUS = "plus"


@dataclass(frozen=True)
class SwitchModel:
    key: str
    display_name: str
    switch_class: SwitchClass
    port_count: int
    poe_port_count: int
    backends: frozenset[Backend]
    snmp_vendor_base: str | None

    @property
    def has_mac_table(self) -> bool:
        # MAC/FDB table is only reachable via SNMP (managed switches).
        return Backend.SNMP in self.backends


def _model(
    key: str,
    display_name: str,
    switch_class: SwitchClass,
    port_count: int,
    poe_port_count: int,
    backends: set[Backend],
    snmp_vendor_base: str | None,
) -> SwitchModel:
    return SwitchModel(
        key=key,
        display_name=display_name,
        switch_class=switch_class,
        port_count=port_count,
        poe_port_count=poe_port_count,
        backends=frozenset(backends),
        snmp_vendor_base=snmp_vendor_base,
    )


_MODELS: dict[str, SwitchModel] = {
    m.key: m
    for m in (
        _model("m4300-24x", "M4300-24X (XSM4324CS)", SwitchClass.FULLY_MANAGED, 28, 0, {Backend.SNMP}, _FM),
        _model("m4300-16x", "M4300-16X (XSM4316)", SwitchClass.FULLY_MANAGED, 16, 16, {Backend.SNMP}, _FM),
        _model("gsm7252ps", "GSM7252PS", SwitchClass.FULLY_MANAGED, 52, 48, {Backend.SNMP}, _FM),
        _model("gsm7228ps", "GSM7228PS (S3300)", SwitchClass.SMART_MANAGED_PRO, 52, 48, {Backend.SNMP, Backend.HTTP}, _SMP),
        _model("gs110emx", "GS110EMX", SwitchClass.PLUS, 10, 0, {Backend.NSDP, Backend.HTTP}, None),
        _model("gs305ep", "GS305EP", SwitchClass.PLUS, 5, 4, {Backend.NSDP, Backend.HTTP}, None),
    )
}

MODELS: Mapping[str, SwitchModel] = MappingProxyType(_MODELS)


def get_model(key: str) -> SwitchModel:
    try:
        return _MODELS[key]
    except KeyError:
        raise UnknownModelError(f"unknown switch model: {key!r}") from None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_registry.py -v`
Expected: PASS (5 passed).

- [ ] **Step 5: Commit**

```bash
git add src/netgear_switch/registry.py tests/test_registry.py
git commit -m "feat: add switch-model registry"
```

---

### Task 5: Inventory config & credential resolution

**Files:**
- Create: `src/netgear_switch/config.py`
- Test: `tests/test_config.py`

**Interfaces:**
- Consumes: `errors.ConfigError`, `errors.CredentialError`, `registry.get_model`, `registry.SwitchModel`.
- Produces:
  - `resolve_secret(spec: str | None, *, env: Mapping[str, str], runner=subprocess.run) -> str | None` — resolves one secret string. `None` → `None`. `"${VAR}"` → `env["VAR"]` (missing → `CredentialError`). `"!cmd args"` → stdout of `cmd args` stripped (non-zero exit → `CredentialError`). Anything else → the literal string.
  - `@dataclass(frozen=True) SwitchConfig(name: str, model: SwitchModel, host: str, snmp_community: str | None, snmp_write_community_spec: str | None, http_password_spec: str | None, nsdp_interface: str | None, protected_ports: frozenset[int])` with method `snmp_write_community(*, env, runner=subprocess.run) -> str | None` and `http_password(...)` that call `resolve_secret` lazily.
  - `load_inventory(path: str | os.PathLike, *, env: Mapping[str, str] | None = None) -> dict[str, SwitchConfig]` — parse a TOML file with a top-level `[switches.<name>]` table each. `env` defaults to `os.environ`. Enforces secure file permissions when the file contains any literal secret (see `ensure_secure_file`).
  - `ensure_secure_file(path) -> None` — raise `ConfigError` if the file is group/other-readable (mode & 0o077).

- [ ] **Step 1: Write the failing test**

`tests/test_config.py`:
```python
import os
import stat
import textwrap

import pytest

from netgear_switch import errors
from netgear_switch.config import (
    SwitchConfig,
    ensure_secure_file,
    load_inventory,
    resolve_secret,
)


def test_resolve_secret_literal_env_command_and_none():
    assert resolve_secret(None, env={}) is None
    assert resolve_secret("public", env={}) == "public"
    assert resolve_secret("${WC}", env={"WC": "s3cr3t"}) == "s3cr3t"

    def fake_runner(args, **kw):
        assert args == ["pass", "show", "netgear/x"]
        return __import__("types").SimpleNamespace(returncode=0, stdout="frompass\n", stderr="")

    assert resolve_secret("!pass show netgear/x", env={}, runner=fake_runner) == "frompass"


def test_resolve_secret_missing_env_raises():
    with pytest.raises(errors.CredentialError):
        resolve_secret("${NOPE}", env={})


def test_resolve_secret_command_failure_raises():
    def failing(args, **kw):
        return __import__("types").SimpleNamespace(returncode=1, stdout="", stderr="boom")

    with pytest.raises(errors.CredentialError):
        resolve_secret("!false", env={}, runner=failing)


def _write(tmp_path, body, mode=0o600):
    p = tmp_path / "inv.toml"
    p.write_text(textwrap.dedent(body))
    os.chmod(p, mode)
    return p


def test_load_inventory_parses_switches(tmp_path):
    p = _write(
        tmp_path,
        """
        [switches.sw-a]
        model = "gsm7252ps"
        host = "10.1.5.20"
        snmp.community = "public"
        snmp.write_community = "${WC}"
        protected_ports = [9, 10]

        [switches.sw-b]
        model = "gs110emx"
        host = "10.1.5.25"
        http.password = "${PW}"
        nsdp.interface = "eth0"
        """,
    )
    inv = load_inventory(p, env={"WC": "w", "PW": "p"})
    assert set(inv) == {"sw-a", "sw-b"}
    a = inv["sw-a"]
    assert isinstance(a, SwitchConfig)
    assert a.model.key == "gsm7252ps"
    assert a.snmp_community == "public"
    assert a.protected_ports == frozenset({9, 10})
    assert a.snmp_write_community(env={"WC": "w"}) == "w"
    assert inv["sw-b"].nsdp_interface == "eth0"
    assert inv["sw-b"].http_password(env={"PW": "p"}) == "p"


def test_load_inventory_unknown_model_raises(tmp_path):
    p = _write(
        tmp_path,
        """
        [switches.bad]
        model = "nope"
        host = "1.2.3.4"
        """,
    )
    with pytest.raises(errors.NetgearSwitchError):
        load_inventory(p, env={})


def test_literal_secret_requires_secure_permissions(tmp_path):
    p = _write(
        tmp_path,
        """
        [switches.sw]
        model = "gsm7252ps"
        host = "10.1.5.20"
        snmp.write_community = "literalsecret"
        """,
        mode=0o644,
    )
    with pytest.raises(errors.ConfigError):
        load_inventory(p, env={})


def test_ensure_secure_file_accepts_600(tmp_path):
    p = tmp_path / "ok"
    p.write_text("x")
    os.chmod(p, 0o600)
    ensure_secure_file(p)  # no raise


def test_ensure_secure_file_rejects_world_readable(tmp_path):
    p = tmp_path / "bad"
    p.write_text("x")
    os.chmod(p, stat.S_IRUSR | stat.S_IWUSR | stat.S_IROTH)
    with pytest.raises(errors.ConfigError):
        ensure_secure_file(p)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_config.py -v`
Expected: FAIL (ImportError from `netgear_switch.config`).

- [ ] **Step 3: Write the implementation**

`src/netgear_switch/config.py`:
```python
"""TOML inventory loading and credential resolution."""

from __future__ import annotations

import os
import shlex
import subprocess
import tomllib
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from .errors import ConfigError, CredentialError
from .registry import SwitchModel, get_model

Runner = Callable[..., subprocess.CompletedProcess]


def resolve_secret(
    spec: str | None,
    *,
    env: Mapping[str, str],
    runner: Runner = subprocess.run,
) -> str | None:
    """Resolve one secret spec to its value (or None)."""
    if spec is None:
        return None
    if spec.startswith("${") and spec.endswith("}"):
        name = spec[2:-1]
        try:
            return env[name]
        except KeyError:
            raise CredentialError(f"environment variable {name!r} is not set") from None
    if spec.startswith("!"):
        args = shlex.split(spec[1:])
        if not args:
            raise CredentialError("empty command in secret spec")
        result = runner(args, capture_output=True, text=True)
        if result.returncode != 0:
            raise CredentialError(
                f"secret command {args!r} failed (exit {result.returncode}): {result.stderr.strip()}"
            )
        return result.stdout.strip()
    return spec


def _is_literal(spec: str | None) -> bool:
    if spec is None:
        return False
    return not (spec.startswith("${") and spec.endswith("}")) and not spec.startswith("!")


def ensure_secure_file(path: os.PathLike | str) -> None:
    """Raise if the file is readable/writable by group or other."""
    mode = os.stat(path).st_mode
    if mode & 0o077:
        raise ConfigError(
            f"{os.fspath(path)} has insecure permissions {oct(mode & 0o777)}; "
            "chmod 600 it (contains a literal secret)"
        )


@dataclass(frozen=True)
class SwitchConfig:
    name: str
    model: SwitchModel
    host: str
    snmp_community: str | None
    snmp_write_community_spec: str | None
    http_password_spec: str | None
    nsdp_interface: str | None
    protected_ports: frozenset[int]

    def snmp_write_community(
        self, *, env: Mapping[str, str], runner: Runner = subprocess.run
    ) -> str | None:
        return resolve_secret(self.snmp_write_community_spec, env=env, runner=runner)

    def http_password(
        self, *, env: Mapping[str, str], runner: Runner = subprocess.run
    ) -> str | None:
        return resolve_secret(self.http_password_spec, env=env, runner=runner)


def _switch_from_table(name: str, table: Mapping[str, object]) -> tuple[SwitchConfig, list[str]]:
    try:
        model_key = table["model"]
        host = table["host"]
    except KeyError as exc:
        raise ConfigError(f"switch {name!r} is missing required key {exc.args[0]!r}") from None
    if not isinstance(model_key, str) or not isinstance(host, str):
        raise ConfigError(f"switch {name!r}: 'model' and 'host' must be strings")

    snmp = table.get("snmp", {})
    http = table.get("http", {})
    nsdp = table.get("nsdp", {})
    if not isinstance(snmp, Mapping) or not isinstance(http, Mapping) or not isinstance(nsdp, Mapping):
        raise ConfigError(f"switch {name!r}: snmp/http/nsdp must be tables")

    ports = table.get("protected_ports", [])
    if not isinstance(ports, list) or not all(isinstance(p, int) for p in ports):
        raise ConfigError(f"switch {name!r}: protected_ports must be a list of ints")

    secret_specs = [
        snmp.get("write_community"),
        http.get("password"),
    ]
    literals = [s for s in secret_specs if _is_literal(s if isinstance(s, str) else None)]

    cfg = SwitchConfig(
        name=name,
        model=get_model(model_key),
        host=host,
        snmp_community=snmp.get("community"),
        snmp_write_community_spec=snmp.get("write_community"),
        http_password_spec=http.get("password"),
        nsdp_interface=nsdp.get("interface"),
        protected_ports=frozenset(ports),
    )
    return cfg, literals


def load_inventory(
    path: os.PathLike | str,
    *,
    env: Mapping[str, str] | None = None,
) -> dict[str, SwitchConfig]:
    """Load a TOML inventory into a {name: SwitchConfig} dict."""
    if env is None:
        env = os.environ
    with open(path, "rb") as fh:
        data = tomllib.load(fh)

    switches = data.get("switches", {})
    if not isinstance(switches, Mapping):
        raise ConfigError("top-level [switches] must be a table")

    result: dict[str, SwitchConfig] = {}
    any_literal = False
    for name, table in switches.items():
        if not isinstance(table, Mapping):
            raise ConfigError(f"[switches.{name}] must be a table")
        cfg, literals = _switch_from_table(name, table)
        if literals:
            any_literal = True
        result[name] = cfg

    if any_literal:
        ensure_secure_file(path)
    return result
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_config.py -v`
Expected: PASS (8 passed).

- [ ] **Step 5: Full suite + lint**

Run: `uv run --extra testing pytest -q && uv run ruff check`
Expected: all tests pass; `All checks passed!`

- [ ] **Step 6: Commit**

```bash
git add src/netgear_switch/config.py tests/test_config.py
git commit -m "feat: add TOML inventory and credential resolution"
```

---

## Self-Review Notes

- **Spec coverage (foundation slice):** package/packaging (§8) → Task 1; error types incl. `UnsupportedCapability`/`WriteVerificationError` (§2, §6) → Task 2; public model shape `SwitchData` & friends (§3) → Task 3; model registry with backends, vendor OID subtree, Plus-has-no-MAC-table constraint (§2, §5.2) → Task 4; TOML inventory + credential resolution order incl. `${ENV}`/`!command`/literal + `ensure_secure_file` (§5) → Task 5. Backends' actual I/O, dual APIs, virtual switch, CLI, cross-check are **out of scope for this plan** by design (later plans in the sequence).
- **Deferred-but-declared:** the `ngsw` entry point in `pyproject.toml` points at a module delivered later; noted inline in Task 1 so it is intentional, not a placeholder.
- **Type consistency:** `SwitchModel` fields, `Backend`/`SwitchClass` enums, and `resolve_secret`/`SwitchConfig` signatures are used identically across tasks 4–5. `snmp_vendor_base` values (`_FM`/`_SMP`) match the spec's `4526.10`/`4526.11`.
- **Credential precedence caveat:** this plan implements the config-value and env/command/literal resolution. The full **CLI flag → env → config → prompt** ordering is completed in the CLI plan, which layers flags and interactive prompting on top of `resolve_secret`.
