# SNMP Read Core + SNMP Virtual Face Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a pure-logic + transport SNMP **read** core (OID tables, pure parsers, sync/async clients, model-driven read operations) plus an SNMP **virtual-switch face** (a pysnmp agent over authoritative device state), so every read capability is testable against a mock with no real hardware.

**Architecture:** All SNMP *knowledge* lives in I/O-free pure code — `protocols/snmp/oids.py` (OID constants + per-model tables) and `protocols/snmp/parse.py` (SNMP rows → frozen `models.py` objects). Only byte I/O is duplicated per sync/async transport (`transport/sync/snmp_ezsnmp.py` on ezsnmp, `transport/aio/snmp_pysnmp.py` on pysnmp v7), behind a shared `SnmpRow`/`SnmpError`/`SnmpClient` seam. A thin `SnmpReader`/`AsyncSnmpReader` orchestrates client walks through the parsers. The `virtual/` subpackage holds one authoritative `VirtualSwitchState`, a hand-authored `gsm7252ps` seed, and a pysnmp command-responder face that serves GET/GETNEXT/BULK from that state — a *different* SNMP stack than the ezsnmp client under test, so the cross-check is not a mirror.

**Tech Stack:** Python ≥3.11, `uv`, hatchling. ezsnmp (sync SNMP), pysnmp v7 (async SNMP + agent engine). pytest, pytest-cov, ruff, mypy (strict).

## Global Constraints

- **Python ≥ 3.11** (`requires-python = ">=3.11"`); target `py311`.
- **Import name `netgear_switch`**; distribution `python-netgear-switch-library`; CLI `ngsw`.
- **Package/dep management via `uv`.** Run tests with `uv run pytest`, lint with `uv run ruff`, types with `uv run mypy`. If a `uv` command hits a read-only-fs / uv-cache error, that is a sandbox artifact — re-run outside the sandbox; it is not a code failure.
- **Never `git add -A` / `git add .`** — the working tree contains overlay char-device dotfiles that corrupt the index. Every commit lists **explicit file paths**.
- **Public return types are frozen and hashable** — `@dataclass(frozen=True)`, fields are scalars / `enum.Enum` / `tuple` / `frozenset` (never `list`/`dict`/`set`). Both APIs return identical instances.
- **Quality gates are enforced and must stay green after every task:** `ruff check`, `mypy --strict` on `src/`, and `pytest` with `--cov-fail-under=90`. No skips, no xfails papering over real failures, no flaky tests.
- **Errors surfaced early:** invalid/unexpected switch responses, unknown models, unsupported-capability-per-model, and out-of-range values raise typed errors from `netgear_switch.errors` — never silently swallowed or returned as empty/`None`. (A counter a device genuinely does not expose is a legitimate `None`, distinct from an error.)
- **Lazy-import heavy deps:** `ezsnmp` and `pysnmp` are imported *inside* functions/methods, never at module top level, so the pure layer and unit tests never load a C extension or the async engine. These lazy imports and the deliberately broad `except Exception` in the transports carry **no `# noqa`** — the rules that would flag them (`PLC0415`, `BLE001`) are not in the Task 1 ruff `select` list, and because `RUF` *is* selected, `RUF100` (unused-noqa) would fail the "ruff clean" gate on any such dead directive. Never suppress a rule that is not enabled.
- **Local == CI:** everything green locally must be green in GitHub Actions and vice-versa.

---

## File Structure

**Created:**
- `src/netgear_switch/protocols/__init__.py` — namespace package marker.
- `src/netgear_switch/protocols/snmp/__init__.py` — namespace package marker.
- `src/netgear_switch/protocols/snmp/client.py` — pure seam: `SnmpRow` frozen dataclass, `SnmpError`, `SnmpClient`/`AsyncSnmpClient` `Protocol`s. No I/O.
- `src/netgear_switch/protocols/snmp/oids.py` — OID constants + per-model OID tables as pure data.
- `src/netgear_switch/protocols/snmp/parse.py` — pure functions: SNMP rows → `models.py` objects.
- `src/netgear_switch/transport/__init__.py` — namespace package marker.
- `src/netgear_switch/transport/sync/__init__.py` — namespace package marker.
- `src/netgear_switch/transport/sync/snmp_ezsnmp.py` — sync `SnmpClient` on ezsnmp (lazy import).
- `src/netgear_switch/transport/aio/__init__.py` — namespace package marker.
- `src/netgear_switch/transport/aio/snmp_pysnmp.py` — async `SnmpClient` on pysnmp v7 (lazy import).
- `src/netgear_switch/snmp_read.py` — `SnmpReader` (sync) + `AsyncSnmpReader`: client + model → model objects.
- `src/netgear_switch/virtual/__init__.py` — subpackage marker (public `VirtualSwitch`, `VirtualSwitchState`).
- `src/netgear_switch/virtual/state.py` — `VirtualSwitchState`: one mutable source of truth.
- `src/netgear_switch/virtual/seed.py` — build state from registry + hand-authored fixtures (`gsm7252ps`).
- `src/netgear_switch/virtual/faces/__init__.py` — marker.
- `src/netgear_switch/virtual/faces/mibview.py` — pure `StateMibView` OID responder (GET/GETNEXT via `bisect` over the sorted OID map); no network, no pysnmp.
- `src/netgear_switch/virtual/faces/snmp.py` — pysnmp command-responder MIB controller wiring `StateMibView` onto the agent engine.
- `src/netgear_switch/virtual/server.py` — `VirtualSwitch(model=...)`: binds the SNMP face to an ephemeral UDP port.
- Tests: `tests/protocols/snmp/test_oids.py`, `test_parse_ports.py`, `test_parse_vlans.py`, `test_parse_lldp_macs.py`, `test_parse_poe_sensors.py`, `test_parse_mgmt_ip.py`; `tests/transport/test_snmp_ezsnmp.py`, `test_snmp_pysnmp.py`; `tests/test_snmp_read.py`; `tests/virtual/test_state_seed.py`, `test_mibview.py`, `test_virtual_snmp_face.py`; `tests/test_snmp_integration.py`; `tests/fixtures/snmp/*.txt` (hand-copied walk fixtures).

**Modified:**
- `src/netgear_switch/models.py` — add `PortStats`, `MgmtIpConfig`, `IpMode`; extend `SwitchData`.
- `pyproject.toml` — ruff rule expansion, mypy strict config, pytest-cov config, dev deps.
- `tests/test_public_api.py` — assert the new public model names are exported (only if it already checks exports).

---

### Task 1: Quality tooling gates + dependency wiring

Adopt strict lint, strict typing, and a coverage floor as enforced gates **first**, so every later task keeps them green. Confirm ezsnmp actually imports in this environment; if it did not, this task would be the documented blocker. (Verified during planning: `python3 -c "import ezsnmp"` succeeds — the net-snmp C binding is present. pysnmp is not in the base interpreter but is declared under the `async`/`testing` extras and loaded via `uv run`.)

**Files:**
- Modify: `pyproject.toml`
- Create: `src/netgear_switch/protocols/__init__.py`, `src/netgear_switch/protocols/snmp/__init__.py`
- Test: `tests/test_quality_gates.py`

**Interfaces:**
- Consumes: nothing.
- Produces: gate commands `uv run ruff check`, `uv run mypy --strict src`, `uv run pytest --cov=netgear_switch --cov-fail-under=90`; the `protocols.snmp` import path.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_quality_gates.py
"""The quality gates and the new package path must be wired up."""
from __future__ import annotations

import tomllib
from pathlib import Path


def test_ruff_selects_type_aware_and_bug_rules():
    cfg = tomllib.loads(Path("pyproject.toml").read_text())
    select = cfg["tool"]["ruff"]["lint"]["select"]
    for rule in ("E", "F", "I", "UP", "B", "SIM", "RUF", "PT", "TC", "C4"):
        assert rule in select, f"ruff must select {rule}"


def test_mypy_strict_configured():
    cfg = tomllib.loads(Path("pyproject.toml").read_text())
    assert cfg["tool"]["mypy"]["strict"] is True
    assert "netgear_switch" in cfg["tool"]["mypy"]["packages"]


def test_coverage_floor_configured():
    cfg = tomllib.loads(Path("pyproject.toml").read_text())
    addopts = cfg["tool"]["pytest"]["ini_options"]["addopts"]
    assert "--cov=netgear_switch" in addopts
    assert "--cov-fail-under=90" in addopts


def test_dev_group_has_type_and_cov_tools():
    cfg = tomllib.loads(Path("pyproject.toml").read_text())
    dev = " ".join(cfg["dependency-groups"]["dev"])
    assert "mypy" in dev
    assert "pytest-cov" in dev


def test_protocols_snmp_package_importable():
    import netgear_switch.protocols.snmp  # noqa: F401
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_quality_gates.py -v`
Expected: FAIL — `tool.mypy` missing, `--cov` not in addopts, `netgear_switch.protocols.snmp` import error.

- [ ] **Step 3: Wire the gates and create the package markers**

Create empty `src/netgear_switch/protocols/__init__.py` and `src/netgear_switch/protocols/snmp/__init__.py` each containing only:
```python
"""SNMP protocol logic (pure, I/O-free)."""
```
Edit `pyproject.toml`:
```toml
[dependency-groups]
dev = ["pytest>=8.0", "ruff>=0.6", "mypy>=1.11", "pytest-cov>=5.0"]

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-ra --cov=netgear_switch --cov-report=term-missing --cov-fail-under=90"

[tool.ruff.lint]
select = ["E", "F", "I", "UP", "B", "SIM", "RUF", "PT", "TC", "C4", "PIE", "RET", "N"]

[tool.mypy]
packages = ["netgear_switch"]
strict = true
python_version = "3.11"
```
(Keep existing `[tool.ruff]` `target-version`/`src`. The `async`/`testing` extras already list `pysnmp>=7.0`; the `sync` extra already lists `ezsnmp~=1.1` — leave them.)

- [ ] **Step 4: Run tests + all gates to verify green**

Run:
```
uv run pytest tests/test_quality_gates.py -v
uv run ruff check
uv run mypy --strict src
uv run pytest
```
Expected: quality-gates test PASSES; ruff clean; mypy clean; full suite passes with coverage ≥ 90%.

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml tests/test_quality_gates.py \
  src/netgear_switch/protocols/__init__.py \
  src/netgear_switch/protocols/snmp/__init__.py
git commit -m "build: adopt strict ruff/mypy/coverage gates and protocols.snmp package"
```

---

### Task 2: Extend `models.py` with `PortStats`, `MgmtIpConfig`, `IpMode`

Add the two read types §11 needs but the foundation lacks, keeping them frozen/hashable, and thread them onto `SwitchData`.

**Files:**
- Modify: `src/netgear_switch/models.py`
- Test: `tests/test_models_snmp_read.py`

**Interfaces:**
- Consumes: existing `models.py` types.
- Produces:
  - `class IpMode(enum.Enum)` with `DHCP="dhcp"`, `STATIC="static"`, `UNKNOWN="unknown"`.
  - `PortStats(port:int, rx_bytes:int|None, tx_bytes:int|None, rx_packets:int|None, tx_packets:int|None, rx_errors:int|None, tx_errors:int|None)` frozen.
  - `MgmtIpConfig(mode:IpMode, address:str|None, netmask:str|None, gateway:str|None)` frozen.
  - `SwitchData` gains `stats: tuple[PortStats, ...] = ()` and `mgmt_ip: MgmtIpConfig | None = None`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_models_snmp_read.py
from __future__ import annotations

from netgear_switch.models import IpMode, MgmtIpConfig, PortStats, SwitchData


def test_portstats_is_frozen_and_hashable():
    s = PortStats(port=1, rx_bytes=10, tx_bytes=20, rx_packets=3,
                  tx_packets=4, rx_errors=0, tx_errors=None)
    assert hash(s) == hash(
        PortStats(1, 10, 20, 3, 4, 0, None)
    )
    import dataclasses
    assert dataclasses.is_dataclass(s)


def test_mgmtipconfig_frozen_and_mode_enum():
    m = MgmtIpConfig(mode=IpMode.STATIC, address="10.1.5.20",
                     netmask="255.255.255.0", gateway="10.1.5.1")
    assert m.mode is IpMode.STATIC
    assert hash(m)  # hashable


def test_switchdata_defaults_include_stats_and_mgmt_ip():
    d = SwitchData(model="gsm7252ps", host="10.1.5.20")
    assert d.stats == ()
    assert d.mgmt_ip is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_models_snmp_read.py -v`
Expected: FAIL — `ImportError: cannot import name 'PortStats'`.

- [ ] **Step 3: Implement the model additions**

In `src/netgear_switch/models.py`, add after the existing enums:
```python
class IpMode(enum.Enum):
    DHCP = "dhcp"
    STATIC = "static"
    UNKNOWN = "unknown"
```
Add near the other dataclasses:
```python
@dataclass(frozen=True)
class PortStats:
    port: int
    rx_bytes: int | None
    tx_bytes: int | None
    rx_packets: int | None
    tx_packets: int | None
    rx_errors: int | None
    tx_errors: int | None


@dataclass(frozen=True)
class MgmtIpConfig:
    mode: IpMode
    address: str | None
    netmask: str | None
    gateway: str | None
```
Extend `SwitchData` (append fields after `sensors`, keeping tuple/None defaults so existing call sites stay valid):
```python
    stats: tuple[PortStats, ...] = ()
    mgmt_ip: MgmtIpConfig | None = None
```

- [ ] **Step 4: Run test + gates to verify green**

Run: `uv run pytest tests/test_models_snmp_read.py -v && uv run mypy --strict src && uv run ruff check`
Expected: PASS; mypy + ruff clean.

- [ ] **Step 5: Commit**

```bash
git add src/netgear_switch/models.py tests/test_models_snmp_read.py
git commit -m "feat(models): add PortStats, MgmtIpConfig, IpMode read types"
```

---

### Task 3: SNMP transport seam — `SnmpRow`, `SnmpError`, client protocols

Define the shared, pure seam every parser and transport uses. `SnmpRow` and the `Protocol`s carry no I/O, so they live in the pure `protocols/snmp` layer; the ezsnmp/pysnmp implementations (later tasks) import from here.

**Files:**
- Create: `src/netgear_switch/protocols/snmp/client.py`
- Test: `tests/protocols/snmp/test_client.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `SnmpRow(oid:str, value:str, snmp_type:str)` frozen dataclass. `oid` is the full dotted-decimal numeric OID (no leading dot); `value` is the string form; `snmp_type` is the agent-reported type token (e.g. `"INTEGER"`, `"Gauge32"`, `"OCTETSTR"`).
  - `class SnmpError(NetgearSwitchError)` — raised on transport failure (import from `..errors`? No — see note). Defined here inheriting from `netgear_switch.errors.NetgearSwitchError`.
  - `ABSENT_TYPES: frozenset[str]` = `{"NOSUCHOBJECT", "NOSUCHINSTANCE", "ENDOFMIBVIEW"}`.
  - `full_oid(oid:str, oid_index:str) -> str` helper (rejoins ezsnmp's split; strips leading dot).
  - `class SnmpClient(Protocol)`: `def get(self, oid:str) -> SnmpRow | None`; `def walk(self, oid:str) -> list[SnmpRow]`.
  - `class AsyncSnmpClient(Protocol)`: `async def get(...) -> SnmpRow | None`; `async def walk(...) -> list[SnmpRow]`.

- [ ] **Step 1: Write the failing test**

```python
# tests/protocols/snmp/test_client.py
from __future__ import annotations

from netgear_switch.errors import NetgearSwitchError
from netgear_switch.protocols.snmp.client import (
    ABSENT_TYPES,
    SnmpError,
    SnmpRow,
    full_oid,
)


def test_snmprow_frozen_hashable():
    r = SnmpRow(oid="1.3.6.1.2.1.2.2.1.8.1", value="1", snmp_type="INTEGER")
    assert hash(r)
    assert r.oid.endswith(".8.1")


def test_snmp_error_is_library_error():
    assert issubclass(SnmpError, NetgearSwitchError)


def test_full_oid_rejoins_and_strips_leading_dot():
    assert full_oid(".1.3.6.1.2.1.2.2.1.8", "1") == "1.3.6.1.2.1.2.2.1.8.1"
    assert full_oid("1.3.6.1.2.1.2.2.1.8.1", "") == "1.3.6.1.2.1.2.2.1.8.1"


def test_absent_types():
    assert "NOSUCHINSTANCE" in ABSENT_TYPES
    assert "ENDOFMIBVIEW" in ABSENT_TYPES
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/protocols/snmp/test_client.py -v`
Expected: FAIL — module `netgear_switch.protocols.snmp.client` not found. (Create `tests/protocols/__init__.py`, `tests/protocols/snmp/__init__.py` are NOT needed — pytest uses rootdir discovery; but add `tests/protocols/` dir implicitly by the test file path.)

- [ ] **Step 3: Implement the seam**

```python
# src/netgear_switch/protocols/snmp/client.py
"""Shared SNMP transport seam: row type, error, and client protocols.

Pure and I/O-free. The ezsnmp (sync) and pysnmp (async) transports both
implement these protocols and return SnmpRow instances the parsers consume.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from ...errors import NetgearSwitchError

# snmp_type tokens meaning "no value present here".
ABSENT_TYPES: frozenset[str] = frozenset(
    {"NOSUCHOBJECT", "NOSUCHINSTANCE", "ENDOFMIBVIEW"}
)


@dataclass(frozen=True)
class SnmpRow:
    """One SNMP varbind: full numeric OID, value string, agent type token."""

    oid: str
    value: str
    snmp_type: str


class SnmpError(NetgearSwitchError):
    """An SNMP transport operation failed (timeout, connection, agent error)."""


def full_oid(oid: str, oid_index: str) -> str:
    """Rejoin ezsnmp's (oid, oid_index) split into a full numeric OID.

    ezsnmp may return the whole numeric OID in ``oid`` with an empty
    ``oid_index``, or split the instance into ``oid_index``. Joining both
    and stripping any leading dot is correct either way.
    """
    oid = oid.lstrip(".")
    return f"{oid}.{oid_index}" if oid_index else oid


class SnmpClient(Protocol):
    """Synchronous SNMP v2c read client for a single switch."""

    def get(self, oid: str) -> SnmpRow | None: ...

    def walk(self, oid: str) -> list[SnmpRow]: ...


class AsyncSnmpClient(Protocol):
    """Asynchronous SNMP v2c read client for a single switch."""

    async def get(self, oid: str) -> SnmpRow | None: ...

    async def walk(self, oid: str) -> list[SnmpRow]: ...
```

- [ ] **Step 4: Run test + gates**

Run: `uv run pytest tests/protocols/snmp/test_client.py -v && uv run mypy --strict src && uv run ruff check`
Expected: PASS; clean.

- [ ] **Step 5: Commit**

```bash
git add src/netgear_switch/protocols/snmp/client.py tests/protocols/snmp/test_client.py
git commit -m "feat(snmp): shared SnmpRow/SnmpError seam and client protocols"
```

---

### Task 4: `oids.py` — OID constants + per-model tables

Encode every OID this slice reads, as pure data, citing the real strings mined from `gdoc2netcfg/supplements/bridge.py`, `sensors2mqtt/collector/snmp.py`, `snmp_control.py`, and `snmp_common.py`. Vendor bases come from the registry's `snmp_vendor_base` (`1.3.6.1.4.1.4526.10` fully-managed, `.11` smart-managed-pro).

**Files:**
- Create: `src/netgear_switch/protocols/snmp/oids.py`
- Test: `tests/protocols/snmp/test_oids.py`

**Interfaces:**
- Consumes: `netgear_switch.registry.SwitchModel`.
- Produces: module-level standard-MIB OID constants (all `str`, dotted-decimal, no leading dot); a `VendorOids` frozen dataclass and `vendor_oids(model: SwitchModel) -> VendorOids`; `BOX_SENSOR_COLUMNS: tuple[tuple[str, str, str], ...]` of `(kind, unit, column_suffix)`.

Standard-MIB constants (authoritative source: `bridge.py` lines 52–120, `snmp_control.py` lines 57–59, `snmp_common.py` lines 35–36):
```
IF_ADMIN_STATUS   = "1.3.6.1.2.1.2.2.1.7"        # ifAdminStatus (1=up,2=down)
IF_OPER_STATUS    = "1.3.6.1.2.1.2.2.1.8"        # ifOperStatus  (1=up,2=down)
IF_IN_ERRORS      = "1.3.6.1.2.1.2.2.1.14"
IF_OUT_ERRORS     = "1.3.6.1.2.1.2.2.1.20"
IF_NAME           = "1.3.6.1.2.1.31.1.1.1.1"
IF_HC_IN_OCTETS   = "1.3.6.1.2.1.31.1.1.1.6"
IF_HC_IN_UCAST    = "1.3.6.1.2.1.31.1.1.1.7"
IF_HC_OUT_OCTETS  = "1.3.6.1.2.1.31.1.1.1.10"
IF_HC_OUT_UCAST   = "1.3.6.1.2.1.31.1.1.1.11"
IF_HIGH_SPEED     = "1.3.6.1.2.1.31.1.1.1.15"    # Mbps
IF_ALIAS          = "1.3.6.1.2.1.31.1.1.1.18"
DOT1D_BASE_PORT_IF_INDEX = "1.3.6.1.2.1.17.1.4.1.2"
DOT1Q_TP_FDB_PORT        = "1.3.6.1.2.1.17.7.1.2.2.1.2"   # MAC table, port column ONLY
DOT1Q_VLAN_STATIC_NAME     = "1.3.6.1.2.1.17.7.1.4.3.1.1"
DOT1Q_VLAN_STATIC_EGRESS   = "1.3.6.1.2.1.17.7.1.4.3.1.2"
DOT1Q_VLAN_STATIC_UNTAGGED = "1.3.6.1.2.1.17.7.1.4.3.1.4"
DOT1Q_PVID                 = "1.3.6.1.2.1.17.7.1.4.5.1.1"
LLDP_REM_TABLE    = "1.0.8802.1.1.2.1.4.1"       # columns 5=chassis,7=portId,8=portDesc,9=sysName
PETH_PSE_PORT_TABLE = "1.3.6.1.2.1.105.1.1.1"    # RFC3621; col3=admin, col6=detect
IP_ADENT_ADDR     = "1.3.6.1.2.1.4.20.1.1"       # ipAddrTable (snmp_common.py:36 base .4.20)
IP_ADENT_IFINDEX  = "1.3.6.1.2.1.4.20.1.2"
IP_ADENT_NETMASK  = "1.3.6.1.2.1.4.20.1.3"
IP_ROUTE_DEST     = "1.3.6.1.2.1.4.21.1.1"       # ipRouteDest
IP_ROUTE_NEXTHOP  = "1.3.6.1.2.1.4.21.1.7"       # ipRouteNextHop (gateway where dest=0.0.0.0)
```
Vendor OIDs (source: `bridge.py` lines 96–115; `sensors2mqtt/collector/snmp.py` lines 205–236). `{base}` is `model.snmp_vendor_base`:
```
POE_POWER_MW  = "{base}.15.1.1.1.2"              # per-port PoE draw, milliwatts
BOX_FAN       = "{base}.43.1.6.1.4"              # RPM  (STRING; "Not Supported" = skip)
BOX_PSU_POWER = "{base}.43.1.8.1.5"              # Watts
BOX_TEMP      = "{base}.43.1.15.1.3"             # degrees C
# DHCP-vs-static mgmt-IP mode: single named, UNVERIFIED constant (never a bare
# literal). Exposed as VendorOids.dhcp_mode_unverified = "{base}.99.1"; see the
# loud docstring in Step 3 and RISK 3 in Self-Review.
```

- [ ] **Step 1: Write the failing test**

```python
# tests/protocols/snmp/test_oids.py
from __future__ import annotations

from netgear_switch.protocols.snmp import oids
from netgear_switch.registry import get_model


def test_standard_oids_are_dotted_no_leading_dot():
    assert oids.IF_OPER_STATUS == "1.3.6.1.2.1.2.2.1.8"
    assert oids.PETH_PSE_PORT_TABLE == "1.3.6.1.2.1.105.1.1.1"
    assert oids.DOT1Q_PVID == "1.3.6.1.2.1.17.7.1.4.5.1.1"
    assert not oids.IF_NAME.startswith(".")


def test_vendor_oids_use_registry_base_fully_managed():
    v = oids.vendor_oids(get_model("gsm7252ps"))  # base 4526.10
    assert v.poe_power_mw == "1.3.6.1.4.1.4526.10.15.1.1.1.2"
    assert v.box_fan == "1.3.6.1.4.1.4526.10.43.1.6.1.4"
    assert v.box_psu_power == "1.3.6.1.4.1.4526.10.43.1.8.1.5"
    assert v.box_temp == "1.3.6.1.4.1.4526.10.43.1.15.1.3"
    # The single named UNVERIFIED DHCP-mode OID (never a bare .99.1 literal).
    assert v.dhcp_mode_unverified == "1.3.6.1.4.1.4526.10.99.1"


def test_vendor_oids_use_registry_base_smart_managed():
    v = oids.vendor_oids(get_model("gsm7228ps"))  # base 4526.11
    assert v.poe_power_mw == "1.3.6.1.4.1.4526.11.15.1.1.1.2"


def test_vendor_oids_rejects_model_without_base():
    import pytest

    from netgear_switch.errors import UnsupportedCapability

    with pytest.raises(UnsupportedCapability):
        oids.vendor_oids(get_model("gs110emx"))  # Plus, no SNMP


def test_box_sensor_columns_cover_fan_psu_temp():
    kinds = {kind for kind, _unit, _suffix in oids.BOX_SENSOR_COLUMNS}
    assert kinds == {"fan", "power", "temperature"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/protocols/snmp/test_oids.py -v`
Expected: FAIL — module `oids` not found.

- [ ] **Step 3: Implement `oids.py`**

The module begins with its docstring and `from __future__ import annotations`
(so every annotation is a string and `SwitchModel` can stay behind
`TYPE_CHECKING`). Define all standard constants above verbatim. Then:
```python
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ...errors import UnsupportedCapability

if TYPE_CHECKING:
    # Imported only for the vendor_oids() type annotation; keep it behind
    # TYPE_CHECKING so ruff's TC rules stay clean and the pure layer stays light.
    from ...registry import SwitchModel

# (kind, unit, column suffix under {base}.43.1)
BOX_SENSOR_COLUMNS: tuple[tuple[str, str, str], ...] = (
    ("fan", "RPM", "6.1.4"),
    ("power", "W", "8.1.5"),
    ("temperature", "C", "15.1.3"),
)

DHCP_MODE_OID_SUFFIX = "99.1"
"""UNVERIFIED — this Netgear private OID for DHCP-vs-static management-IP mode is an unconfirmed guess used only so the mock and reader agree under test; it MUST be confirmed against real hardware via the capture utility (Slice 7) before it is trusted. Until then get_mgmt_ip returns IpMode.UNKNOWN when this OID is absent."""


@dataclass(frozen=True)
class VendorOids:
    base: str
    poe_power_mw: str
    box_fan: str
    box_psu_power: str
    box_temp: str
    dhcp_mode_unverified: str
    """The ONE symbol every call site uses for the DHCP-mode OID. See
    DHCP_MODE_OID_SUFFIX above — UNVERIFIED, best-effort read only. No call site
    may hard-code a ``.99.1`` literal; they all reference this field."""


def vendor_oids(model: SwitchModel) -> VendorOids:
    base = model.snmp_vendor_base
    if base is None:
        raise UnsupportedCapability(
            f"model {model.key!r} has no SNMP vendor OID subtree"
        )
    return VendorOids(
        base=base,
        poe_power_mw=f"{base}.15.1.1.1.2",
        box_fan=f"{base}.43.1.6.1.4",
        box_psu_power=f"{base}.43.1.8.1.5",
        box_temp=f"{base}.43.1.15.1.3",
        dhcp_mode_unverified=f"{base}.{DHCP_MODE_OID_SUFFIX}",
    )
```
Reading the mgmt-IP mode is best-effort/unverified; **setting** mgmt-IP mode is
out of scope for this read-only slice until the OID is confirmed on hardware.

- [ ] **Step 4: Run test + gates**

Run: `uv run pytest tests/protocols/snmp/test_oids.py -v && uv run mypy --strict src && uv run ruff check`
Expected: PASS; clean.

- [ ] **Step 5: Commit**

```bash
git add src/netgear_switch/protocols/snmp/oids.py tests/protocols/snmp/test_oids.py
git commit -m "feat(snmp): OID constants and per-model vendor OID tables"
```

---

### Task 5: `parse.py` — port status + port stats + shared helpers

First slice of the pure parser module: index helpers, port status (`PortStatus`), and port stats (`PortStats`). Lifted and adapted from `bridge.py::parse_port_status` / `_parse_port_statistics`, but returning frozen model objects and reading `SnmpRow`s.

**Files:**
- Create: `src/netgear_switch/protocols/snmp/parse.py`
- Create: `tests/fixtures/snmp/gsm7252ps_ifoperstatus.txt`, `gsm7252ps_ifhighspeed.txt` (hand-copied from `sensors2mqtt/tests/fixtures/snmpwalk_gsm7252ps_*`, normalising the leading `iso` → `1`).
- Test: `tests/protocols/snmp/test_parse_ports.py`

**Interfaces:**
- Consumes: `SnmpRow`; `oids`; `models.PortStatus`, `models.PortStats`.
- Produces:
  - `index_int_column(rows, base_oid) -> dict[int, int]` — last-component int index → int value; raises `SnmpError` on a non-integer value under `base_oid`.
  - `index_str_column(rows, base_oid) -> dict[int, str]`.
  - `parse_port_status(admin, oper, speed, names) -> list[PortStatus]` — args are `Sequence[SnmpRow]`; sorted by port; `admin_enabled = admin==1`; `link_up = oper==1`; `speed_mbps = speed or None` (0 → `None`); `name` from `names` or `None`.
  - `parse_port_stats(*, in_octets, out_octets, in_ucast, out_ucast, in_errors, out_errors) -> list[PortStats]` — each `Sequence[SnmpRow]`; a counter absent for a port is `None`, never fabricated.

Test data (from fixtures): ifOperStatus `...8.1=1, .8.2=1, .8.3=2, .8.4=2`; ifHighSpeed `...15.1=1000, .15.2=1000, .15.3=0, .15.4=0`.

- [ ] **Step 1: Write the failing test**

```python
# tests/protocols/snmp/test_parse_ports.py
from __future__ import annotations

import pytest

from netgear_switch.protocols.snmp import parse
from netgear_switch.protocols.snmp.client import SnmpError, SnmpRow


def _rows(base: str, pairs: dict[int, str], typ: str) -> list[SnmpRow]:
    return [SnmpRow(f"{base}.{i}", v, typ) for i, v in pairs.items()]


def test_parse_port_status_joins_admin_oper_speed_name():
    admin = _rows("1.3.6.1.2.1.2.2.1.7", {1: "1", 2: "2"}, "INTEGER")
    oper = _rows("1.3.6.1.2.1.2.2.1.8", {1: "1", 2: "2"}, "INTEGER")
    speed = _rows("1.3.6.1.2.1.31.1.1.1.15", {1: "1000", 2: "0"}, "Gauge32")
    names = _rows("1.3.6.1.2.1.31.1.1.1.1", {1: "1/0/1", 2: "1/0/2"}, "OCTETSTR")

    ports = parse.parse_port_status(admin, oper, speed, names)
    assert [p.port for p in ports] == [1, 2]
    assert ports[0].admin_enabled is True and ports[0].link_up is True
    assert ports[0].speed_mbps == 1000 and ports[0].name == "1/0/1"
    assert ports[1].admin_enabled is False and ports[1].link_up is False
    assert ports[1].speed_mbps is None  # 0 Mbps -> None


def test_parse_port_stats_absent_counter_is_none():
    stats = parse.parse_port_stats(
        in_octets=_rows("1.3.6.1.2.1.31.1.1.1.6", {1: "100"}, "Counter64"),
        out_octets=_rows("1.3.6.1.2.1.31.1.1.1.10", {1: "200"}, "Counter64"),
        in_ucast=_rows("1.3.6.1.2.1.31.1.1.1.7", {1: "5"}, "Counter64"),
        out_ucast=_rows("1.3.6.1.2.1.31.1.1.1.11", {1: "6"}, "Counter64"),
        in_errors=_rows("1.3.6.1.2.1.2.2.1.14", {1: "0"}, "Counter32"),
        out_errors=[],  # switch didn't expose ifOutErrors for port 1
    )
    assert len(stats) == 1
    assert stats[0].rx_bytes == 100 and stats[0].tx_bytes == 200
    assert stats[0].rx_packets == 5 and stats[0].tx_packets == 6
    assert stats[0].rx_errors == 0 and stats[0].tx_errors is None


def test_index_int_column_raises_on_non_integer():
    with pytest.raises(SnmpError):
        parse.index_int_column(
            [SnmpRow("1.3.6.1.2.1.2.2.1.8.1", "up", "OCTETSTR")],
            "1.3.6.1.2.1.2.2.1.8",
        )


def test_index_str_column_raises_on_present_but_malformed_index():
    # Column IS present under base but its index component is non-integer:
    # drift, not absence -> SnmpError (an absent column would just be {}).
    with pytest.raises(SnmpError):
        parse.index_str_column(
            [SnmpRow("1.3.6.1.2.1.31.1.1.1.1.x", "eth", "OCTETSTR")],
            "1.3.6.1.2.1.31.1.1.1.1",
        )
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/protocols/snmp/test_parse_ports.py -v`
Expected: FAIL — module `parse` not found.

- [ ] **Step 3: Implement helpers + the two parsers**

```python
# src/netgear_switch/protocols/snmp/parse.py
"""Pure SNMP-row -> models.py parsers. No I/O."""
from __future__ import annotations

from collections.abc import Sequence

from ...models import PortStats, PortStatus
from .client import SnmpError, SnmpRow


def _suffix(row: SnmpRow, base: str) -> str | None:
    prefix = base + "."
    if not row.oid.startswith(prefix):
        return None
    return row.oid[len(prefix):]


def index_int_column(rows: Sequence[SnmpRow], base_oid: str) -> dict[int, int]:
    """Map a single-int-index column walk to {index: int_value}.

    Raises SnmpError on a value that is not an integer under base_oid: the
    walk is pinned to one column, so a non-integer means the table drifted.
    """
    out: dict[int, int] = {}
    for row in rows:
        suffix = _suffix(row, base_oid)
        if suffix is None or "." in suffix:
            continue
        try:
            out[int(suffix)] = int(row.value)
        except ValueError as exc:
            raise SnmpError(
                f"non-integer value {row.value!r} at {row.oid}"
            ) from exc
    return out


def index_str_column(rows: Sequence[SnmpRow], base_oid: str) -> dict[int, str]:
    """Map a single-index column walk to {index: str_value}.

    An absent column (no rows under base_oid) yields an empty dict. But a row
    that IS present under base_oid with a single, non-integer index component is
    table drift, not absence, and raises SnmpError naming the offending OID —
    consistent with index_int_column. (A multi-component suffix belongs to a
    different, deeper column and is skipped.)
    """
    out: dict[int, str] = {}
    for row in rows:
        suffix = _suffix(row, base_oid)
        if suffix is None or "." in suffix:
            continue
        try:
            out[int(suffix)] = row.value
        except ValueError as exc:
            raise SnmpError(
                f"non-integer index {suffix!r} at {row.oid}"
            ) from exc
    return out


def parse_port_status(
    admin: Sequence[SnmpRow],
    oper: Sequence[SnmpRow],
    speed: Sequence[SnmpRow],
    names: Sequence[SnmpRow],
) -> list[PortStatus]:
    from . import oids

    admin_map = index_int_column(admin, oids.IF_ADMIN_STATUS)
    oper_map = index_int_column(oper, oids.IF_OPER_STATUS)
    speed_map = index_int_column(speed, oids.IF_HIGH_SPEED)
    name_map = index_str_column(names, oids.IF_NAME)

    ports = sorted(set(admin_map) | set(oper_map))
    result: list[PortStatus] = []
    for p in ports:
        mbps = speed_map.get(p)
        result.append(
            PortStatus(
                port=p,
                name=name_map.get(p) or None,
                admin_enabled=admin_map.get(p) == 1,
                link_up=oper_map.get(p) == 1,
                speed_mbps=mbps if mbps else None,
            )
        )
    return result


def parse_port_stats(
    *,
    in_octets: Sequence[SnmpRow],
    out_octets: Sequence[SnmpRow],
    in_ucast: Sequence[SnmpRow],
    out_ucast: Sequence[SnmpRow],
    in_errors: Sequence[SnmpRow],
    out_errors: Sequence[SnmpRow],
) -> list[PortStats]:
    from . import oids

    rx_b = index_int_column(in_octets, oids.IF_HC_IN_OCTETS)
    tx_b = index_int_column(out_octets, oids.IF_HC_OUT_OCTETS)
    rx_p = index_int_column(in_ucast, oids.IF_HC_IN_UCAST)
    tx_p = index_int_column(out_ucast, oids.IF_HC_OUT_UCAST)
    rx_e = index_int_column(in_errors, oids.IF_IN_ERRORS)
    tx_e = index_int_column(out_errors, oids.IF_OUT_ERRORS)

    ports = sorted(set(rx_b) | set(tx_b) | set(rx_p) | set(tx_p)
                   | set(rx_e) | set(tx_e))
    return [
        PortStats(
            port=p,
            rx_bytes=rx_b.get(p),
            tx_bytes=tx_b.get(p),
            rx_packets=rx_p.get(p),
            tx_packets=tx_p.get(p),
            rx_errors=rx_e.get(p),
            tx_errors=tx_e.get(p),
        )
        for p in ports
    ]
```

- [ ] **Step 4: Run test + gates**

Run: `uv run pytest tests/protocols/snmp/test_parse_ports.py -v && uv run mypy --strict src && uv run ruff check`
Expected: PASS; clean.

- [ ] **Step 5: Commit**

```bash
git add src/netgear_switch/protocols/snmp/parse.py \
  tests/protocols/snmp/test_parse_ports.py tests/fixtures/snmp/gsm7252ps_ifoperstatus.txt \
  tests/fixtures/snmp/gsm7252ps_ifhighspeed.txt
git commit -m "feat(snmp): pure port-status and port-stats parsers"
```

---

### Task 6: `parse.py` — VLAN static table (bitmap decode) + PVID

Add VLAN parsing (name + egress/untagged bitmaps → `VLANInfo`) and PVID parsing. Bitmap decode lifted from `bridge.py::_bitmap_to_ports` (bit 7 of byte 0 = port 1). VLAN name/egress/untagged join lifted from `bridge.py::bridge_to_switch_data`, with `untagged_ports` and `tagged_ports = member − untagged` both populated (foundation `VLANInfo` has all three fields).

**Files:**
- Modify: `src/netgear_switch/protocols/snmp/parse.py`
- Test: `tests/protocols/snmp/test_parse_vlans.py`

**Interfaces:**
- Consumes: `SnmpRow`, `oids`, `models.VLANInfo`.
- Produces:
  - `decode_port_bitmap(bitmap: str) -> frozenset[int]` — `bitmap` is the OCTET STRING value as a latin-1 string; returns 1-based ports.
  - `parse_vlans(names, egress, untagged) -> list[VLANInfo]` — each `Sequence[SnmpRow]`; sorted by vlan_id; `member_ports` from egress, `untagged_ports` from untagged, `tagged_ports = member − untagged`.
  - `parse_pvids(rows) -> list[tuple[int, int]]` — `(port, vlan_id)` sorted by port.

Note on bitmap value form: ezsnmp and the pysnmp face both surface OCTET STRING bitmaps as a str whose chars are the byte values (latin-1). `decode_port_bitmap` encodes back via `bitmap.encode("latin-1")`.

- [ ] **Step 1: Write the failing test**

```python
# tests/protocols/snmp/test_parse_vlans.py
from __future__ import annotations

import pytest

from netgear_switch.protocols.snmp import parse
from netgear_switch.protocols.snmp.client import SnmpError, SnmpRow


def test_decode_port_bitmap_bit7_is_port1():
    # 0b10100000 -> ports 1 and 3
    assert parse.decode_port_bitmap(chr(0b10100000)) == frozenset({1, 3})
    # second byte, bit7 -> port 9
    assert parse.decode_port_bitmap(chr(0) + chr(0b10000000)) == frozenset({9})
    assert parse.decode_port_bitmap("") == frozenset()


def test_parse_vlans_joins_names_egress_untagged():
    names = [SnmpRow("1.3.6.1.2.1.17.7.1.4.3.1.1.5", "net", "OCTETSTR")]
    # egress ports 1,2 ; untagged port 2  -> tagged {1}, untagged {2}
    egress = [SnmpRow("1.3.6.1.2.1.17.7.1.4.3.1.2.5", chr(0b11000000), "OCTETSTR")]
    untag = [SnmpRow("1.3.6.1.2.1.17.7.1.4.3.1.4.5", chr(0b01000000), "OCTETSTR")]
    vlans = parse.parse_vlans(names, egress, untag)
    assert len(vlans) == 1
    v = vlans[0]
    assert v.vlan_id == 5 and v.name == "net"
    assert v.member_ports == frozenset({1, 2})
    assert v.untagged_ports == frozenset({2})
    assert v.tagged_ports == frozenset({1})


def test_parse_pvids_sorted_port_vlan_pairs():
    rows = [
        SnmpRow("1.3.6.1.2.1.17.7.1.4.5.1.1.2", "90", "Gauge32"),
        SnmpRow("1.3.6.1.2.1.17.7.1.4.5.1.1.1", "90", "Gauge32"),
    ]
    assert parse.parse_pvids(rows) == [(1, 90), (2, 90)]


def test_parse_vlans_raises_on_present_but_malformed_index():
    names = [SnmpRow("1.3.6.1.2.1.17.7.1.4.3.1.1.5", "net", "OCTETSTR")]
    # egress row IS present but its VLAN index is non-numeric -> SnmpError.
    egress = [SnmpRow("1.3.6.1.2.1.17.7.1.4.3.1.2.x", chr(0b11000000), "OCTETSTR")]
    with pytest.raises(SnmpError):
        parse.parse_vlans(names, egress, [])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/protocols/snmp/test_parse_vlans.py -v`
Expected: FAIL — `decode_port_bitmap` undefined.

- [ ] **Step 3: Implement in `parse.py`**

Add `from ...models import VLANInfo` to the imports, then:
```python
def decode_port_bitmap(bitmap: str) -> frozenset[int]:
    """Decode an SNMP VLAN port bitmap. Bit 7 of byte 0 = port 1.

    An empty string is a legitimately absent bitmap -> no ports. A non-empty
    value that is not a valid latin-1 byte string is malformed and raises
    SnmpError naming the value.
    """
    if not bitmap:
        return frozenset()
    try:
        data = bitmap.encode("latin-1")
    except UnicodeEncodeError as exc:
        raise SnmpError(f"malformed VLAN port bitmap {bitmap!r}") from exc
    ports: set[int] = set()
    for byte_idx, byte_val in enumerate(data):
        for bit in range(8):
            if byte_val & (0x80 >> bit):
                ports.add(byte_idx * 8 + bit + 1)
    return frozenset(ports)


def _vlan_bitmap_map(rows: Sequence[SnmpRow], base_oid: str) -> dict[int, str]:
    """{vlan_id: bitmap_value} for a VLAN bitmap column.

    A row absent from the column is skipped; a row present under base_oid whose
    VLAN index is non-numeric is drift and raises SnmpError naming the OID.
    """
    out: dict[int, str] = {}
    for row in rows:
        s = _suffix(row, base_oid)
        if s is None:
            continue
        if not s.isdigit():
            raise SnmpError(f"malformed VLAN index {s!r} at {row.oid}")
        out[int(s)] = row.value
    return out


def parse_vlans(
    names: Sequence[SnmpRow],
    egress: Sequence[SnmpRow],
    untagged: Sequence[SnmpRow],
) -> list[VLANInfo]:
    from . import oids

    name_map = index_str_column(names, oids.DOT1Q_VLAN_STATIC_NAME)
    egress_map = _vlan_bitmap_map(egress, oids.DOT1Q_VLAN_STATIC_EGRESS)
    untag_map = _vlan_bitmap_map(untagged, oids.DOT1Q_VLAN_STATIC_UNTAGGED)
    result: list[VLANInfo] = []
    for vid in sorted(name_map):
        member = decode_port_bitmap(egress_map.get(vid, ""))
        untag = decode_port_bitmap(untag_map.get(vid, ""))
        result.append(
            VLANInfo(
                vlan_id=vid,
                name=name_map.get(vid) or None,
                member_ports=member,
                tagged_ports=member - untag,
                untagged_ports=untag,
            )
        )
    return result


def parse_pvids(rows: Sequence[SnmpRow]) -> list[tuple[int, int]]:
    from . import oids

    pvids = index_int_column(rows, oids.DOT1Q_PVID)
    return sorted(pvids.items())
```

- [ ] **Step 4: Run test + gates**

Run: `uv run pytest tests/protocols/snmp/test_parse_vlans.py -v && uv run mypy --strict src && uv run ruff check`
Expected: PASS; clean.

- [ ] **Step 5: Commit**

```bash
git add src/netgear_switch/protocols/snmp/parse.py tests/protocols/snmp/test_parse_vlans.py
git commit -m "feat(snmp): VLAN static-table (bitmap decode) and PVID parsers"
```

---

### Task 7: `parse.py` — LLDP neighbours + MAC table

Add LLDP remote-table grouping (columns 5/7/8/9 → `LLDPNeighbor`) and MAC/FDB parsing (`dot1qTpFdbPort` + `dot1dBasePortIfIndex` → `MacEntry`). Both lifted from `bridge.py::parse_lldp_neighbors` / `parse_mac_table`, honouring the issue-#10 fix (walk pinned to the FDB *port column*; a non-integer bridge-port value is a hard `SnmpError`).

**Files:**
- Modify: `src/netgear_switch/protocols/snmp/parse.py`
- Test: `tests/protocols/snmp/test_parse_lldp_macs.py`

**Interfaces:**
- Consumes: `SnmpRow`, `oids`, `models.LLDPNeighbor`, `models.MacEntry`.
- Produces:
  - `parse_lldp(rows) -> list[LLDPNeighbor]` — groups `LLDP_REM_TABLE.1.<col>.<timeMark>.<localPort>.<remIdx>`; col5=chassis, col7=portId, col8=portDesc, col9=sysName; `local_port` = middle index component; sorted by `local_port`; skips fully-empty neighbours; chassis formatted as `XX:XX:...` when a 6-byte value, else raw.
  - `parse_macs(fdb, bridge_ports) -> list[MacEntry]` — `fdb` and `bridge_ports` are `Sequence[SnmpRow]`; suffix `<vlan>.<6 MAC bytes>`; `port` = `dot1dBasePortIfIndex[bridge_port]` (falls back to bridge_port if unmapped); raises `SnmpError` on non-integer port value; sorted by `(port, mac)`.
  - private `_format_mac_bytes`, `_format_chassis_id` helpers.

- [ ] **Step 1: Write the failing test**

```python
# tests/protocols/snmp/test_parse_lldp_macs.py
from __future__ import annotations

import pytest

from netgear_switch.protocols.snmp import parse
from netgear_switch.protocols.snmp.client import SnmpError, SnmpRow


def test_parse_lldp_groups_columns_by_local_port():
    base = "1.0.8802.1.1.2.1.4.1.1"
    rows = [
        SnmpRow(f"{base}.9.75.49.7", "sw-cisco-shed", "OCTETSTR"),
        SnmpRow(f"{base}.8.75.49.7", "eth0", "OCTETSTR"),
        SnmpRow(f"{base}.7.75.49.7", "1/xg51", "OCTETSTR"),
    ]
    n = parse.parse_lldp(rows)
    assert len(n) == 1
    assert n[0].local_port == 49
    assert n[0].remote_sys_name == "sw-cisco-shed"
    assert n[0].remote_port_desc == "eth0"


def test_parse_macs_maps_bridge_port_to_ifindex():
    fdb_base = "1.3.6.1.2.1.17.7.1.2.2.1.2"
    fdb = [SnmpRow(f"{fdb_base}.90.200.0.132.137.113.112", "10", "INTEGER")]
    bridge = [SnmpRow("1.3.6.1.2.1.17.1.4.1.2.10", "24", "INTEGER")]  # bridge 10 -> if 24
    macs = parse.parse_macs(fdb, bridge)
    assert len(macs) == 1
    assert macs[0].mac == "C8:00:84:89:71:70"
    assert macs[0].vlan_id == 90
    assert macs[0].port == 24


def test_parse_macs_raises_on_non_integer_port():
    fdb_base = "1.3.6.1.2.1.17.7.1.2.2.1.2"
    bad = [SnmpRow(f"{fdb_base}.1.1.2.3.4.5.6", "learned", "OCTETSTR")]
    with pytest.raises(SnmpError):
        parse.parse_macs(bad, [])


def test_parse_lldp_raises_on_present_but_malformed_local_port():
    base = "1.0.8802.1.1.2.1.4.1.1"
    # Row IS present with a non-empty sysName column but a non-integer local port.
    rows = [SnmpRow(f"{base}.9.75.xx.7", "sw-cisco-shed", "OCTETSTR")]
    with pytest.raises(SnmpError):
        parse.parse_lldp(rows)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/protocols/snmp/test_parse_lldp_macs.py -v`
Expected: FAIL — `parse_lldp` undefined.

- [ ] **Step 3: Implement in `parse.py`**

Add `from ...models import LLDPNeighbor, MacEntry`. Then:
```python
def _format_mac_bytes(byte_strs: Sequence[str]) -> str:
    return ":".join(f"{int(b):02X}" for b in byte_strs)


def _format_chassis_id(value: str) -> str:
    if len(value) == 6:  # raw 6-byte OCTET STRING
        return ":".join(f"{ord(c):02X}" for c in value)
    return value


def parse_lldp(rows: Sequence[SnmpRow]) -> list[LLDPNeighbor]:
    from . import oids

    prefix = oids.LLDP_REM_TABLE + ".1."
    grouped: dict[tuple[str, str, str], dict[int, str]] = {}
    for row in rows:
        if not row.oid.startswith(prefix):
            continue
        parts = row.oid[len(prefix):].split(".")
        # A row present under the lldpRemTable prefix but structurally too short
        # to carry (column, timeMark, localPort, remIdx) is drift, not absence.
        if len(parts) < 4:
            raise SnmpError(f"malformed LLDP index at {row.oid}")
        try:
            column = int(parts[0])
        except ValueError as exc:
            raise SnmpError(
                f"non-integer LLDP column {parts[0]!r} at {row.oid}"
            ) from exc
        key = (parts[1], parts[2], parts[3])  # timeMark, localPort, remIdx
        grouped.setdefault(key, {})[column] = row.value

    result: list[LLDPNeighbor] = []
    for (_tm, local_port, _rem), cols in grouped.items():
        chassis = cols.get(5, "")
        port_id = cols.get(7, "")
        port_desc = cols.get(8, "")
        sys_name = cols.get(9, "")
        # A neighbour row group with every column empty carries no data (absent);
        # skip it. A present-but-non-integer local-port index is drift -> raise.
        if not (chassis or port_id or port_desc or sys_name):
            continue
        try:
            lp = int(local_port)
        except ValueError as exc:
            raise SnmpError(
                f"non-integer LLDP local port {local_port!r} at {prefix}...{local_port}"
            ) from exc
        result.append(
            LLDPNeighbor(
                local_port=lp,
                remote_sys_name=sys_name or None,
                remote_port_desc=port_desc or None,
                remote_chassis_id=_format_chassis_id(chassis) or None,
            )
        )
    return sorted(result, key=lambda n: n.local_port)


def parse_macs(
    fdb: Sequence[SnmpRow], bridge_ports: Sequence[SnmpRow]
) -> list[MacEntry]:
    from . import oids

    bridge_to_if = index_int_column(bridge_ports, oids.DOT1D_BASE_PORT_IF_INDEX)
    prefix = oids.DOT1Q_TP_FDB_PORT + "."
    result: list[MacEntry] = []
    for row in fdb:
        if not row.oid.startswith(prefix):
            continue
        parts = row.oid[len(prefix):].split(".")
        if len(parts) != 7:  # <vlan>.<6 MAC bytes>
            continue
        try:
            vlan_id = int(parts[0])
        except ValueError:
            continue
        try:
            bridge_port = int(row.value)
        except ValueError as exc:
            raise SnmpError(
                f"non-integer bridge port {row.value!r} at {row.oid}"
            ) from exc
        port = bridge_to_if.get(bridge_port, bridge_port)
        result.append(
            MacEntry(mac=_format_mac_bytes(parts[1:7]), port=port, vlan_id=vlan_id)
        )
    return sorted(result, key=lambda m: (m.port, m.mac))
```

- [ ] **Step 4: Run test + gates**

Run: `uv run pytest tests/protocols/snmp/test_parse_lldp_macs.py -v && uv run mypy --strict src && uv run ruff check`
Expected: PASS; clean.

- [ ] **Step 5: Commit**

```bash
git add src/netgear_switch/protocols/snmp/parse.py tests/protocols/snmp/test_parse_lldp_macs.py
git commit -m "feat(snmp): LLDP-neighbour and MAC/FDB parsers"
```

---

### Task 8: `parse.py` — PoE status (RFC3621 + vendor mW) + sensors (box walk)

Add PoE parsing (RFC3621 `pethPsePortTable` admin col3 / detect col6, joined with vendor per-port mW) → `PoEStatus`, and box-sensor parsing (walk-discovered fan/temp/PSU, skip literal `"Not Supported"`) → `Sensor`. Lifted from `bridge.py::parse_poe_status` / `parse_poe_power` / `parse_box_sensors`. Honour the hard-won RFC3621 column fix: **admin = column 3, detect = column 6** (never column 1).

**Files:**
- Modify: `src/netgear_switch/protocols/snmp/parse.py`
- Create: `tests/fixtures/snmp/gsm7252ps_fans.txt`, `gsm7252ps_psu.txt` (hand-copied).
- Test: `tests/protocols/snmp/test_parse_poe_sensors.py`

**Interfaces:**
- Consumes: `SnmpRow`, `oids`, `models.PoEStatus`, `models.PoEDetect`, `models.Sensor`.
- Produces:
  - `DETECT_MAP: dict[int, PoEDetect]` = `{1:DISABLED, 2:SEARCHING, 3:DELIVERING, 4:FAULT}` (other → `UNKNOWN`).
  - `parse_poe(status, power_mw) -> list[PoEStatus]` — `status` walk of `PETH_PSE_PORT_TABLE`, `power_mw` walk of vendor `POE_POWER_MW`; groups status by `(group, port)` on columns 3/6; raises `SnmpError` if a port is missing col3 or col6; `power_mw` matched by port index (2nd suffix component); a port without a vendor mW row gets `power_mw=None`; sorted by port.
  - `parse_box_sensors(rows_by_kind: Sequence[tuple[str, str, Sequence[SnmpRow]]]) -> list[Sensor]` — each tuple `(kind, unit, rows)` with `rows` the walk of one vendor column; skips `"Not Supported"`; raises `SnmpError` on any other non-integer; `name = f"{kind}{instance}"` where `instance` is the OID suffix under the column; `value = float(int(...))`.

- [ ] **Step 1: Write the failing test**

```python
# tests/protocols/snmp/test_parse_poe_sensors.py
from __future__ import annotations

import pytest

from netgear_switch.models import PoEDetect
from netgear_switch.protocols.snmp import parse
from netgear_switch.protocols.snmp.client import SnmpError, SnmpRow


def test_parse_poe_uses_col3_admin_col6_detect_and_vendor_mw():
    tbl = "1.3.6.1.2.1.105.1.1.1"
    status = [
        SnmpRow(f"{tbl}.3.1.1", "1", "INTEGER"),  # admin enabled
        SnmpRow(f"{tbl}.6.1.1", "3", "INTEGER"),  # delivering
        SnmpRow(f"{tbl}.3.1.2", "2", "INTEGER"),  # admin disabled
        SnmpRow(f"{tbl}.6.1.2", "1", "INTEGER"),  # disabled/unused
    ]
    power = [
        SnmpRow("1.3.6.1.4.1.4526.10.15.1.1.1.2.1.1", "12800", "Gauge32"),
        SnmpRow("1.3.6.1.4.1.4526.10.15.1.1.1.2.1.2", "0", "Gauge32"),
    ]
    poe = parse.parse_poe(status, power)
    assert [p.port for p in poe] == [1, 2]
    assert poe[0].admin_enabled is True
    assert poe[0].detect is PoEDetect.DELIVERING
    assert poe[0].power_mw == 12800
    assert poe[1].admin_enabled is False
    assert poe[1].detect is PoEDetect.DISABLED


def test_parse_poe_missing_detect_column_raises():
    tbl = "1.3.6.1.2.1.105.1.1.1"
    status = [SnmpRow(f"{tbl}.3.1.1", "1", "INTEGER")]  # no col6
    with pytest.raises(SnmpError):
        parse.parse_poe(status, [])


def test_parse_box_sensors_skips_not_supported():
    fan = "1.3.6.1.4.1.4526.10.43.1.6.1.4"
    rows = [
        SnmpRow(f"{fan}.0", "3500", "OCTETSTR"),
        SnmpRow(f"{fan}.1", "Not Supported", "OCTETSTR"),
        SnmpRow(f"{fan}.2", "3450", "OCTETSTR"),
    ]
    sensors = parse.parse_box_sensors([("fan", "RPM", rows)])
    assert [s.name for s in sensors] == ["fan0", "fan2"]
    assert sensors[0].kind == "fan" and sensors[0].unit == "RPM"
    assert sensors[0].value == 3500.0


def test_parse_box_sensors_raises_on_other_non_integer():
    temp = "1.3.6.1.4.1.4526.10.43.1.15.1.3"
    rows = [SnmpRow(f"{temp}.1", "warm", "OCTETSTR")]
    with pytest.raises(SnmpError):
        parse.parse_box_sensors([("temperature", "C", rows)])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/protocols/snmp/test_parse_poe_sensors.py -v`
Expected: FAIL — `parse_poe` undefined.

- [ ] **Step 3: Implement in `parse.py`**

Add `from ...models import PoEDetect, PoEStatus, Sensor`. Then:
```python
DETECT_MAP: dict[int, PoEDetect] = {
    1: PoEDetect.DISABLED,
    2: PoEDetect.SEARCHING,
    3: PoEDetect.DELIVERING,
    4: PoEDetect.FAULT,
}


def parse_poe(
    status: Sequence[SnmpRow], power_mw: Sequence[SnmpRow]
) -> list[PoEStatus]:
    from . import oids

    prefix = oids.PETH_PSE_PORT_TABLE + "."
    cols: dict[tuple[int, int], dict[int, int]] = {}
    for row in status:
        if not row.oid.startswith(prefix):
            continue
        parts = row.oid[len(prefix):].split(".")
        if len(parts) != 3:
            continue
        column = int(parts[0])
        if column not in (3, 6):
            continue
        try:
            key = (int(parts[1]), int(parts[2]))
            cols.setdefault(key, {})[column] = int(row.value)
        except ValueError as exc:
            raise SnmpError(
                f"non-integer PoE value {row.value!r} at {row.oid}"
            ) from exc

    # vendor mW keyed by port index (2nd suffix component)
    mw: dict[int, int] = {}
    for row in power_mw:
        parts = row.oid.split(".")
        try:
            mw[int(parts[-1])] = int(row.value)
        except ValueError:
            continue

    result: list[PoEStatus] = []
    for (_group, port), c in sorted(cols.items()):
        if 3 not in c:
            raise SnmpError(f"PoE port {port} missing admin (col 3)")
        if 6 not in c:
            raise SnmpError(f"PoE port {port} missing detect (col 6)")
        result.append(
            PoEStatus(
                port=port,
                admin_enabled=c[3] == 1,
                detect=DETECT_MAP.get(c[6], PoEDetect.UNKNOWN),
                power_mw=mw.get(port),
            )
        )
    return result


def parse_box_sensors(
    rows_by_kind: Sequence[tuple[str, str, Sequence[SnmpRow]]],
) -> list[Sensor]:
    result: list[Sensor] = []
    for kind, unit, rows in rows_by_kind:
        # derive the column base from the shortest common prefix of the walk
        for row in rows:
            parts = row.oid.split(".")
            instance = parts[-1]
            if row.value == "Not Supported":
                continue
            try:
                value = int(row.value)
            except ValueError as exc:
                raise SnmpError(
                    f"non-integer {kind} reading {row.value!r} at {row.oid}"
                ) from exc
            result.append(
                Sensor(name=f"{kind}{instance}", kind=kind,
                        value=float(value), unit=unit)
            )
    return result
```
(`power_mw` rows are matched by their final OID component, as shown. `oids`
stays imported because `parse_poe` still references `oids.PETH_PSE_PORT_TABLE`.)

- [ ] **Step 4: Run test + gates**

Run: `uv run pytest tests/protocols/snmp/test_parse_poe_sensors.py -v && uv run mypy --strict src && uv run ruff check`
Expected: PASS; clean.

- [ ] **Step 5: Commit**

```bash
git add src/netgear_switch/protocols/snmp/parse.py \
  tests/protocols/snmp/test_parse_poe_sensors.py \
  tests/fixtures/snmp/gsm7252ps_fans.txt tests/fixtures/snmp/gsm7252ps_psu.txt
git commit -m "feat(snmp): PoE (RFC3621 + vendor mW) and box-sensor parsers"
```

---

### Task 9: `parse.py` — management-IP config

Add `parse_mgmt_ip`: read the standard `ipAddrTable` for address+netmask, `ipRouteTable` for the default gateway (`ipRouteNextHop` where `ipRouteDest = 0.0.0.0`), and derive `IpMode` from the Netgear DHCP-mode vendor row when present (else `UNKNOWN`). The virtual face serves whatever OIDs the parser reads, so the read path is self-consistent under test; the vendor DHCP-mode OID is the single named `VendorOids.dhcp_mode_unverified` constant (Task 4), flagged for hardware confirmation in the capture step (Self-Review RISK 3). Reading the mode is best-effort/unverified — `parse_mgmt_ip` returns `IpMode.UNKNOWN` whenever the mode OID is absent/unset (never a guessed dhcp/static), while address/netmask/gateway always come from the standard MIBs; **setting** mgmt-IP mode is out of scope for this read-only slice until the OID is verified.

**Files:**
- Modify: `src/netgear_switch/protocols/snmp/parse.py`
- Test: `tests/protocols/snmp/test_parse_mgmt_ip.py`

**Interfaces:**
- Consumes: `SnmpRow`, `oids`, `models.MgmtIpConfig`, `models.IpMode`.
- Produces: `parse_mgmt_ip(addr, netmask, route_dest, route_nexthop, dhcp_mode) -> MgmtIpConfig` — args are `Sequence[SnmpRow]`; picks the first non-loopback `ipAdEntAddr` (skip `127.0.0.1`); `netmask` matched by the IP index in the `ipAdEntNetMask` walk; `gateway` = `ipRouteNextHop` value whose `ipRouteDest` row value is `"0.0.0.0"`; `mode` = `DHCP` if any `dhcp_mode` row value is `"1"`, `STATIC` if `"2"`, else `UNKNOWN`.

- [ ] **Step 1: Write the failing test**

```python
# tests/protocols/snmp/test_parse_mgmt_ip.py
from __future__ import annotations

from netgear_switch.models import IpMode
from netgear_switch.protocols.snmp import oids, parse
from netgear_switch.protocols.snmp.client import SnmpRow
from netgear_switch.registry import get_model

# The DHCP-mode OID comes from the ONE named constant, never a bare .99.1 literal.
_DHCP_MODE_OID = f"{oids.vendor_oids(get_model('gsm7252ps')).dhcp_mode_unverified}.0"


def test_parse_mgmt_ip_static_with_gateway():
    addr = [
        SnmpRow("1.3.6.1.2.1.4.20.1.1.127.0.0.1", "127.0.0.1", "IPADDR"),
        SnmpRow("1.3.6.1.2.1.4.20.1.1.10.1.5.20", "10.1.5.20", "IPADDR"),
    ]
    netmask = [
        SnmpRow("1.3.6.1.2.1.4.20.1.3.10.1.5.20", "255.255.255.0", "IPADDR"),
    ]
    route_dest = [SnmpRow("1.3.6.1.2.1.4.21.1.1.0.0.0.0", "0.0.0.0", "IPADDR")]
    route_next = [SnmpRow("1.3.6.1.2.1.4.21.1.7.0.0.0.0", "10.1.5.1", "IPADDR")]
    dhcp = [SnmpRow(_DHCP_MODE_OID, "2", "INTEGER")]  # static

    cfg = parse.parse_mgmt_ip(addr, netmask, route_dest, route_next, dhcp)
    assert cfg.address == "10.1.5.20"
    assert cfg.netmask == "255.255.255.0"
    assert cfg.gateway == "10.1.5.1"
    assert cfg.mode is IpMode.STATIC


def test_parse_mgmt_ip_dhcp_and_unknown_default():
    addr = [SnmpRow("1.3.6.1.2.1.4.20.1.1.10.1.5.20", "10.1.5.20", "IPADDR")]
    cfg = parse.parse_mgmt_ip(
        addr, [], [], [],
        [SnmpRow(_DHCP_MODE_OID, "1", "INTEGER")],
    )
    assert cfg.mode is IpMode.DHCP
    # Mode OID absent -> UNKNOWN (never a guessed dhcp/static), gateway None.
    cfg2 = parse.parse_mgmt_ip(addr, [], [], [], [])
    assert cfg2.mode is IpMode.UNKNOWN
    assert cfg2.gateway is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/protocols/snmp/test_parse_mgmt_ip.py -v`
Expected: FAIL — `parse_mgmt_ip` undefined.

- [ ] **Step 3: Implement in `parse.py`**

Add `from ...models import IpMode, MgmtIpConfig`. Then:
```python
def parse_mgmt_ip(
    addr: Sequence[SnmpRow],
    netmask: Sequence[SnmpRow],
    route_dest: Sequence[SnmpRow],
    route_nexthop: Sequence[SnmpRow],
    dhcp_mode: Sequence[SnmpRow],
) -> MgmtIpConfig:
    from . import oids

    ip: str | None = None
    ip_index: str | None = None
    aprefix = oids.IP_ADENT_ADDR + "."
    for row in addr:
        if not row.oid.startswith(aprefix):
            continue
        if row.value == "127.0.0.1":
            continue
        ip = row.value
        ip_index = row.oid[len(aprefix):]
        break

    mask: str | None = None
    if ip_index is not None:
        want = oids.IP_ADENT_NETMASK + "." + ip_index
        mask = next((r.value for r in netmask if r.oid == want), None)

    dest_rows = {
        r.oid[len(oids.IP_ROUTE_DEST) + 1:]: r.value for r in route_dest
    }
    gateway: str | None = None
    nprefix = oids.IP_ROUTE_NEXTHOP + "."
    for row in route_nexthop:
        if not row.oid.startswith(nprefix):
            continue
        idx = row.oid[len(nprefix):]
        if dest_rows.get(idx) == "0.0.0.0":
            gateway = row.value
            break

    mode = IpMode.UNKNOWN
    for row in dhcp_mode:
        if row.value == "1":
            mode = IpMode.DHCP
        elif row.value == "2":
            mode = IpMode.STATIC
        break

    return MgmtIpConfig(mode=mode, address=ip, netmask=mask, gateway=gateway)
```

- [ ] **Step 4: Run test + gates**

Run: `uv run pytest tests/protocols/snmp/test_parse_mgmt_ip.py -v && uv run mypy --strict src && uv run ruff check`
Expected: PASS; clean.

- [ ] **Step 5: Commit**

```bash
git add src/netgear_switch/protocols/snmp/parse.py tests/protocols/snmp/test_parse_mgmt_ip.py
git commit -m "feat(snmp): management-IP config parser"
```

---

### Task 10: Sync SNMP client on ezsnmp

Implement the sync `SnmpClient` on ezsnmp, lifted from the `native-snmp-library` `snmp_client.py` seam, adapted to the shared `SnmpRow`/`SnmpError`/`full_oid` and read-only (`get`/`walk`). ezsnmp is lazy-imported inside the session factory; a test injects a fake session so the C extension never loads on the unit path.

**Files:**
- Create: `src/netgear_switch/transport/__init__.py`, `src/netgear_switch/transport/sync/__init__.py`, `src/netgear_switch/transport/aio/__init__.py`
- Create: `src/netgear_switch/transport/sync/snmp_ezsnmp.py`
- Test: `tests/transport/test_snmp_ezsnmp.py`

**Interfaces:**
- Consumes: `SnmpRow`, `SnmpError`, `full_oid`, `ABSENT_TYPES`.
- Produces:
  - `class EzsnmpClient` implementing `SnmpClient`: `__init__(self, host, community, *, timeout=10, retries=1, session_factory=_default_session_factory)`; `get(oid)`; `walk(oid)`.
  - `_default_session_factory(host, community, timeout, retries)` — lazy `import ezsnmp`.
  - A fake session shape for tests: object with `.get(oid)` / `.walk(oid)` returning objects having `.oid`, `.oid_index`, `.value`, `.snmp_type`.

- [ ] **Step 1: Write the failing test**

```python
# tests/transport/test_snmp_ezsnmp.py
from __future__ import annotations

from dataclasses import dataclass

import pytest

from netgear_switch.protocols.snmp.client import SnmpError
from netgear_switch.transport.sync.snmp_ezsnmp import EzsnmpClient


@dataclass
class _Var:
    oid: str
    oid_index: str
    value: str
    snmp_type: str


class _FakeSession:
    def __init__(self, *_a, **_k):
        pass

    def get(self, oid):
        return _Var("1.3.6.1.2.1.2.2.1.8", "1", "1", "INTEGER")

    def walk(self, oid):
        return [
            _Var("1.3.6.1.2.1.2.2.1.8", "1", "1", "INTEGER"),
            _Var("1.3.6.1.2.1.2.2.1.8", "2", "2", "INTEGER"),
            _Var("1.3.6.1.2.1.2.2.1.8", "3", "", "NOSUCHINSTANCE"),
        ]


def test_get_reconstructs_full_oid():
    c = EzsnmpClient("h", "public", session_factory=_FakeSession)
    row = c.get("1.3.6.1.2.1.2.2.1.8.1")
    assert row is not None and row.oid == "1.3.6.1.2.1.2.2.1.8.1"
    assert row.value == "1"


def test_walk_filters_absent_types():
    c = EzsnmpClient("h", "public", session_factory=_FakeSession)
    rows = c.walk("1.3.6.1.2.1.2.2.1.8")
    assert [r.oid for r in rows] == [
        "1.3.6.1.2.1.2.2.1.8.1",
        "1.3.6.1.2.1.2.2.1.8.2",
    ]


def test_errors_wrap_as_snmp_error():
    class _Boom(_FakeSession):
        def get(self, oid):
            raise RuntimeError("timeout")

    c = EzsnmpClient("h", "public", session_factory=_Boom)
    with pytest.raises(SnmpError):
        c.get("1.3.6.1.2.1.2.2.1.8.1")


def test_ezsnmp_imports_in_this_environment():
    # Blocker guard: the sync backend's C dependency must be importable.
    import ezsnmp  # noqa: F401
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/transport/test_snmp_ezsnmp.py -v`
Expected: FAIL — module `snmp_ezsnmp` not found.

- [ ] **Step 3: Implement the ezsnmp client**

Create the three `transport` marker `__init__.py` files (docstring only). Then:
```python
# src/netgear_switch/transport/sync/snmp_ezsnmp.py
"""Synchronous SNMP v2c client on ezsnmp. ezsnmp is imported lazily."""
from __future__ import annotations

from collections.abc import Callable

from ...protocols.snmp.client import ABSENT_TYPES, SnmpError, SnmpRow, full_oid


def _default_session_factory(
    host: str, community: str, timeout: int, retries: int
) -> object:
    import ezsnmp

    return ezsnmp.Session(
        hostname=host, community=community, version=2,
        timeout=timeout, retries=retries,
        use_numeric=True, use_long_names=True,
    )


class EzsnmpClient:
    """Read-only sync SNMP client. A fresh session is created per call."""

    def __init__(
        self,
        host: str,
        community: str,
        *,
        timeout: int = 10,
        retries: int = 1,
        session_factory: Callable[..., object] = _default_session_factory,
    ) -> None:
        self.host = host
        self.community = community
        self.timeout = timeout
        self.retries = retries
        self._session_factory = session_factory

    def _session(self) -> object:
        return self._session_factory(
            self.host, self.community, self.timeout, self.retries
        )

    def get(self, oid: str) -> SnmpRow | None:
        try:
            v = self._session().get(oid)  # type: ignore[attr-defined]
        except Exception as exc:
            raise SnmpError(f"GET {oid} on {self.host} failed: {exc}") from exc
        if v.snmp_type in ABSENT_TYPES:
            return None
        return SnmpRow(full_oid(v.oid, v.oid_index), v.value, v.snmp_type)

    def walk(self, oid: str) -> list[SnmpRow]:
        try:
            variables = self._session().walk(oid)  # type: ignore[attr-defined]
        except Exception as exc:
            raise SnmpError(f"WALK {oid} on {self.host} failed: {exc}") from exc
        return [
            SnmpRow(full_oid(v.oid, v.oid_index), v.value, v.snmp_type)
            for v in variables
            if v.snmp_type not in ABSENT_TYPES
        ]
```

- [ ] **Step 4: Run test + gates**

Run: `uv run pytest tests/transport/test_snmp_ezsnmp.py -v && uv run mypy --strict src && uv run ruff check`
Expected: PASS; clean.

- [ ] **Step 5: Commit**

```bash
git add src/netgear_switch/transport/__init__.py \
  src/netgear_switch/transport/sync/__init__.py \
  src/netgear_switch/transport/aio/__init__.py \
  src/netgear_switch/transport/sync/snmp_ezsnmp.py \
  tests/transport/test_snmp_ezsnmp.py
git commit -m "feat(transport): sync SNMP read client on ezsnmp"
```

---

### Task 11: Async SNMP client on pysnmp v7

Implement the async `SnmpClient` on pysnmp v7 (asyncio), modelled on `gdoc2netcfg/supplements/snmp_common.py` (`get_cmd` / `bulk_walk_cmd`, `close_dispatcher` in `finally`). pysnmp is lazy-imported. Unit tests inject a fake engine/command layer via a small seam so the async engine never loads on the unit path; a real end-to-end exercise happens in Task 16 against the virtual face.

**Files:**
- Create: `src/netgear_switch/transport/aio/snmp_pysnmp.py`
- Test: `tests/transport/test_snmp_pysnmp.py`

**Interfaces:**
- Consumes: `SnmpRow`, `SnmpError`, `ABSENT_TYPES`.
- Produces:
  - `class PysnmpClient` implementing `AsyncSnmpClient`: `__init__(self, host, community, *, port=161, timeout=2.0, retries=1)`; `async get(oid)`; `async walk(oid)`.
  - A private `async def _do_get(self, oid) -> tuple[str, str, str] | None` and `async def _do_walk(self, oid) -> list[tuple[str, str, str]]` that own all pysnmp calls; the public methods wrap them into `SnmpRow`/`SnmpError`. Tests monkeypatch `_do_get`/`_do_walk` to avoid importing pysnmp.

- [ ] **Step 1: Write the failing test**

```python
# tests/transport/test_snmp_pysnmp.py
from __future__ import annotations

import asyncio

import pytest

from netgear_switch.protocols.snmp.client import SnmpError
from netgear_switch.transport.aio.snmp_pysnmp import PysnmpClient


def test_get_wraps_tuple_into_row(monkeypatch):
    c = PysnmpClient("h", "public")

    async def fake_do_get(oid):
        return ("1.3.6.1.2.1.2.2.1.8.1", "1", "INTEGER")

    monkeypatch.setattr(c, "_do_get", fake_do_get)
    row = asyncio.run(c.get("1.3.6.1.2.1.2.2.1.8.1"))
    assert row is not None and row.oid.endswith(".8.1") and row.value == "1"


def test_walk_filters_absent_and_wraps(monkeypatch):
    c = PysnmpClient("h", "public")

    async def fake_do_walk(oid):
        return [
            ("1.3.6.1.2.1.2.2.1.8.1", "1", "INTEGER"),
            ("1.3.6.1.2.1.2.2.1.8.2", "", "ENDOFMIBVIEW"),
        ]

    monkeypatch.setattr(c, "_do_walk", fake_do_walk)
    rows = asyncio.run(c.walk("1.3.6.1.2.1.2.2.1.8"))
    assert [r.oid for r in rows] == ["1.3.6.1.2.1.2.2.1.8.1"]


def test_get_error_wraps(monkeypatch):
    c = PysnmpClient("h", "public")

    async def boom(oid):
        raise RuntimeError("engine down")

    monkeypatch.setattr(c, "_do_get", boom)
    with pytest.raises(SnmpError):
        asyncio.run(c.get("1.3.6.1.2.1.2.2.1.8.1"))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run --extra async pytest tests/transport/test_snmp_pysnmp.py -v`
Expected: FAIL — module `snmp_pysnmp` not found.

- [ ] **Step 3: Implement the pysnmp client**

```python
# src/netgear_switch/transport/aio/snmp_pysnmp.py
"""Asynchronous SNMP v2c client on pysnmp v7. pysnmp is imported lazily."""
from __future__ import annotations

from ...protocols.snmp.client import ABSENT_TYPES, SnmpError, SnmpRow


class PysnmpClient:
    """Read-only async SNMP client for a single switch."""

    def __init__(
        self,
        host: str,
        community: str,
        *,
        port: int = 161,
        timeout: float = 2.0,
        retries: int = 1,
    ) -> None:
        self.host = host
        self.community = community
        self.port = port
        self.timeout = timeout
        self.retries = retries

    async def _do_get(self, oid: str) -> tuple[str, str, str] | None:
        from pysnmp.hlapi.v3arch.asyncio import (
            CommunityData,
            ContextData,
            ObjectIdentity,
            ObjectType,
            SnmpEngine,
            UdpTransportTarget,
            get_cmd,
        )

        engine = SnmpEngine()
        try:
            target = await UdpTransportTarget.create(
                (self.host, self.port), timeout=self.timeout, retries=self.retries
            )
            err_ind, err_stat, _idx, binds = await get_cmd(
                engine, CommunityData(self.community), target, ContextData(),
                ObjectType(ObjectIdentity(oid)),
            )
            if err_ind or err_stat:
                raise SnmpError(f"GET {oid} on {self.host}: {err_ind or err_stat}")
            vb = binds[0]
            return (str(vb[0]), vb[1].prettyPrint(), vb[1].__class__.__name__)
        finally:
            engine.close_dispatcher()

    async def _do_walk(self, oid: str) -> list[tuple[str, str, str]]:
        from pysnmp.hlapi.v3arch.asyncio import (
            CommunityData,
            ContextData,
            ObjectIdentity,
            ObjectType,
            SnmpEngine,
            UdpTransportTarget,
            bulk_walk_cmd,
        )

        engine = SnmpEngine()
        rows: list[tuple[str, str, str]] = []
        try:
            target = await UdpTransportTarget.create(
                (self.host, self.port), timeout=self.timeout, retries=self.retries
            )
            async for err_ind, err_stat, _idx, binds in bulk_walk_cmd(
                engine, CommunityData(self.community), target, ContextData(),
                0, 25, ObjectType(ObjectIdentity(oid)), lexicographicMode=False,
            ):
                if err_ind or err_stat:
                    break
                for vb in binds:
                    rows.append(
                        (str(vb[0]), vb[1].prettyPrint(), vb[1].__class__.__name__)
                    )
            return rows
        finally:
            engine.close_dispatcher()

    async def get(self, oid: str) -> SnmpRow | None:
        try:
            result = await self._do_get(oid)
        except SnmpError:
            raise
        except Exception as exc:
            raise SnmpError(f"GET {oid} on {self.host} failed: {exc}") from exc
        if result is None:
            return None
        found_oid, value, typ = result
        if typ.upper() in ABSENT_TYPES or value in ABSENT_TYPES:
            return None
        return SnmpRow(found_oid.lstrip("."), value, typ)

    async def walk(self, oid: str) -> list[SnmpRow]:
        try:
            raw = await self._do_walk(oid)
        except Exception as exc:
            raise SnmpError(f"WALK {oid} on {self.host} failed: {exc}") from exc
        return [
            SnmpRow(found.lstrip("."), value, typ)
            for found, value, typ in raw
            if typ.upper() not in ABSENT_TYPES and value not in ABSENT_TYPES
        ]
```

- [ ] **Step 4: Run test + gates**

Run: `uv run --extra async pytest tests/transport/test_snmp_pysnmp.py -v && uv run mypy --strict src && uv run ruff check`
Expected: PASS; clean.

- [ ] **Step 5: Commit**

```bash
git add src/netgear_switch/transport/aio/snmp_pysnmp.py tests/transport/test_snmp_pysnmp.py
git commit -m "feat(transport): async SNMP read client on pysnmp v7"
```

---

### Task 12: SNMP read operations — `SnmpReader` / `AsyncSnmpReader`

Orchestrate: given a client + `SwitchModel`, walk the right OIDs and hand rows to the pure parsers, returning model objects. Backend guard: SNMP is managed-only — `_require_snmp(model)` in `__init__` raises `UnsupportedCapability` for any model without `Backend.SNMP` (i.e. Plus), and that single gate is authoritative. `get_macs` does **not** re-check `has_mac_table`: it duplicates the same condition (`has_mac_table == (Backend.SNMP in backends)`), already enforced at construction. (`registry.has_mac_table` stays for external callers.) Vendor OIDs are resolved lazily — only inside `get_poe`/`get_sensors`/`get_mgmt_ip`, never in `__init__`. The async reader mirrors the sync one, sharing every parser — the only difference is `await`, seeding the sync/async equivalence theme.

**Files:**
- Create: `src/netgear_switch/snmp_read.py`
- Test: `tests/test_snmp_read.py`

**Interfaces:**
- Consumes: `SnmpClient`/`AsyncSnmpClient`, `SnmpRow`, `oids`, `parse`, `registry.SwitchModel`, `registry.Backend`, `errors.UnsupportedCapability`, all model types.
- Produces:
  - `class SnmpReader(client: SnmpClient, model: SwitchModel)` with: `get_ports() -> list[PortStatus]`, `get_stats() -> list[PortStats]`, `get_vlans() -> list[VLANInfo]`, `get_pvids() -> list[tuple[int, int]]`, `get_lldp() -> list[LLDPNeighbor]`, `get_macs() -> list[MacEntry]`, `get_poe() -> list[PoEStatus]`, `get_sensors() -> list[Sensor]`, `get_mgmt_ip() -> MgmtIpConfig`.
  - `class AsyncSnmpReader(client: AsyncSnmpClient, model: SwitchModel)` with the same method names, all `async`.

- [ ] **Step 1: Write the failing test** (uses a fake in-memory client keyed by OID prefix)

```python
# tests/test_snmp_read.py
from __future__ import annotations

import pytest

from netgear_switch.errors import UnsupportedCapability
from netgear_switch.models import PoEDetect
from netgear_switch.protocols.snmp.client import SnmpRow
from netgear_switch.registry import get_model
from netgear_switch.snmp_read import SnmpReader


class FakeClient:
    """Serves canned SnmpRows by longest-matching OID prefix."""

    def __init__(self, tables: dict[str, list[SnmpRow]]):
        self._tables = tables

    def get(self, oid):  # not used by these read paths
        rows = self.walk(oid)
        return rows[0] if rows else None

    def walk(self, oid):
        return list(self._tables.get(oid, []))


def _r(base, pairs, typ="INTEGER"):
    return [SnmpRow(f"{base}.{k}", v, typ) for k, v in pairs.items()]


def test_get_ports_via_reader():
    tables = {
        "1.3.6.1.2.1.2.2.1.7": _r("1.3.6.1.2.1.2.2.1.7", {1: "1"}),
        "1.3.6.1.2.1.2.2.1.8": _r("1.3.6.1.2.1.2.2.1.8", {1: "1"}),
        "1.3.6.1.2.1.31.1.1.1.15": _r("1.3.6.1.2.1.31.1.1.1.15", {1: "1000"}, "Gauge32"),
        "1.3.6.1.2.1.31.1.1.1.1": _r("1.3.6.1.2.1.31.1.1.1.1", {1: "1/0/1"}, "OCTETSTR"),
    }
    r = SnmpReader(FakeClient(tables), get_model("gsm7252ps"))
    ports = r.get_ports()
    assert ports[0].port == 1 and ports[0].speed_mbps == 1000


def test_get_poe_joins_status_and_vendor_mw():
    tbl = "1.3.6.1.2.1.105.1.1.1"
    tables = {
        tbl: [
            SnmpRow(f"{tbl}.3.1.1", "1", "INTEGER"),
            SnmpRow(f"{tbl}.6.1.1", "3", "INTEGER"),
        ],
        "1.3.6.1.4.1.4526.10.15.1.1.1.2": [
            SnmpRow("1.3.6.1.4.1.4526.10.15.1.1.1.2.1.1", "12800", "Gauge32"),
        ],
    }
    r = SnmpReader(FakeClient(tables), get_model("gsm7252ps"))
    poe = r.get_poe()
    assert poe[0].detect is PoEDetect.DELIVERING and poe[0].power_mw == 12800


def test_snmp_reader_rejects_non_snmp_model():
    # The constructor itself is the capability gate for a Plus model, so the
    # construction MUST be inside the raises-block (it never returns a reader).
    with pytest.raises(UnsupportedCapability):
        SnmpReader(FakeClient({}), get_model("gs110emx"))  # Plus, no SNMP backend


def test_snmp_reader_constructs_for_managed_model():
    # Positive control: a managed model constructs fine and is usable.
    reader = SnmpReader(FakeClient({}), get_model("gsm7252ps"))
    assert reader.model.key == "gsm7252ps"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_snmp_read.py -v`
Expected: FAIL — module `snmp_read` not found.

- [ ] **Step 3: Implement `snmp_read.py`**

```python
# src/netgear_switch/snmp_read.py
"""Model-driven SNMP read operations over a sync or async client."""
from __future__ import annotations

from .errors import UnsupportedCapability
from .models import (
    LLDPNeighbor,
    MacEntry,
    MgmtIpConfig,
    PoEStatus,
    PortStats,
    PortStatus,
    Sensor,
    VLANInfo,
)
from .protocols.snmp import oids, parse
from .protocols.snmp.client import AsyncSnmpClient, SnmpClient
from .registry import Backend, SwitchModel


def _require_snmp(model: SwitchModel) -> None:
    if Backend.SNMP not in model.backends:
        raise UnsupportedCapability(f"model {model.key!r} has no SNMP backend")


class SnmpReader:
    def __init__(self, client: SnmpClient, model: SwitchModel) -> None:
        # _require_snmp is the single capability gate: it raises for any model
        # without an SNMP backend (i.e. Plus). Vendor OIDs are resolved lazily,
        # only in the ops that need the vendor subtree (get_poe/get_sensors/
        # get_mgmt_ip), so constructing a reader never touches vendor_oids.
        _require_snmp(model)
        self.client = client
        self.model = model

    def get_ports(self) -> list[PortStatus]:
        w = self.client.walk
        return parse.parse_port_status(
            w(oids.IF_ADMIN_STATUS), w(oids.IF_OPER_STATUS),
            w(oids.IF_HIGH_SPEED), w(oids.IF_NAME),
        )

    def get_stats(self) -> list[PortStats]:
        w = self.client.walk
        return parse.parse_port_stats(
            in_octets=w(oids.IF_HC_IN_OCTETS), out_octets=w(oids.IF_HC_OUT_OCTETS),
            in_ucast=w(oids.IF_HC_IN_UCAST), out_ucast=w(oids.IF_HC_OUT_UCAST),
            in_errors=w(oids.IF_IN_ERRORS), out_errors=w(oids.IF_OUT_ERRORS),
        )

    def get_vlans(self) -> list[VLANInfo]:
        w = self.client.walk
        return parse.parse_vlans(
            w(oids.DOT1Q_VLAN_STATIC_NAME), w(oids.DOT1Q_VLAN_STATIC_EGRESS),
            w(oids.DOT1Q_VLAN_STATIC_UNTAGGED),
        )

    def get_pvids(self) -> list[tuple[int, int]]:
        return parse.parse_pvids(self.client.walk(oids.DOT1Q_PVID))

    def get_lldp(self) -> list[LLDPNeighbor]:
        return parse.parse_lldp(self.client.walk(oids.LLDP_REM_TABLE))

    def get_macs(self) -> list[MacEntry]:
        # No has_mac_table guard here: has_mac_table == (Backend.SNMP in
        # backends), which __init__'s _require_snmp already enforced. (The
        # registry.has_mac_table property stays for external callers.)
        w = self.client.walk
        return parse.parse_macs(
            w(oids.DOT1Q_TP_FDB_PORT), w(oids.DOT1D_BASE_PORT_IF_INDEX)
        )

    def get_poe(self) -> list[PoEStatus]:
        vendor = oids.vendor_oids(self.model)
        w = self.client.walk
        return parse.parse_poe(
            w(oids.PETH_PSE_PORT_TABLE), w(vendor.poe_power_mw)
        )

    def get_sensors(self) -> list[Sensor]:
        vendor = oids.vendor_oids(self.model)
        w = self.client.walk
        columns = [
            ("fan", "RPM", w(vendor.box_fan)),
            ("power", "W", w(vendor.box_psu_power)),
            ("temperature", "C", w(vendor.box_temp)),
        ]
        return parse.parse_box_sensors(columns)

    def get_mgmt_ip(self) -> MgmtIpConfig:
        vendor = oids.vendor_oids(self.model)
        w = self.client.walk
        return parse.parse_mgmt_ip(
            w(oids.IP_ADENT_ADDR), w(oids.IP_ADENT_NETMASK),
            w(oids.IP_ROUTE_DEST), w(oids.IP_ROUTE_NEXTHOP),
            w(vendor.dhcp_mode_unverified),  # single named UNVERIFIED OID (Task 4)
        )


class AsyncSnmpReader:
    def __init__(self, client: AsyncSnmpClient, model: SwitchModel) -> None:
        # Same contract as SnmpReader: _require_snmp gates construction; vendor
        # OIDs resolved lazily in get_poe/get_sensors/get_mgmt_ip only.
        _require_snmp(model)
        self.client = client
        self.model = model

    async def get_ports(self) -> list[PortStatus]:
        w = self.client.walk
        return parse.parse_port_status(
            await w(oids.IF_ADMIN_STATUS), await w(oids.IF_OPER_STATUS),
            await w(oids.IF_HIGH_SPEED), await w(oids.IF_NAME),
        )

    async def get_stats(self) -> list[PortStats]:
        w = self.client.walk
        return parse.parse_port_stats(
            in_octets=await w(oids.IF_HC_IN_OCTETS),
            out_octets=await w(oids.IF_HC_OUT_OCTETS),
            in_ucast=await w(oids.IF_HC_IN_UCAST),
            out_ucast=await w(oids.IF_HC_OUT_UCAST),
            in_errors=await w(oids.IF_IN_ERRORS),
            out_errors=await w(oids.IF_OUT_ERRORS),
        )

    async def get_vlans(self) -> list[VLANInfo]:
        w = self.client.walk
        return parse.parse_vlans(
            await w(oids.DOT1Q_VLAN_STATIC_NAME),
            await w(oids.DOT1Q_VLAN_STATIC_EGRESS),
            await w(oids.DOT1Q_VLAN_STATIC_UNTAGGED),
        )

    async def get_pvids(self) -> list[tuple[int, int]]:
        return parse.parse_pvids(await self.client.walk(oids.DOT1Q_PVID))

    async def get_lldp(self) -> list[LLDPNeighbor]:
        return parse.parse_lldp(await self.client.walk(oids.LLDP_REM_TABLE))

    async def get_macs(self) -> list[MacEntry]:
        # No has_mac_table guard: _require_snmp in __init__ already enforced it.
        w = self.client.walk
        return parse.parse_macs(
            await w(oids.DOT1Q_TP_FDB_PORT),
            await w(oids.DOT1D_BASE_PORT_IF_INDEX),
        )

    async def get_poe(self) -> list[PoEStatus]:
        vendor = oids.vendor_oids(self.model)
        w = self.client.walk
        return parse.parse_poe(
            await w(oids.PETH_PSE_PORT_TABLE), await w(vendor.poe_power_mw)
        )

    async def get_sensors(self) -> list[Sensor]:
        vendor = oids.vendor_oids(self.model)
        w = self.client.walk
        columns = [
            ("fan", "RPM", await w(vendor.box_fan)),
            ("power", "W", await w(vendor.box_psu_power)),
            ("temperature", "C", await w(vendor.box_temp)),
        ]
        return parse.parse_box_sensors(columns)

    async def get_mgmt_ip(self) -> MgmtIpConfig:
        vendor = oids.vendor_oids(self.model)
        w = self.client.walk
        return parse.parse_mgmt_ip(
            await w(oids.IP_ADENT_ADDR), await w(oids.IP_ADENT_NETMASK),
            await w(oids.IP_ROUTE_DEST), await w(oids.IP_ROUTE_NEXTHOP),
            await w(vendor.dhcp_mode_unverified),  # single named UNVERIFIED OID
        )
```

- [ ] **Step 4: Run test + gates**

Run: `uv run pytest tests/test_snmp_read.py -v && uv run mypy --strict src && uv run ruff check`
Expected: PASS; clean.

- [ ] **Step 5: Commit**

```bash
git add src/netgear_switch/snmp_read.py tests/test_snmp_read.py
git commit -m "feat(snmp): SnmpReader/AsyncSnmpReader model-driven read ops"
```

---

### Task 13: Virtual switch state + `gsm7252ps` seed

Create the single authoritative `VirtualSwitchState` and a hand-authored seed for the `gsm7252ps` managed model (realistic ports/vlans/poe/sensors/mgmt-ip). The state exposes a flat, ordered OID→value map (the face reads it directly); this task tests the seed produces a coherent, non-empty map with correct example OIDs.

**Files:**
- Create: `src/netgear_switch/virtual/__init__.py`, `src/netgear_switch/virtual/state.py`, `src/netgear_switch/virtual/seed.py`, `src/netgear_switch/virtual/faces/__init__.py`
- Test: `tests/virtual/test_state_seed.py`

**Interfaces:**
- Consumes: `oids`, `registry.get_model`.
- Produces:
  - `@dataclass class VirtualSwitchState`: mutable holder with `ports: dict[int, PortSim]`, `vlans: dict[int, VlanSim]`, `pvids: dict[int, int]`, `poe: dict[int, PoeSim]`, `sensors: list[SensorSim]`, `macs: list[MacSim]`, `bridge_ports: dict[int, int]` (bridge-port → ifIndex), `lldp: list[LldpSim]`, `mgmt: MgmtSim`, plus `model_key: str`. Small `@dataclass` sub-structs (`PortSim`, `VlanSim`, `PoeSim`, `SensorSim`, `MacSim`, `LldpSim`, `MgmtSim`) — these are *internal* mutable sim types, not the frozen public models. `PortSim` carries counters (`rx_octets`/`tx_octets`/`rx_ucast`/`tx_ucast`/`rx_errors`/`tx_errors`, each `int | None`).
  - `VirtualSwitchState.oid_map() -> dict[str, tuple[str, str]]` — full numeric OID → `(snmp_type_token, value_str)`, built from the sim state using the exact OID layouts in `oids.py`. It MUST emit, non-vacuously: ifOperStatus/ifAdminStatus/ifHighSpeed/ifName; **port stats** (ifHCInOctets/ifHCOutOctets + ifHCInUcastPkts/ifHCOutUcastPkts + ifInErrors/ifOutErrors) for the ports that carry counters; dot1q VLAN name+egress+untagged bitmaps+pvid; **MAC/FDB** (`dot1qTpFdbPort` values) **plus** the matching `dot1dBasePortIfIndex` bridge-port→ifIndex rows; **≥1 LLDP** remote-neighbour across `lldpRemTable` columns 5/7/8/9; pethPsePortTable col3/col6; vendor PoE mW; box fan/psu/temp; ipAddrTable/ipRouteTable/DHCP-mode. Bitmaps are built by an inverse of `decode_port_bitmap`.
  - `seed_gsm7252ps() -> VirtualSwitchState` — 52 ports (48 PoE), with realistic RX/TX counters on **at least ports 1 and 2** (HC in/out octets, in/out unicast packets, in/out errors); VLANs `1 "default"`, `90 "iot"` with a couple members, PVIDs; **at least 2 MAC/FDB entries** with their `dot1qTpFdbPort` bridge-port values AND the corresponding `dot1dBasePortIfIndex` mappings; **at least 1 LLDP neighbour** (chassis/portId/portDesc/sysName); PoE with one delivering port (mW>0); fan/psu sensors incl. a `"Not Supported"` fan slot; mgmt-IP static `10.1.5.20/24 gw 10.1.5.1`.

- [ ] **Step 1: Write the failing test**

```python
# tests/virtual/test_state_seed.py
from __future__ import annotations

from netgear_switch.protocols.snmp import oids, parse
from netgear_switch.registry import get_model
from netgear_switch.virtual.seed import seed_gsm7252ps


def test_seed_builds_coherent_oid_map():
    state = seed_gsm7252ps()
    m = state.oid_map()
    # ifOperStatus for port 1 present
    assert f"{oids.IF_OPER_STATUS}.1" in m
    # a delivering PoE port exists with vendor mW > 0
    poe_base = oids.vendor_oids(get_model("gsm7252ps")).poe_power_mw + "."
    assert any(
        k.startswith(poe_base) and int(v[1]) > 0 for k, v in m.items()
    )


def test_seed_roundtrips_through_parsers():
    from netgear_switch.protocols.snmp.client import SnmpRow

    state = seed_gsm7252ps()
    m = state.oid_map()

    def rows(base: str) -> list[SnmpRow]:
        return [
            SnmpRow(k, v[1], v[0])
            for k, v in m.items()
            if k == base or k.startswith(base + ".")
        ]

    vlans = parse.parse_vlans(
        rows(oids.DOT1Q_VLAN_STATIC_NAME),
        rows(oids.DOT1Q_VLAN_STATIC_EGRESS),
        rows(oids.DOT1Q_VLAN_STATIC_UNTAGGED),
    )
    assert {v.vlan_id for v in vlans} >= {1, 90}
    mgmt = parse.parse_mgmt_ip(
        rows(oids.IP_ADENT_ADDR), rows(oids.IP_ADENT_NETMASK),
        rows(oids.IP_ROUTE_DEST), rows(oids.IP_ROUTE_NEXTHOP),
        rows(oids.vendor_oids(get_model("gsm7252ps")).dhcp_mode_unverified),
    )
    assert mgmt.address == "10.1.5.20" and mgmt.gateway == "10.1.5.1"


def test_seed_emits_nonempty_stats_macs_lldp():
    from netgear_switch.protocols.snmp.client import SnmpRow

    state = seed_gsm7252ps()
    m = state.oid_map()

    def rows(base: str) -> list[SnmpRow]:
        return [
            SnmpRow(k, v[1], v[0])
            for k, v in m.items()
            if k == base or k.startswith(base + ".")
        ]

    stats = parse.parse_port_stats(
        in_octets=rows(oids.IF_HC_IN_OCTETS), out_octets=rows(oids.IF_HC_OUT_OCTETS),
        in_ucast=rows(oids.IF_HC_IN_UCAST), out_ucast=rows(oids.IF_HC_OUT_UCAST),
        in_errors=rows(oids.IF_IN_ERRORS), out_errors=rows(oids.IF_OUT_ERRORS),
    )
    assert len([s for s in stats if s.rx_bytes is not None]) >= 2

    macs = parse.parse_macs(
        rows(oids.DOT1Q_TP_FDB_PORT), rows(oids.DOT1D_BASE_PORT_IF_INDEX)
    )
    assert len(macs) >= 2

    lldp = parse.parse_lldp(rows(oids.LLDP_REM_TABLE))
    assert len(lldp) >= 1 and lldp[0].remote_sys_name == "sw-cisco-shed"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/virtual/test_state_seed.py -v`
Expected: FAIL — module `seed` not found.

- [ ] **Step 3: Implement `state.py` and `seed.py`**

`state.py`: define the mutable sim dataclasses and `VirtualSwitchState.oid_map()`. Key snippet for the bitmap encode and a couple of column builders (build the rest analogously for every OID `SnmpReader` reads, so `oid_map()` is complete):
```python
def encode_port_bitmap(ports: set[int], width_bytes: int = 8) -> str:
    data = bytearray(width_bytes)
    for p in ports:
        byte_idx, bit = divmod(p - 1, 8)
        while byte_idx >= len(data):
            data.append(0)
        data[byte_idx] |= 0x80 >> bit
    return data.decode("latin-1")

def oid_map(self) -> dict[str, tuple[str, str]]:
    from ..protocols.snmp import oids
    v = oids.vendor_oids(get_model(self.model_key))
    m: dict[str, tuple[str, str]] = {}
    for port, sim in self.ports.items():
        m[f"{oids.IF_ADMIN_STATUS}.{port}"] = ("INTEGER", "1" if sim.admin else "2")
        m[f"{oids.IF_OPER_STATUS}.{port}"] = ("INTEGER", "1" if sim.link else "2")
        m[f"{oids.IF_HIGH_SPEED}.{port}"] = ("Gauge32", str(sim.speed))
        m[f"{oids.IF_NAME}.{port}"] = ("OCTETSTR", sim.name)
        # Port stats: only emit a counter the port actually exposes (None -> skip,
        # so parse_port_stats yields None there, never a fabricated 0).
        stat_cols = (
            (oids.IF_HC_IN_OCTETS, "Counter64", sim.rx_octets),
            (oids.IF_HC_OUT_OCTETS, "Counter64", sim.tx_octets),
            (oids.IF_HC_IN_UCAST, "Counter64", sim.rx_ucast),
            (oids.IF_HC_OUT_UCAST, "Counter64", sim.tx_ucast),
            (oids.IF_IN_ERRORS, "Counter32", sim.rx_errors),
            (oids.IF_OUT_ERRORS, "Counter32", sim.tx_errors),
        )
        for base, typ, val in stat_cols:
            if val is not None:
                m[f"{base}.{port}"] = (typ, str(val))
    for vid, vsim in self.vlans.items():
        m[f"{oids.DOT1Q_VLAN_STATIC_NAME}.{vid}"] = ("OCTETSTR", vsim.name)
        m[f"{oids.DOT1Q_VLAN_STATIC_EGRESS}.{vid}"] = (
            "OCTETSTR", encode_port_bitmap(vsim.member))
        m[f"{oids.DOT1Q_VLAN_STATIC_UNTAGGED}.{vid}"] = (
            "OCTETSTR", encode_port_bitmap(vsim.untagged))
    for port, pv in self.pvids.items():
        m[f"{oids.DOT1Q_PVID}.{port}"] = ("Gauge32", str(pv))
    for port, psim in self.poe.items():
        m[f"{oids.PETH_PSE_PORT_TABLE}.3.1.{port}"] = (
            "INTEGER", "1" if psim.admin else "2")
        m[f"{oids.PETH_PSE_PORT_TABLE}.6.1.{port}"] = ("INTEGER", str(psim.detect))
        m[f"{v.poe_power_mw}.1.{port}"] = ("Gauge32", str(psim.power_mw))
    for ssim in self.sensors:
        base = {"fan": v.box_fan, "power": v.box_psu_power,
                "temperature": v.box_temp}[ssim.kind]
        m[f"{base}.{ssim.instance}"] = ("OCTETSTR", ssim.raw)
    # MAC/FDB: dot1qTpFdbPort values keyed by <vlan>.<6 MAC bytes>, plus the
    # dot1dBasePortIfIndex bridge-port -> ifIndex rows the parser joins on.
    for msim in self.macs:
        mac_suffix = ".".join(str(b) for b in msim.mac_bytes)  # 6 decimal bytes
        m[f"{oids.DOT1Q_TP_FDB_PORT}.{msim.vlan}.{mac_suffix}"] = (
            "INTEGER", str(msim.bridge_port))
    for bridge_port, ifindex in self.bridge_ports.items():
        m[f"{oids.DOT1D_BASE_PORT_IF_INDEX}.{bridge_port}"] = (
            "INTEGER", str(ifindex))
    # LLDP remote neighbours across lldpRemTable columns 5/7/8/9.
    for nb in self.lldp:
        idx = f"{nb.time_mark}.{nb.local_port}.{nb.rem_idx}"
        m[f"{oids.LLDP_REM_TABLE}.1.5.{idx}"] = ("OCTETSTR", nb.chassis)
        m[f"{oids.LLDP_REM_TABLE}.1.7.{idx}"] = ("OCTETSTR", nb.port_id)
        m[f"{oids.LLDP_REM_TABLE}.1.8.{idx}"] = ("OCTETSTR", nb.port_desc)
        m[f"{oids.LLDP_REM_TABLE}.1.9.{idx}"] = ("OCTETSTR", nb.sys_name)
    # mgmt-ip: ipAddrTable + ipRouteTable + DHCP mode
    idx = self.mgmt.address
    m[f"{oids.IP_ADENT_ADDR}.{idx}"] = ("IPADDR", self.mgmt.address)
    m[f"{oids.IP_ADENT_NETMASK}.{idx}"] = ("IPADDR", self.mgmt.netmask)
    m[f"{oids.IP_ROUTE_DEST}.0.0.0.0"] = ("IPADDR", "0.0.0.0")
    m[f"{oids.IP_ROUTE_NEXTHOP}.0.0.0.0"] = ("IPADDR", self.mgmt.gateway)
    # Single named UNVERIFIED DHCP-mode OID (Task 4) — never a bare .99.1 literal.
    m[f"{v.dhcp_mode_unverified}.0"] = (
        "INTEGER", "2" if self.mgmt.mode == "static" else "1")
    return m
```
`seed.py`: construct a `VirtualSwitchState(model_key="gsm7252ps", ...)` with the concrete values described in Produces (ports 1–52, `speed=1000`, port 3 link-down; VLANs 1/90; PVIDs; PoE port 1 delivering `detect=3 admin=1 power_mw=12800`, others `detect=1`; sensors `fan0=3500`, `fan1="Not Supported"`, `fan2=3450`, `power1.0=53`; mgmt static `10.1.5.20/255.255.255.0` gw `10.1.5.1`). Include a `"Not Supported"` fan `SensorSim(kind="fan", instance="1", raw="Not Supported")`. Also seed the non-vacuous read data the equivalence test needs:
- **Port counters on ports 1 and 2**, e.g. `PortSim(..., rx_octets=1_000_000, tx_octets=2_000_000, rx_ucast=8_000, tx_ucast=9_000, rx_errors=0, tx_errors=0)` (leave the other ports' counters `None` so absence is exercised too).
- **≥2 MAC/FDB entries** — e.g. `MacSim(vlan=90, mac_bytes=(0xC8,0x00,0x84,0x89,0x71,0x70), bridge_port=10)` and `MacSim(vlan=1, mac_bytes=(0x00,0x1B,0x21,0x3C,0x4D,0x5E), bridge_port=11)` — plus `bridge_ports={10: 10, 11: 11}` so `dot1dBasePortIfIndex` maps each bridge port to an ifIndex.
- **≥1 LLDP neighbour** — e.g. `LldpSim(time_mark=75, local_port=49, rem_idx=7, chassis="".join(chr(b) for b in (0xC8, 0x00, 0x84, 0x89, 0x71, 0x70)), port_id="1/xg51", port_desc="eth0", sys_name="sw-cisco-shed")` (the 6-byte chassis is a latin-1 string, matching how the face serves the OCTET STRING).

- [ ] **Step 4: Run test + gates**

Run: `uv run pytest tests/virtual/test_state_seed.py -v && uv run mypy --strict src && uv run ruff check`
Expected: PASS; clean.

- [ ] **Step 5: Commit**

```bash
git add src/netgear_switch/virtual/__init__.py src/netgear_switch/virtual/state.py \
  src/netgear_switch/virtual/seed.py src/netgear_switch/virtual/faces/__init__.py \
  tests/virtual/test_state_seed.py
git commit -m "feat(virtual): VirtualSwitchState and hand-authored gsm7252ps seed"
```

---

### Task 14: Virtual face core — `StateMibView` OID responder (pure, no network)

Build the pure, unit-testable heart of the SNMP face: a class that turns `VirtualSwitchState.oid_map()` into a SORTED list of `(oid_tuple, snmp_type, value)` and answers exact-match GET and lexicographic GETNEXT over it with Python's `bisect`. No pysnmp, no UDP, no threads — so the hard OID-ordering logic (numeric `.2` before `.10`, GETNEXT off a bare column prefix, past-end handling) is tested independently of a running server. Task 15 wraps this in the real pysnmp engine.

**Files:**
- Create: `src/netgear_switch/virtual/faces/mibview.py`
- Test: `tests/virtual/test_mibview.py`

**Interfaces:**
- Consumes: `VirtualSwitchState.oid_map()`.
- Produces:
  - `class StateMibView(state: VirtualSwitchState)` holding a sorted `list[tuple[int, ...]]` of OID tuples and the parallel `(oid_tuple, snmp_type, value)` entries, derived once at construction from `state.oid_map()`.
  - `get(oid: tuple[int, ...]) -> tuple[tuple[int, ...], str, str] | None` — exact match via `bisect_left`; `None` means "no such instance" (the pysnmp wrapper maps it to the `NoSuchInstance` sentinel).
  - `get_next(oid: tuple[int, ...]) -> tuple[tuple[int, ...], str, str] | None` — first entry whose OID tuple is strictly greater, via `bisect_right`; `None` means "end of MIB view" (mapped to `endOfMibView`).

- [ ] **Step 1: Write the failing test**

```python
# tests/virtual/test_mibview.py
from __future__ import annotations

from netgear_switch.virtual.faces.mibview import StateMibView


class _FakeState:
    def __init__(self, mapping: dict[str, tuple[str, str]]) -> None:
        self._mapping = mapping

    def oid_map(self) -> dict[str, tuple[str, str]]:
        return self._mapping


def _view() -> StateMibView:
    # .8.2 must sort BEFORE .8.10 numerically (a string sort would invert them).
    return StateMibView(_FakeState({
        "1.3.6.1.2.1.2.2.1.8.1": ("INTEGER", "1"),
        "1.3.6.1.2.1.2.2.1.8.2": ("INTEGER", "2"),
        "1.3.6.1.2.1.2.2.1.8.10": ("INTEGER", "3"),
    }))


def test_get_exact_match():
    got = _view().get((1, 3, 6, 1, 2, 1, 2, 2, 1, 8, 2))
    assert got == ((1, 3, 6, 1, 2, 1, 2, 2, 1, 8, 2), "INTEGER", "2")


def test_get_missing_returns_none():
    assert _view().get((1, 3, 6, 1, 2, 1, 2, 2, 1, 8, 99)) is None


def test_get_next_uses_numeric_order():
    nxt = _view().get_next((1, 3, 6, 1, 2, 1, 2, 2, 1, 8, 2))
    assert nxt is not None
    assert nxt[0] == (1, 3, 6, 1, 2, 1, 2, 2, 1, 8, 10)  # .8.10, not string order


def test_get_next_from_column_prefix():
    nxt = _view().get_next((1, 3, 6, 1, 2, 1, 2, 2, 1, 8))
    assert nxt is not None and nxt[0][-1] == 1


def test_get_next_past_end_returns_none():
    assert _view().get_next((9, 9, 9)) is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/virtual/test_mibview.py -v`
Expected: FAIL — module `mibview` not found.

- [ ] **Step 3: Implement `mibview.py`**

```python
# src/netgear_switch/virtual/faces/mibview.py
"""Pure OID responder over VirtualSwitchState.oid_map().

No pysnmp, no network: a sorted (oid_tuple, snmp_type, value) list answering
exact-match GET and lexicographic GETNEXT with bisect. Task 15 wires this into
the real pysnmp command responder.
"""
from __future__ import annotations

import bisect
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..state import VirtualSwitchState

_Entry = tuple[tuple[int, ...], str, str]  # (oid_tuple, snmp_type, value)


def _oid_to_tuple(oid: str) -> tuple[int, ...]:
    return tuple(int(part) for part in oid.lstrip(".").split("."))


class StateMibView:
    """Sorted view of a switch's OID map supporting GET and GETNEXT."""

    def __init__(self, state: VirtualSwitchState) -> None:
        entries: list[_Entry] = [
            (_oid_to_tuple(oid), snmp_type, value)
            for oid, (snmp_type, value) in state.oid_map().items()
        ]
        entries.sort(key=lambda e: e[0])
        self._entries = entries
        self._oids = [e[0] for e in entries]  # parallel key list for bisect

    def get(self, oid: tuple[int, ...]) -> _Entry | None:
        i = bisect.bisect_left(self._oids, oid)
        if i < len(self._oids) and self._oids[i] == oid:
            return self._entries[i]
        return None  # caller maps None -> NoSuchInstance

    def get_next(self, oid: tuple[int, ...]) -> _Entry | None:
        # bisect_right -> index of the first OID strictly greater than `oid`.
        i = bisect.bisect_right(self._oids, oid)
        if i < len(self._oids):
            return self._entries[i]
        return None  # caller maps None -> endOfMibView
```

- [ ] **Step 4: Run test + gates**

Run: `uv run pytest tests/virtual/test_mibview.py -v && uv run mypy --strict src && uv run ruff check`
Expected: PASS; clean.

- [ ] **Step 5: Commit**

```bash
git add src/netgear_switch/virtual/faces/mibview.py tests/virtual/test_mibview.py
git commit -m "feat(virtual): pure StateMibView OID responder (bisect GET/GETNEXT)"
```

---

### Task 15: SNMP virtual face + `VirtualSwitch` server (pysnmp agent)

Wire `StateMibView` (Task 14) into a real pysnmp v7 command-responder on an ephemeral UDP port, and the `VirtualSwitch` server that binds it. This exercises a *different* SNMP stack than ezsnmp. GETNEXT/BULK correctness comes entirely from `StateMibView`; this task only adapts pysnmp's controller callbacks to it and manages the engine lifecycle.

**IMPORTANT — verify pysnmp v7 API names before coding.** pysnmp's agent-engine API is large and version-sensitive. Confirm the exact class/module names in the *installed* pysnmp v7 (the engine class, the UDP transport, the `MibInstrumController`/`SnmpContext` equivalents, and the SMI value types) against the package before use — e.g. `uv run --extra testing python -c "import pysnmp.entity.engine, pysnmp.entity.rfc3413.cmdrsp, pysnmp.smi.instrum"` and inspect their contents — rather than assuming the names in the snippets below are current.

**Files:**
- Create: `src/netgear_switch/virtual/faces/snmp.py`, `src/netgear_switch/virtual/server.py`
- Test: `tests/virtual/test_virtual_snmp_face.py`

**Interfaces:**
- Consumes: `StateMibView`, `VirtualSwitchState`, pysnmp v7 agent engine (lazy import).
- Produces:
  - `class VirtualSnmpFace` with `start() -> int` (returns bound UDP port) and `stop()`; internally holds a `StateMibView` and registers a custom MIB instrumentation controller whose `read_vars`/`read_next_vars` delegate to `StateMibView.get`/`get_next`, converting each `(snmp_type, value)` to the matching pysnmp SMI value.
  - `class VirtualSwitch(model: str, community: str = "public")` with `start() -> None`, `stop() -> None`, `port: int`, `host: str = "127.0.0.1"`, and `state: VirtualSwitchState`. Binds the SNMP face only for models whose registry entry supports `Backend.SNMP` (managed); on a Plus model it raises `UnsupportedCapability` in this slice.

Implementation notes (key snippets only; confirm the real class names first, per the note above): run the pysnmp engine with `CommunityData`/community index configured for v2c, add a UDP transport on `("127.0.0.1", 0)` and read back the assigned port via the transport dispatcher. Convert each `StateMibView` entry to a pysnmp SMI value by `snmp_type` token: `INTEGER`→`Integer32`, `Gauge32`→`Gauge32`, `Counter32`→`Counter32`, `Counter64`→`Counter64`, `OCTETSTR`→`OctetString` (encode the latin-1 bitmap string as bytes), `IPADDR`→`IpAddress`. The custom controller is thin — it owns no ordering logic, only adapting the callbacks to `StateMibView`:
```python
class _StateInstrum:  # adapts StateMibView to the pysnmp controller callbacks
    def __init__(self, view: StateMibView) -> None:
        self._view = view
    def read_vars(self, varBinds, acInfo=None, **kw):
        # per varBind: StateMibView.get(oid_tuple) -> SMI value or NoSuchInstance
        ...
    def read_next_vars(self, varBinds, acInfo=None, **kw):
        # per varBind: StateMibView.get_next(oid_tuple) -> next (oid, value) or endOfMibView
        ...
```
Run the engine's asyncio dispatcher in a background thread with its own event loop; `stop()` closes the dispatcher and joins the thread. The face is only imported under the `[testing]` extra (pysnmp).

- [ ] **Step 1: Write the failing test**

```python
# tests/virtual/test_virtual_snmp_face.py
from __future__ import annotations

import pytest

from netgear_switch.errors import UnsupportedCapability
from netgear_switch.transport.aio.snmp_pysnmp import PysnmpClient
from netgear_switch.virtual.server import VirtualSwitch


@pytest.mark.asyncio_or_run  # see conftest note; test uses asyncio.run directly
def test_get_and_walk_against_virtual_face():
    import asyncio

    from netgear_switch.protocols.snmp import oids

    sw = VirtualSwitch(model="gsm7252ps")
    sw.start()
    try:
        client = PysnmpClient(sw.host, "public", port=sw.port)
        row = asyncio.run(client.get(f"{oids.IF_OPER_STATUS}.1"))
        assert row is not None and row.value in {"1", "up(1)"}
        rows = asyncio.run(client.walk(oids.DOT1Q_VLAN_STATIC_NAME))
        names = {r.value for r in rows}
        assert "default" in names and "iot" in names
    finally:
        sw.stop()


def test_plus_model_has_no_snmp_face():
    with pytest.raises(UnsupportedCapability):
        VirtualSwitch(model="gs110emx").start()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run --extra testing --extra async pytest tests/virtual/test_virtual_snmp_face.py -v`
Expected: FAIL — module `server` not found.

- [ ] **Step 3: Implement the face and server**

Implement `faces/snmp.py` (`VirtualSnmpFace`) and `server.py` (`VirtualSwitch`) per the notes above. Guard `VirtualSwitch.start()`: `if Backend.SNMP not in get_model(model).backends: raise UnsupportedCapability(...)`. Construct one `StateMibView(self.state)` at `start()` (it does the sorting once) and have `_StateInstrum` delegate GET/GETNEXT to it, converting each `(snmp_type, value)` to the matching pysnmp SMI value. Bind UDP to `("127.0.0.1", 0)`, read back the port, run the dispatcher in a daemon thread. Having confirmed the pysnmp v7 names per the IMPORTANT note, use the lower-level `pysnmp.entity.engine` + `config.add_transport` + a `context.SnmpContext` whose `MibInstrumController` is the custom `_StateInstrum`; that is the intended path for serving a flat enterprise-OID map with correct GETNEXT semantics (all ordering already lives in `StateMibView`).

- [ ] **Step 4: Run test + gates**

Run: `uv run --extra testing --extra async pytest tests/virtual/test_virtual_snmp_face.py -v && uv run mypy --strict src && uv run ruff check`
Expected: PASS; clean. (If mypy cannot see pysnmp types, add `[[tool.mypy.overrides]] module = ["pysnmp.*"]` `ignore_missing_imports = true` to `pyproject.toml` in this task and stage it.)

- [ ] **Step 5: Commit**

```bash
git add src/netgear_switch/virtual/faces/snmp.py src/netgear_switch/virtual/server.py \
  tests/virtual/test_virtual_snmp_face.py pyproject.toml
git commit -m "feat(virtual): pysnmp SNMP face and VirtualSwitch server"
```

---

### Task 16: Integration — both clients vs the virtual face, identical objects

The capstone: run every read operation through **both** the ezsnmp sync client and the pysnmp async client against the same virtual face and assert the returned model objects are identical — and NON-EMPTY, so the equivalence is never vacuous. This is the sync/async equivalence seed and the cross-check against a different SNMP stack. ezsnmp talks real UDP to the pysnmp face on the ephemeral port (both are real stacks; no mocking here). The seed (Task 13) supplies populated port-stats, MAC/FDB and LLDP so `get_stats()`/`get_macs()`/`get_lldp()` are compared over real data, not empty lists.

**Files:**
- Create: `tests/test_snmp_integration.py`, `tests/conftest.py` (a fixture starting/stopping a `VirtualSwitch`).
- Test: `tests/test_snmp_integration.py`

**Interfaces:**
- Consumes: `VirtualSwitch`, `EzsnmpClient`, `PysnmpClient`, `SnmpReader`, `AsyncSnmpReader`, `get_model`.
- Produces: an equivalence assertion helper `assert_equal_reads(sync_reader, async_reader)`.

- [ ] **Step 1: Write the failing test**

```python
# tests/conftest.py
from __future__ import annotations

import pytest

from netgear_switch.virtual.server import VirtualSwitch


@pytest.fixture
def virtual_gsm7252ps():
    sw = VirtualSwitch(model="gsm7252ps")
    sw.start()
    yield sw
    sw.stop()
```

```python
# tests/test_snmp_integration.py
from __future__ import annotations

import asyncio

from netgear_switch.registry import get_model
from netgear_switch.snmp_read import AsyncSnmpReader, SnmpReader
from netgear_switch.transport.aio.snmp_pysnmp import PysnmpClient
from netgear_switch.transport.sync.snmp_ezsnmp import EzsnmpClient


def test_sync_and_async_reads_are_identical(virtual_gsm7252ps):
    sw = virtual_gsm7252ps
    model = get_model("gsm7252ps")
    sync = SnmpReader(EzsnmpClient(sw.host, "public"), model)
    aio = AsyncSnmpReader(PysnmpClient(sw.host, "public", port=sw.port), model)

    # NOTE: point ezsnmp at the ephemeral port. EzsnmpClient builds
    # "host:port" hostnames; construct with host=f"{sw.host}:{sw.port}".
    sync = SnmpReader(EzsnmpClient(f"{sw.host}:{sw.port}", "public"), model)

    # Prove equivalence over NON-EMPTY data for every read op this slice adds —
    # otherwise "sync == async" would pass vacuously on empty lists. The seed
    # (Task 13) guarantees stats, macs and lldp are populated.
    sync_ports = sync.get_ports()
    sync_stats = sync.get_stats()
    sync_vlans = sync.get_vlans()
    sync_lldp = sync.get_lldp()
    sync_macs = sync.get_macs()
    sync_poe = sync.get_poe()
    sync_sensors = sync.get_sensors()
    assert sync_ports, "ports must be non-empty"
    assert [s for s in sync_stats if s.rx_bytes is not None], "stats must be non-empty"
    assert sync_vlans and sync_lldp and sync_macs, "vlans/lldp/macs must be non-empty"
    assert any(p.power_mw for p in sync_poe) and sync_sensors

    assert sync_ports == asyncio.run(aio.get_ports())
    assert sync_stats == asyncio.run(aio.get_stats())
    assert sync_vlans == asyncio.run(aio.get_vlans())
    assert sync.get_pvids() == asyncio.run(aio.get_pvids())
    assert sync_lldp == asyncio.run(aio.get_lldp())
    assert sync_macs == asyncio.run(aio.get_macs())
    assert sync_poe == asyncio.run(aio.get_poe())
    assert sync_sensors == asyncio.run(aio.get_sensors())
    assert sync.get_mgmt_ip() == asyncio.run(aio.get_mgmt_ip())


def test_reads_return_expected_seed_values(virtual_gsm7252ps):
    sw = virtual_gsm7252ps
    reader = SnmpReader(
        EzsnmpClient(f"{sw.host}:{sw.port}", "public"), get_model("gsm7252ps")
    )
    vlans = {v.vlan_id: v.name for v in reader.get_vlans()}
    assert vlans[90] == "iot"
    assert reader.get_mgmt_ip().address == "10.1.5.20"
    assert any(p.power_mw and p.power_mw > 0 for p in reader.get_poe())
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run --extra testing --extra async --extra sync pytest tests/test_snmp_integration.py -v`
Expected: FAIL — until the face serves values byte-identically to what the parsers expect (likely first failures are OCTET STRING/bitmap or IPADDR formatting differences between the two stacks). Drive these to green by normalising in the transports/face, **not** by loosening the equality assertions.

- [ ] **Step 3: Reconcile representation differences**

If sync and async disagree on a field, fix it at the transport/face boundary so both surface the same dotted-decimal OID and value string the parsers expect (e.g. ensure the face returns VLAN bitmaps as raw `OctetString(bytes)` and IP addresses as `IpAddress`, and confirm `PysnmpClient` uses `prettyPrint()` while `EzsnmpClient` uses `use_numeric=True`). No production-code change should be needed in `parse.py`; if one is, add a unit test for it in the relevant parser test file first.

- [ ] **Step 4: Run test + full gate sweep**

Run:
```
uv run --extra testing --extra async --extra sync pytest -v
uv run ruff check
uv run mypy --strict src
```
Expected: entire suite PASSES with coverage ≥ 90%; ruff + mypy clean.

- [ ] **Step 5: Commit**

```bash
git add tests/conftest.py tests/test_snmp_integration.py
git commit -m "test(snmp): sync/async equivalence + cross-check vs virtual face"
```

---

## Self-Review Notes

**Spec §11 read-surface coverage → task mapping:**

| §11 read item | Task(s) |
|---|---|
| Port status: link up/down, speed | Task 5 (`parse_port_status`), Task 12 (`get_ports`) |
| Port RX/TX counters (packets + bytes, errors) → `PortStats` | Task 2 (model), Task 5 (`parse_port_stats`), Task 12 (`get_stats`) |
| VLAN static table (+ bitmap decode) & PVID | Task 6, Task 12 |
| LLDP local/remote neighbours | Task 7 (`parse_lldp`), Task 12 (`get_lldp`) |
| MAC table (SNMP/managed only; Plus raises) | Task 7 (`parse_macs`), Task 12 (`_require_snmp` gate in `__init__`) |
| PoE status: admin/detect (RFC3621 col3/col6) + power mW | Task 8 (`parse_poe`), Task 12 (`get_poe`) |
| Sensors: fan/temp/PSU, walk-discovered, "Not Supported" skip | Task 8 (`parse_box_sensors`), Task 12 (`get_sensors`) |
| Mgmt-interface DHCP/IP config (query) → `MgmtIpConfig` | Task 2 (model), Task 9 (`parse_mgmt_ip`), Task 12 (`get_mgmt_ip`) |
| Sync (ezsnmp) + async (pysnmp) transports, `get()`/`walk()`, lazy import | Task 3 (seam), Task 10 (sync), Task 11 (async) |
| SNMP virtual face on pysnmp agent engine, ephemeral UDP | Task 13 (state/seed), Task 14 (`StateMibView` core), Task 15 (pysnmp face/server) |
| Mock complete for the seeded model; dual-client equivalence | Task 16 |
| Quality gates: strict lint + strict types + coverage floor | Task 1 (adopted first; every task re-runs them) |

**Write paths (§11 VLAN create/delete, PoE control, mgmt-IP set) and the second/third virtual faces are correctly out of this slice** — they are Slice 4 (SNMP write) and Slices 5–6, per the §11.5 sequence. This slice is read-only + the SNMP face.

**Port-range validation against `model.port_count`/`poe_port_count` is a CONSCIOUS non-goal for this read-only slice.** Reads surface whatever ports/PoE indices the device reports; rejecting an out-of-range *requested* port is a write-path concern and lands in the write slice (Slice 4). It is deliberately deferred, not forgotten.

**Type consistency with the foundation:** parsers emit exactly the foundation's frozen types — `PortStatus(port,name,admin_enabled,link_up,speed_mbps)`, `VLANInfo(vlan_id,name,member_ports,tagged_ports,untagged_ports)` (all three port sets populated), `PoEStatus(port,admin_enabled,detect: PoEDetect,power_mw)`, `LLDPNeighbor(local_port,remote_sys_name,remote_port_desc,remote_chassis_id)`, `MacEntry(mac,port,vlan_id)`, `Sensor(name,kind,value,unit)`. New types `PortStats`/`MgmtIpConfig`/`IpMode` (Task 2) follow the same frozen/hashable rule and are threaded onto `SwitchData` with tuple/None defaults so existing construction sites stay valid. `PoEDetect` mapping uses the existing members (`DISABLED/SEARCHING/DELIVERING/FAULT/UNKNOWN`) — no enum changes. Method/type names are stable across tasks: `SnmpRow`, `SnmpClient`/`AsyncSnmpClient`, `EzsnmpClient`, `PysnmpClient`, `SnmpReader`/`AsyncSnmpReader`, `VirtualSwitch`/`VirtualSwitchState` are referenced identically everywhere they appear.

**RISK / controller decisions:**
1. **ezsnmp import — CLEARED.** `python3 -c "import ezsnmp"` succeeds in this environment (libsnmp-dev present), so sync SNMP is not blocked and no fallback is needed. Task 10 keeps a guard test asserting the import so a regression surfaces immediately.
2. **pysnmp not in the base interpreter** — it is declared under the `async`/`testing` extras; all async/face/integration test commands use `uv run --extra async`/`--extra testing`. Not a blocker, but the plan's test commands must include those extras (they do).
3. **Netgear DHCP-mode OID is unverified.** `parse_mgmt_ip` reads a Netgear private DHCP-mode row addressed by the single named `VendorOids.dhcp_mode_unverified` constant (Task 4, `{base}.99.1`) — never a bare literal at any call site — and the virtual face serves it, so the read path is self-consistent under test; but the real OID/encoding must be confirmed against hardware (the §7.1 capture utility, Slice 7) before mgmt-IP is trusted on live switches. When the OID is absent/unset the parser returns `IpMode.UNKNOWN` (never a guessed dhcp/static), and address/netmask/gateway come from standard `ipAddrTable`/`ipRouteTable` and are safe. Reading the mode is best-effort; **setting** it is out of scope until verified.
4. **Seeding scope — one model.** This slice seeds only `gsm7252ps` (a fully-managed `4526.10` model exercising ports/VLANs/PoE/sensors/mgmt-IP). §11.2's "complete mock of every switch model" is a Slice 4+ goal; recommend the controller confirm one seeded model is sufficient for Slice 2, with `m4300-24x` (no PoE, colon-STRING bridge MAC) and `gsm7228ps` (`4526.11` base) added when their write/quirk behaviour lands. If the controller wants broader read coverage now, add analogous `seed_m4300_24x()` / `seed_gsm7228ps()` as an extra task before Task 16 and parametrize the integration test over models.
5. **pysnmp agent-engine API surface (Task 15)** is the highest-effort/uncertainty task; the plan specifies the low-level `entity.engine` + custom `MibInstrumController` path as the reliable way to serve a flat enterprise-OID map with correct GETNEXT/BULK, and Task 15 explicitly instructs the implementer to confirm the exact pysnmp v7 class/module names against the installed version before use. All OID-ordering logic is unit-tested in Task 14's pure `StateMibView` (real `bisect` GET/GETNEXT), so a running UDP server is not needed to validate it.
