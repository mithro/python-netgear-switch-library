# Slice 3: Dual Read-API Facades + Equivalence Harness — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the public `SyncSwitch`/`AsyncSwitch` read facades over the merged SNMP core, plus a reusable sync/async equivalence harness that proves both facades return identical model objects against the live `VirtualSwitch`.

**Architecture:** Two thin facades (`sync_api.py`, `aio_api.py`) each hold a `SwitchModel` + host + credentials and delegate every read op to a model-selected backend reader. Backend selection lives behind one shared internal seam (`_dispatch.py`): today only SNMP is wired (build `SnmpReader`/`AsyncSnmpReader` over the existing transport clients); NSDP/HTTP-only (Plus) models raise `UnsupportedCapabilityError` with a "not yet implemented" message so Slices 5/6 can plug backends in without touching the facades' public surface. A `tests/equivalence.py` harness runs every op through both facades against a `VirtualSwitch` and asserts non-empty, content-pinned, sync==async results.

**Tech Stack:** Python ≥3.11, uv, net-snmp CLI (system dep, sync transport), pysnmp v7 (async transport, `--extra testing`), pytest + pytest-cov, ruff, mypy --strict.

## Global Constraints

Python ≥3.11; import `netgear_switch`; uv (run pysnmp/mock tests with `--extra testing`, net-snmp CLI is a system dep); frozen/hashable public types; strict ruff + mypy --strict + coverage≥90 as ENFORCED gates, all green locally; no blanket mypy ignores (pysnmp untyped handled via the existing importlib seam); errors surfaced early (typed errors, never silent-empty); never `git add -A` (overlay char-device dotfiles); no flaky tests (ephemeral ports, clean VirtualSwitch teardown, must pass under `-W error::ResourceWarning`); both facades MUST return identical model objects (the equivalence harness enforces this).

---

## File Structure

**New source files:**
- `src/netgear_switch/_dispatch.py` — internal backend-resolution seam shared by both facades: `require_snmp_backend`, `require_mac_table`, `build_sync_snmp_client`, `build_async_snmp_client`, and the `BACKEND_NOT_IMPLEMENTED` message. Transport imports are function-local so `import netgear_switch` never pulls net-snmp/pysnmp.
- `src/netgear_switch/sync_api.py` — public `SyncSwitch` facade (sync read methods + `snapshot()`).
- `src/netgear_switch/aio_api.py` — public `AsyncSwitch` facade (async read methods + `snapshot()`), mirror of `SyncSwitch`.

**Modified source files:**
- `src/netgear_switch/__init__.py` — export `SyncSwitch`/`AsyncSwitch`.

**New test files:**
- `tests/test_sync_api.py` — unit tests for `SyncSwitch` with an injected `FakeClient` (no network): delegation, backend dispatch, capability guards, `from_config`.
- `tests/test_aio_api.py` — unit tests for `AsyncSwitch` with `FakeAsyncClient` via `asyncio.run` (no network): mirror of the sync tests.
- `tests/equivalence.py` — reusable harness: `EquivalencePins`, `GSM7252PS_PINS`, `facades_for`, `assert_facades_equivalent` (imported by equivalence tests; generalizes `tests/test_snmp_integration.py`).
- `tests/test_facade_equivalence.py` — live-mock equivalence test driving both facades through the harness against `VirtualSwitch`.

**Untouched (kept working):** `tests/test_snmp_integration.py` remains the reader-level (Slice 2) capstone; the new harness covers the facade level.

---

### Task 1: Internal backend-resolution seam (`_dispatch.py`)

**Files:**
- Create: `src/netgear_switch/_dispatch.py`
- Test: `tests/test_dispatch.py`

**Interfaces:**
- Consumes (from merged Slice 1/2):
  - `netgear_switch.registry.Backend` (enum, member `SNMP`), `netgear_switch.registry.SwitchModel` (frozen dataclass with `.key: str`, `.backends: frozenset[Backend]`, `.has_mac_table: bool` property).
  - `netgear_switch.errors.UnsupportedCapabilityError`, `netgear_switch.errors.CredentialError`.
  - `netgear_switch.transport.sync.snmp_netsnmp_cli.NetsnmpCliClient(host: str, community: str, *, timeout=10, retries=1, runner=subprocess.run)`.
  - `netgear_switch.transport.aio.snmp_pysnmp.PysnmpClient(host: str, community: str, *, port=161, timeout=2.0, retries=1)`.
  - `netgear_switch.protocols.snmp.client.SnmpClient` / `AsyncSnmpClient` (Protocols).
- Produces (used by Tasks 2, 3, 5):
  - `BACKEND_NOT_IMPLEMENTED: str` — a `str.format` template with a `{key!r}` field.
  - `require_snmp_backend(model: SwitchModel) -> None` — raises `UnsupportedCapabilityError` if `Backend.SNMP not in model.backends`.
  - `require_mac_table(model: SwitchModel) -> None` — raises `UnsupportedCapabilityError` if `not model.has_mac_table`.
  - `build_sync_snmp_client(host: str, community: str | None) -> SnmpClient` — raises `CredentialError` if `community is None`, else returns a `NetsnmpCliClient`.
  - `build_async_snmp_client(host: str, community: str | None) -> AsyncSnmpClient` — raises `CredentialError` if `community is None`, else returns a `PysnmpClient`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_dispatch.py`:

```python
from __future__ import annotations

import pytest

from netgear_switch import _dispatch
from netgear_switch.errors import CredentialError, UnsupportedCapabilityError
from netgear_switch.registry import get_model


def test_require_snmp_backend_passes_for_snmp_model() -> None:
    # gsm7252ps has {SNMP}; must not raise.
    _dispatch.require_snmp_backend(get_model("gsm7252ps"))


def test_require_snmp_backend_raises_for_plus_model() -> None:
    with pytest.raises(UnsupportedCapabilityError) as exc:
        _dispatch.require_snmp_backend(get_model("gs305ep"))  # {NSDP, HTTP}
    msg = str(exc.value)
    assert "gs305ep" in msg
    assert "not" in msg and "implemented" in msg


def test_require_mac_table_passes_for_snmp_model() -> None:
    _dispatch.require_mac_table(get_model("gsm7252ps"))


def test_require_mac_table_raises_for_plus_model() -> None:
    with pytest.raises(UnsupportedCapabilityError):
        _dispatch.require_mac_table(get_model("gs305ep"))


def test_build_sync_client_requires_community() -> None:
    with pytest.raises(CredentialError):
        _dispatch.build_sync_snmp_client("sw.example", None)


def test_build_async_client_requires_community() -> None:
    with pytest.raises(CredentialError):
        _dispatch.build_async_snmp_client("sw.example", None)


def test_build_sync_client_returns_netsnmp_cli_client() -> None:
    from netgear_switch.transport.sync.snmp_netsnmp_cli import NetsnmpCliClient

    client = _dispatch.build_sync_snmp_client("sw.example", "public")
    assert isinstance(client, NetsnmpCliClient)
    assert client.host == "sw.example"
    assert client.community == "public"


def test_build_async_client_returns_pysnmp_client() -> None:
    from netgear_switch.transport.aio.snmp_pysnmp import PysnmpClient

    client = _dispatch.build_async_snmp_client("sw.example", "public")
    assert isinstance(client, PysnmpClient)
    assert client.host == "sw.example"
    assert client.community == "public"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run --extra testing pytest tests/test_dispatch.py -v --no-cov`
Expected: FAIL — `ModuleNotFoundError: No module named 'netgear_switch._dispatch'`.

- [ ] **Step 3: Write the implementation**

Create `src/netgear_switch/_dispatch.py`:

```python
"""Internal backend-resolution seam shared by SyncSwitch and AsyncSwitch.

Only SNMP is wired in this slice. Model-driven dispatch lives here so the two
facades stay identical and Slices 5/6 can add NSDP/HTTP backends without
touching the public facade surface. Transport imports are function-local so
``import netgear_switch`` never requires net-snmp binaries or pysnmp.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from .errors import CredentialError, UnsupportedCapabilityError
from .registry import Backend

if TYPE_CHECKING:
    from .protocols.snmp.client import AsyncSnmpClient, SnmpClient
    from .registry import SwitchModel

BACKEND_NOT_IMPLEMENTED = (
    "model {key!r} has no SNMP backend; NSDP/HTTP read backends are not "
    "implemented yet (Slices 5-6)"
)


def require_snmp_backend(model: SwitchModel) -> None:
    """Raise unless the model exposes an SNMP read backend."""
    if Backend.SNMP not in model.backends:
        raise UnsupportedCapabilityError(
            BACKEND_NOT_IMPLEMENTED.format(key=model.key)
        )


def require_mac_table(model: SwitchModel) -> None:
    """Raise unless the model has a readable MAC/FDB table."""
    if not model.has_mac_table:
        raise UnsupportedCapabilityError(
            f"model {model.key!r} has no MAC/FDB table"
        )


def _require_community(host: str, community: str | None) -> str:
    if community is None:
        raise CredentialError(
            f"no SNMP read community configured for {host!r}"
        )
    return community


def build_sync_snmp_client(host: str, community: str | None) -> SnmpClient:
    """Default sync SNMP client (net-snmp CLI). Imported lazily."""
    from .transport.sync.snmp_netsnmp_cli import NetsnmpCliClient

    return NetsnmpCliClient(host, _require_community(host, community))


def build_async_snmp_client(host: str, community: str | None) -> AsyncSnmpClient:
    """Default async SNMP client (pysnmp). Imported lazily."""
    from .transport.aio.snmp_pysnmp import PysnmpClient

    return PysnmpClient(host, _require_community(host, community))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run --extra testing pytest tests/test_dispatch.py -v --no-cov`
Expected: PASS (8 passed).

- [ ] **Step 5: Lint and type-check**

Run: `uv run ruff check src/netgear_switch/_dispatch.py tests/test_dispatch.py && uv run mypy`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add src/netgear_switch/_dispatch.py tests/test_dispatch.py
git commit -m "feat: add internal backend-resolution seam for read facades"
```

---

### Task 2: `SyncSwitch` facade (`sync_api.py`)

**Files:**
- Create: `src/netgear_switch/sync_api.py`
- Test: `tests/test_sync_api.py`

**Interfaces:**
- Consumes:
  - Task 1: `require_snmp_backend`, `require_mac_table`, `build_sync_snmp_client`.
  - `netgear_switch.snmp_read.SnmpReader(client: SnmpClient, model: SwitchModel)` with sync methods `get_ports() -> list[PortStatus]`, `get_stats() -> list[PortStats]`, `get_vlans() -> list[VLANInfo]`, `get_pvids() -> list[tuple[int, int]]`, `get_lldp() -> list[LLDPNeighbor]`, `get_macs() -> list[MacEntry]`, `get_poe() -> list[PoEStatus]`, `get_sensors() -> list[Sensor]`, `get_mgmt_ip() -> MgmtIpConfig`.
  - `netgear_switch.models.SwitchData(model: str, host: str, ports=(), poe=(), vlans=(), pvids=(), lldp=(), macs=(), sensors=(), stats=(), mgmt_ip=None)`.
  - `netgear_switch.config.SwitchConfig` (`.model: SwitchModel`, `.host: str`, `.snmp_community: str | None`).
  - `netgear_switch.protocols.snmp.client.SnmpClient` (Protocol), `netgear_switch.registry.SwitchModel`.
- Produces (used by Tasks 4, 5):
  - `SyncSwitch(model: SwitchModel, host: str, *, snmp_community: str | None = None, snmp_client: SnmpClient | None = None)`.
  - `SyncSwitch.from_config(cfg: SwitchConfig, *, env: Mapping[str, str] | None = None) -> SyncSwitch` (classmethod).
  - Sync read methods with the exact names/return types above.
  - `SyncSwitch.snapshot() -> SwitchData`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_sync_api.py`:

```python
from __future__ import annotations

import pytest

from netgear_switch.config import SwitchConfig
from netgear_switch.errors import UnsupportedCapabilityError
from netgear_switch.protocols.snmp import oids
from netgear_switch.protocols.snmp.client import SnmpRow
from netgear_switch.registry import get_model
from netgear_switch.sync_api import SyncSwitch


class FakeClient:
    """Serves canned SnmpRows keyed by exact base OID (mirrors test_snmp_read)."""

    def __init__(self, tables: dict[str, list[SnmpRow]]) -> None:
        self._tables = tables

    def get(self, oids: list[str]) -> list[SnmpRow]:
        return [row for oid in oids for row in self.walk(oid)]

    def walk(self, base_oid: str) -> list[SnmpRow]:
        return list(self._tables.get(base_oid, []))


def _ports_tables() -> dict[str, list[SnmpRow]]:
    return {
        oids.IF_ADMIN_STATUS: [SnmpRow(f"{oids.IF_ADMIN_STATUS}.1", 1, "INTEGER")],
        oids.IF_OPER_STATUS: [SnmpRow(f"{oids.IF_OPER_STATUS}.1", 1, "INTEGER")],
        oids.IF_HIGH_SPEED: [SnmpRow(f"{oids.IF_HIGH_SPEED}.1", 1000, "Gauge32")],
        oids.IF_NAME: [SnmpRow(f"{oids.IF_NAME}.1", "1/0/1", "STRING")],
    }


def test_get_ports_delegates_to_injected_client() -> None:
    sw = SyncSwitch(
        get_model("gsm7252ps"), "host", snmp_client=FakeClient(_ports_tables())
    )
    ports = sw.get_ports()
    assert ports[0].port == 1
    assert ports[0].name == "1/0/1"
    assert ports[0].speed_mbps == 1000


def test_plus_model_read_raises_backend_not_implemented() -> None:
    sw = SyncSwitch(get_model("gs305ep"), "host")  # {NSDP, HTTP} only
    with pytest.raises(UnsupportedCapabilityError) as exc:
        sw.get_ports()
    assert "gs305ep" in str(exc.value)


def test_get_macs_on_plus_model_raises_no_mac_table() -> None:
    sw = SyncSwitch(get_model("gs305ep"), "host")
    with pytest.raises(UnsupportedCapabilityError) as exc:
        sw.get_macs()
    assert "MAC" in str(exc.value) or "mac" in str(exc.value)


def test_from_config_builds_facade_without_touching_network() -> None:
    cfg = SwitchConfig(
        name="core",
        model=get_model("gsm7252ps"),
        host="10.0.0.9",
        snmp_community="public",
        snmp_write_community_spec=None,
        http_password_spec=None,
        nsdp_interface=None,
        protected_ports=frozenset(),
    )
    sw = SyncSwitch.from_config(cfg)
    assert sw.host == "10.0.0.9"
    assert sw.model.key == "gsm7252ps"


def test_snapshot_on_plus_model_raises() -> None:
    sw = SyncSwitch(get_model("gs305ep"), "host")
    with pytest.raises(UnsupportedCapabilityError):
        sw.snapshot()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_sync_api.py -v --no-cov`
Expected: FAIL — `ModuleNotFoundError: No module named 'netgear_switch.sync_api'`.

- [ ] **Step 3: Write the implementation**

Create `src/netgear_switch/sync_api.py`:

```python
"""Public synchronous read facade: SyncSwitch."""
from __future__ import annotations

from typing import TYPE_CHECKING

from ._dispatch import (
    build_sync_snmp_client,
    require_mac_table,
    require_snmp_backend,
)
from .models import SwitchData
from .snmp_read import SnmpReader

if TYPE_CHECKING:
    from collections.abc import Mapping

    from .config import SwitchConfig
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
    from .protocols.snmp.client import SnmpClient
    from .registry import SwitchModel


class SyncSwitch:
    """Synchronous, model-driven read facade over one switch."""

    def __init__(
        self,
        model: SwitchModel,
        host: str,
        *,
        snmp_community: str | None = None,
        snmp_client: SnmpClient | None = None,
    ) -> None:
        self.model = model
        self.host = host
        self._snmp_community = snmp_community
        self._snmp_client = snmp_client

    @classmethod
    def from_config(
        cls, cfg: SwitchConfig, *, env: Mapping[str, str] | None = None
    ) -> SyncSwitch:
        # env is reserved for backends that resolve secrets (SNMP write
        # community / HTTP password in Slices 4-6); SNMP reads use the literal
        # read community stored on the config, so env is unused here.
        _ = env
        return cls(cfg.model, cfg.host, snmp_community=cfg.snmp_community)

    def _reader(self) -> SnmpReader:
        # Backend-resolution seam: today only SNMP is wired. NSDP/HTTP-only
        # (Plus) models raise here; Slices 5/6 extend this without changing any
        # public method below.
        require_snmp_backend(self.model)
        client = self._snmp_client
        if client is None:
            client = build_sync_snmp_client(self.host, self._snmp_community)
        return SnmpReader(client, self.model)

    def get_ports(self) -> list[PortStatus]:
        return self._reader().get_ports()

    def get_stats(self) -> list[PortStats]:
        return self._reader().get_stats()

    def get_vlans(self) -> list[VLANInfo]:
        return self._reader().get_vlans()

    def get_pvids(self) -> list[tuple[int, int]]:
        return self._reader().get_pvids()

    def get_lldp(self) -> list[LLDPNeighbor]:
        return self._reader().get_lldp()

    def get_macs(self) -> list[MacEntry]:
        require_mac_table(self.model)
        return self._reader().get_macs()

    def get_poe(self) -> list[PoEStatus]:
        return self._reader().get_poe()

    def get_sensors(self) -> list[Sensor]:
        return self._reader().get_sensors()

    def get_mgmt_ip(self) -> MgmtIpConfig:
        return self._reader().get_mgmt_ip()

    def snapshot(self) -> SwitchData:
        """Aggregate every read op the model supports into one SwitchData."""
        reader = self._reader()
        macs = reader.get_macs() if self.model.has_mac_table else []
        return SwitchData(
            model=self.model.key,
            host=self.host,
            ports=tuple(reader.get_ports()),
            poe=tuple(reader.get_poe()),
            vlans=tuple(reader.get_vlans()),
            pvids=tuple(reader.get_pvids()),
            lldp=tuple(reader.get_lldp()),
            macs=tuple(macs),
            sensors=tuple(reader.get_sensors()),
            stats=tuple(reader.get_stats()),
            mgmt_ip=reader.get_mgmt_ip(),
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_sync_api.py -v --no-cov`
Expected: PASS (5 passed).

- [ ] **Step 5: Lint and type-check**

Run: `uv run ruff check src/netgear_switch/sync_api.py tests/test_sync_api.py && uv run mypy`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add src/netgear_switch/sync_api.py tests/test_sync_api.py
git commit -m "feat: add SyncSwitch read facade"
```

---

### Task 3: `AsyncSwitch` facade (`aio_api.py`)

**Files:**
- Create: `src/netgear_switch/aio_api.py`
- Test: `tests/test_aio_api.py`

**Interfaces:**
- Consumes:
  - Task 1: `require_snmp_backend`, `require_mac_table`, `build_async_snmp_client`.
  - `netgear_switch.snmp_read.AsyncSnmpReader(client: AsyncSnmpClient, model: SwitchModel)` with `async def` methods of the same names/return types as `SnmpReader` (Task 2 Interfaces).
  - `netgear_switch.models.SwitchData`, `netgear_switch.config.SwitchConfig`.
  - `netgear_switch.protocols.snmp.client.AsyncSnmpClient` (Protocol), `netgear_switch.registry.SwitchModel`.
- Produces (used by Tasks 4, 5):
  - `AsyncSwitch(model: SwitchModel, host: str, *, snmp_community: str | None = None, snmp_client: AsyncSnmpClient | None = None)`.
  - `AsyncSwitch.from_config(cfg: SwitchConfig, *, env: Mapping[str, str] | None = None) -> AsyncSwitch` (classmethod).
  - `async def` read methods with the exact names above, plus `async def snapshot() -> SwitchData`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_aio_api.py`:

```python
from __future__ import annotations

import asyncio

import pytest

from netgear_switch.aio_api import AsyncSwitch
from netgear_switch.errors import UnsupportedCapabilityError
from netgear_switch.protocols.snmp import oids
from netgear_switch.protocols.snmp.client import SnmpRow
from netgear_switch.registry import get_model


class FakeAsyncClient:
    """Async twin of Task 2's FakeClient: identical lookup, async methods."""

    def __init__(self, tables: dict[str, list[SnmpRow]]) -> None:
        self._tables = tables

    async def get(self, oids: list[str]) -> list[SnmpRow]:
        rows: list[SnmpRow] = []
        for oid in oids:
            rows.extend(await self.walk(oid))
        return rows

    async def walk(self, base_oid: str) -> list[SnmpRow]:
        return list(self._tables.get(base_oid, []))


def _ports_tables() -> dict[str, list[SnmpRow]]:
    return {
        oids.IF_ADMIN_STATUS: [SnmpRow(f"{oids.IF_ADMIN_STATUS}.1", 1, "INTEGER")],
        oids.IF_OPER_STATUS: [SnmpRow(f"{oids.IF_OPER_STATUS}.1", 1, "INTEGER")],
        oids.IF_HIGH_SPEED: [SnmpRow(f"{oids.IF_HIGH_SPEED}.1", 1000, "Gauge32")],
        oids.IF_NAME: [SnmpRow(f"{oids.IF_NAME}.1", "1/0/1", "STRING")],
    }


def test_get_ports_delegates_to_injected_async_client() -> None:
    sw = AsyncSwitch(
        get_model("gsm7252ps"), "host", snmp_client=FakeAsyncClient(_ports_tables())
    )
    ports = asyncio.run(sw.get_ports())
    assert ports[0].port == 1
    assert ports[0].name == "1/0/1"
    assert ports[0].speed_mbps == 1000


def test_plus_model_read_raises_backend_not_implemented() -> None:
    sw = AsyncSwitch(get_model("gs305ep"), "host")
    with pytest.raises(UnsupportedCapabilityError) as exc:
        asyncio.run(sw.get_ports())
    assert "gs305ep" in str(exc.value)


def test_get_macs_on_plus_model_raises_no_mac_table() -> None:
    sw = AsyncSwitch(get_model("gs305ep"), "host")
    with pytest.raises(UnsupportedCapabilityError):
        asyncio.run(sw.get_macs())


def test_snapshot_on_plus_model_raises() -> None:
    sw = AsyncSwitch(get_model("gs305ep"), "host")
    with pytest.raises(UnsupportedCapabilityError):
        asyncio.run(sw.snapshot())
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_aio_api.py -v --no-cov`
Expected: FAIL — `ModuleNotFoundError: No module named 'netgear_switch.aio_api'`.

- [ ] **Step 3: Write the implementation**

Create `src/netgear_switch/aio_api.py`:

```python
"""Public asynchronous read facade: AsyncSwitch (mirror of SyncSwitch)."""
from __future__ import annotations

from typing import TYPE_CHECKING

from ._dispatch import (
    build_async_snmp_client,
    require_mac_table,
    require_snmp_backend,
)
from .models import SwitchData
from .snmp_read import AsyncSnmpReader

if TYPE_CHECKING:
    from collections.abc import Mapping

    from .config import SwitchConfig
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
    from .protocols.snmp.client import AsyncSnmpClient
    from .registry import SwitchModel


class AsyncSwitch:
    """Asynchronous, model-driven read facade over one switch."""

    def __init__(
        self,
        model: SwitchModel,
        host: str,
        *,
        snmp_community: str | None = None,
        snmp_client: AsyncSnmpClient | None = None,
    ) -> None:
        self.model = model
        self.host = host
        self._snmp_community = snmp_community
        self._snmp_client = snmp_client

    @classmethod
    def from_config(
        cls, cfg: SwitchConfig, *, env: Mapping[str, str] | None = None
    ) -> AsyncSwitch:
        # env is reserved for secret-resolving backends (Slices 4-6); SNMP
        # reads use the literal read community on the config, so env is unused.
        _ = env
        return cls(cfg.model, cfg.host, snmp_community=cfg.snmp_community)

    def _reader(self) -> AsyncSnmpReader:
        # Backend-resolution seam mirroring SyncSwitch._reader.
        require_snmp_backend(self.model)
        client = self._snmp_client
        if client is None:
            client = build_async_snmp_client(self.host, self._snmp_community)
        return AsyncSnmpReader(client, self.model)

    async def get_ports(self) -> list[PortStatus]:
        return await self._reader().get_ports()

    async def get_stats(self) -> list[PortStats]:
        return await self._reader().get_stats()

    async def get_vlans(self) -> list[VLANInfo]:
        return await self._reader().get_vlans()

    async def get_pvids(self) -> list[tuple[int, int]]:
        return await self._reader().get_pvids()

    async def get_lldp(self) -> list[LLDPNeighbor]:
        return await self._reader().get_lldp()

    async def get_macs(self) -> list[MacEntry]:
        require_mac_table(self.model)
        return await self._reader().get_macs()

    async def get_poe(self) -> list[PoEStatus]:
        return await self._reader().get_poe()

    async def get_sensors(self) -> list[Sensor]:
        return await self._reader().get_sensors()

    async def get_mgmt_ip(self) -> MgmtIpConfig:
        return await self._reader().get_mgmt_ip()

    async def snapshot(self) -> SwitchData:
        """Aggregate every read op the model supports into one SwitchData."""
        reader = self._reader()
        macs = await reader.get_macs() if self.model.has_mac_table else []
        return SwitchData(
            model=self.model.key,
            host=self.host,
            ports=tuple(await reader.get_ports()),
            poe=tuple(await reader.get_poe()),
            vlans=tuple(await reader.get_vlans()),
            pvids=tuple(await reader.get_pvids()),
            lldp=tuple(await reader.get_lldp()),
            macs=tuple(macs),
            sensors=tuple(await reader.get_sensors()),
            stats=tuple(await reader.get_stats()),
            mgmt_ip=await reader.get_mgmt_ip(),
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_aio_api.py -v --no-cov`
Expected: PASS (4 passed).

- [ ] **Step 5: Lint and type-check**

Run: `uv run ruff check src/netgear_switch/aio_api.py tests/test_aio_api.py && uv run mypy`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add src/netgear_switch/aio_api.py tests/test_aio_api.py
git commit -m "feat: add AsyncSwitch read facade"
```

---

### Task 4: Public exports (`__init__.py`)

**Files:**
- Modify: `src/netgear_switch/__init__.py`
- Test: `tests/test_public_api.py` (extend), `tests/test_import.py` (verify no-network import)

**Interfaces:**
- Consumes: `SyncSwitch` (Task 2), `AsyncSwitch` (Task 3).
- Produces: `netgear_switch.SyncSwitch`, `netgear_switch.AsyncSwitch`, both listed in `netgear_switch.__all__`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_public_api.py`:

```python
def test_facades_exported_from_top_level():
    import netgear_switch as ns

    assert "SyncSwitch" in ns.__all__
    assert "AsyncSwitch" in ns.__all__
    assert ns.SyncSwitch is not None
    assert ns.AsyncSwitch is not None
    # Constructible from a model without touching the network.
    sw = ns.SyncSwitch(ns.get_model("gsm7252ps"), "host", snmp_community="public")
    assert sw.model.key == "gsm7252ps"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_public_api.py::test_facades_exported_from_top_level -v --no-cov`
Expected: FAIL — `AttributeError: module 'netgear_switch' has no attribute 'SyncSwitch'`.

- [ ] **Step 3: Add the imports and exports**

In `src/netgear_switch/__init__.py`, add the facade imports after the `registry` import block (before `__version__`):

```python
from .registry import MODELS, Backend, SwitchClass, SwitchModel, get_model
from .sync_api import SyncSwitch
from .aio_api import AsyncSwitch
```

Then add a grouped `# facades` block to `__all__` (immediately after the `# config` group, before the closing `]`):

```python
    # config
    "SwitchConfig",
    "resolve_secret",
    "load_inventory",
    "ensure_secure_file",
    # facades
    "SyncSwitch",
    "AsyncSwitch",
]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_public_api.py tests/test_import.py -v --no-cov`
Expected: PASS (import must succeed with no net-snmp/pysnmp installed — facade transport imports are function-local).

- [ ] **Step 5: Lint and type-check**

Run: `uv run ruff check src/netgear_switch/__init__.py && uv run mypy`
Expected: no errors (the `# noqa: RUF022` on `__all__` keeps the grouped, non-alphabetical order legal).

- [ ] **Step 6: Commit**

```bash
git add src/netgear_switch/__init__.py tests/test_public_api.py
git commit -m "feat: export SyncSwitch and AsyncSwitch from package root"
```

---

### Task 5: Equivalence harness + live-mock facade equivalence test

**Files:**
- Create: `tests/equivalence.py`
- Create: `tests/test_facade_equivalence.py`
- Test: `tests/test_facade_equivalence.py` (drives the harness)

**Interfaces:**
- Consumes:
  - `netgear_switch.sync_api.SyncSwitch`, `netgear_switch.aio_api.AsyncSwitch` (Tasks 2/3).
  - `netgear_switch.transport.sync.snmp_netsnmp_cli.NetsnmpCliClient(host, community)` (note: agent spec is `"host:port"`).
  - `netgear_switch.transport.aio.snmp_pysnmp.PysnmpClient(host, community, *, port=...)` (host and port are separate args).
  - `netgear_switch.registry.get_model`, `netgear_switch.models.IpMode`.
  - `netgear_switch.virtual.server.VirtualSwitch` with attrs `.host: str`, `.port: int` (set after `start()`), `.community: str`, `.model: str`; started/stopped by the existing `virtual_gsm7252ps` fixture in `tests/conftest.py`.
- Produces (reusable by future backends/models):
  - `EquivalencePins` (frozen dataclass of per-model content pins).
  - `GSM7252PS_PINS: EquivalencePins`.
  - `facades_for(sw: VirtualSwitch) -> tuple[SyncSwitch, AsyncSwitch]`.
  - `assert_facades_equivalent(sw: VirtualSwitch, pins: EquivalencePins) -> None`.

- [ ] **Step 1: Write the harness (the reusable helper both this and future tests import)**

Create `tests/equivalence.py`:

```python
"""Reusable sync/async facade equivalence harness.

Generalizes tests/test_snmp_integration.py from the raw readers to the public
facades: given a running VirtualSwitch and a set of per-model content pins, it
runs every read op through BOTH SyncSwitch and AsyncSwitch and asserts the
results are non-empty, content-pinned, and byte-for-byte identical across the
two independent transports. Future backends/models reuse this by supplying
their own EquivalencePins.
"""
from __future__ import annotations

import asyncio
import gc
from dataclasses import dataclass
from typing import TYPE_CHECKING

from netgear_switch.aio_api import AsyncSwitch
from netgear_switch.models import IpMode
from netgear_switch.registry import get_model
from netgear_switch.sync_api import SyncSwitch
from netgear_switch.transport.aio.snmp_pysnmp import PysnmpClient
from netgear_switch.transport.sync.snmp_netsnmp_cli import NetsnmpCliClient

if TYPE_CHECKING:
    from netgear_switch.virtual.server import VirtualSwitch


@dataclass(frozen=True)
class EquivalencePins:
    """Known seed values for one model, proving equivalence is over real data."""

    port_name: str
    vlan_id: int
    vlan_name: str
    vlan_member_port: int
    mgmt_address: str
    mgmt_mode: IpMode
    poe_port: int
    poe_power_mw: int
    mac: str
    mac_port: int


GSM7252PS_PINS = EquivalencePins(
    port_name="1/0/1",
    vlan_id=90,
    vlan_name="iot",
    vlan_member_port=10,
    mgmt_address="10.1.5.20",
    mgmt_mode=IpMode.STATIC,
    poe_port=1,
    poe_power_mw=12_800,
    mac="C8:00:84:89:71:70",
    mac_port=110,
)


def facades_for(sw: VirtualSwitch) -> tuple[SyncSwitch, AsyncSwitch]:
    """Build both facades wired to a running VirtualSwitch via injected clients.

    Injection sidesteps the sync/async host-spec asymmetry: the net-snmp CLI
    client takes a combined ``host:port`` agent spec, while PysnmpClient takes
    host and port separately.
    """
    model = get_model(sw.model)
    sync = SyncSwitch(
        model,
        sw.host,
        snmp_community=sw.community,
        snmp_client=NetsnmpCliClient(f"{sw.host}:{sw.port}", sw.community),
    )
    aio = AsyncSwitch(
        model,
        sw.host,
        snmp_community=sw.community,
        snmp_client=PysnmpClient(sw.host, sw.community, port=sw.port),
    )
    return sync, aio


def assert_facades_equivalent(sw: VirtualSwitch, pins: EquivalencePins) -> None:
    """Run every read op through both facades; assert non-empty + pinned + equal."""
    sync, aio = facades_for(sw)

    ports = sync.get_ports()
    stats = sync.get_stats()
    vlans = sync.get_vlans()
    pvids = sync.get_pvids()
    lldp = sync.get_lldp()
    macs = sync.get_macs()
    poe = sync.get_poe()
    sensors = sync.get_sensors()
    mgmt = sync.get_mgmt_ip()

    # Non-empty: guard against a vacuous [] == [] equivalence pass.
    assert ports, "ports must be non-empty"
    assert [s for s in stats if s.rx_bytes is not None], "stats must be non-empty"
    assert vlans, "vlans must be non-empty"
    assert pvids, "pvids must be non-empty"
    assert lldp, "lldp must be non-empty"
    assert macs, "macs must be non-empty"
    assert any(p.power_mw for p in poe), "poe must show delivered power"
    assert sensors, "sensors must be non-empty"
    assert mgmt.address, "mgmt-ip must be populated"

    # Content pins: prove equivalence is over real, known seed data.
    assert pins.port_name in {p.name for p in ports}
    target_vlan = next(v for v in vlans if v.vlan_id == pins.vlan_id)
    assert target_vlan.name == pins.vlan_name
    assert pins.vlan_member_port in target_vlan.member_ports
    assert mgmt.address == pins.mgmt_address
    assert mgmt.mode is pins.mgmt_mode
    delivering = [p for p in poe if p.power_mw]
    assert delivering[0].port == pins.poe_port
    assert delivering[0].power_mw == pins.poe_power_mw
    # MAC/FDB join proof: a non-identity bridge_port -> ifIndex mapping.
    joined = next(m for m in macs if m.mac == pins.mac)
    assert joined.port == pins.mac_port

    # Equivalence proper: sync (net-snmp CLI) vs async (pysnmp) must be equal.
    assert ports == asyncio.run(aio.get_ports())
    assert stats == asyncio.run(aio.get_stats())
    assert vlans == asyncio.run(aio.get_vlans())
    assert pvids == asyncio.run(aio.get_pvids())
    assert lldp == asyncio.run(aio.get_lldp())
    assert macs == asyncio.run(aio.get_macs())
    assert poe == asyncio.run(aio.get_poe())
    assert sensors == asyncio.run(aio.get_sensors())
    aio_mgmt = asyncio.run(aio.get_mgmt_ip())
    assert mgmt == aio_mgmt
    assert mgmt.mode is pins.mgmt_mode
    assert aio_mgmt.mode is pins.mgmt_mode

    # snapshot() aggregates the same objects and is equivalent across facades.
    sync_snap = sync.snapshot()
    aio_snap = asyncio.run(aio.snapshot())
    assert sync_snap == aio_snap
    assert sync_snap.model == sw.model
    assert sync_snap.ports == tuple(ports)
    assert sync_snap.macs == tuple(macs)

    # Force finalization of any unreferenced pysnmp transport before the
    # -W error::ResourceWarning run inspects warnings.
    gc.collect()
```

- [ ] **Step 2: Write the live-mock test that drives the harness**

Create `tests/test_facade_equivalence.py`:

```python
"""Live-mock equivalence: both facades against a seeded VirtualSwitch."""
from __future__ import annotations

from typing import TYPE_CHECKING

from equivalence import GSM7252PS_PINS, assert_facades_equivalent

if TYPE_CHECKING:
    from netgear_switch.virtual.server import VirtualSwitch


def test_facades_equivalent_gsm7252ps(virtual_gsm7252ps: VirtualSwitch) -> None:
    assert_facades_equivalent(virtual_gsm7252ps, GSM7252PS_PINS)
```

Note: `from equivalence import ...` works because pytest's default (prepend)
import mode puts the `tests/` directory (home of `conftest.py`) on `sys.path`.
`tests/equivalence.py` is a plain helper module, not a test module, so it is
never collected. mypy's scope is `packages = ["netgear_switch"]`, so the test
tree is not type-checked; ruff still lints it.

- [ ] **Step 3: Run the equivalence test to verify it passes**

Run: `uv run --extra testing pytest tests/test_facade_equivalence.py -v --no-cov`
Expected: PASS (1 passed) — requires net-snmp CLI on PATH and the `testing`
extra (pysnmp) installed. If it fails with "net-snmp not installed", install
the system `snmp` package (`apt-get install -y snmp`) and rerun.

- [ ] **Step 4: Run the full suite with coverage and ResourceWarning-as-error**

Run: `uv run --extra testing pytest -W error::ResourceWarning`
Expected: PASS, all tests green, coverage ≥90% (the `--cov-fail-under=90` gate
in `pyproject.toml` addopts must not trip), no ResourceWarning (clean
VirtualSwitch teardown via the `virtual_gsm7252ps` fixture + `gc.collect()`).

- [ ] **Step 5: Lint and type-check the whole tree**

Run: `uv run ruff check . && uv run mypy`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add tests/equivalence.py tests/test_facade_equivalence.py
git commit -m "test: add reusable sync/async facade equivalence harness"
```

---

## Self-Review Notes

**Scope-item → task mapping:**

1. `SyncSwitch` / `AsyncSwitch` public facades with identical read method
   names/signatures, `from_config` classmethod, injected-client testability,
   model-driven backend dispatch, and the NSDP/HTTP "not yet implemented"
   guard → **Tasks 2 (sync) + 3 (async)**, with the shared dispatch seam in
   **Task 1** (`_dispatch.py`). `get_macs` on a Plus/no-MAC model raises
   `UnsupportedCapabilityError` via `require_mac_table` (Tasks 2/3), and the
   `_reader()` seam is the extension point Slices 5/6 fill for NSDP/HTTP.
2. `snapshot()` aggregating supported ops into a populated `SwitchData` →
   **Tasks 2/3** (method) + **Task 5** (happy-path equivalence coverage).
3. Reusable equivalence harness generalizing `test_snmp_integration.py` →
   **Task 5** (`tests/equivalence.py` + `test_facade_equivalence.py`); the
   original reader-level integration test is left untouched and still passing.
4. Public exports of `SyncSwitch`/`AsyncSwitch` in the grouped `__all__` →
   **Task 4**.
5. Facade unit tests with injected fakes (no network) covering delegation,
   backend dispatch, and capability guards; plus live-mock equivalence
   (non-empty, content-pinned, sync==async, mode + mac-join pins) → **Tasks 2/3**
   (unit) + **Task 5** (integration). Import-without-network is asserted in
   **Task 4**; async tests use `asyncio.run` (no pytest-asyncio dependency).

**Type-consistency check against merged Slice-2 code:**

- Reader classes/methods: `SnmpReader` / `AsyncSnmpReader` constructed as
  `(client, model)` with methods `get_ports/get_stats/get_vlans/get_pvids/
  get_lldp/get_macs/get_poe/get_sensors/get_mgmt_ip`; async versions are
  `async def`. `get_pvids` returns `list[tuple[int, int]]`. Facades delegate to
  these exact names/types.
- Transport clients: `NetsnmpCliClient(host, community, *, timeout, retries,
  runner)` uses a combined `"host:port"` agent spec; `PysnmpClient(host,
  community, *, port, timeout, retries)` takes host/port separately. The harness
  and `_dispatch` builders honor both signatures; `.host`/`.community`
  attributes exist on both for the Task 1 assertions.
- Client protocols: `SnmpClient` / `AsyncSnmpClient` from
  `protocols.snmp.client`; `SnmpRow(oid, value, snmp_type)` is the fake-client
  row type (reused verbatim from `test_snmp_read.py`).
- Registry: `SwitchModel` with `.key`, `.backends: frozenset[Backend]`,
  `.has_mac_table` property; `Backend.SNMP`; `get_model`. gsm7252ps → `{SNMP}`
  (facade uses SNMP); gs305ep → `{NSDP, HTTP}` (facade raises). Matches
  `registry.py`.
- Config: `SwitchConfig(name, model, host, snmp_community,
  snmp_write_community_spec, http_password_spec, nsdp_interface,
  protected_ports)` — the Task 2 test constructs it with these exact fields;
  `from_config` reads `.model`, `.host`, `.snmp_community`.
- Models: `SwitchData(model: str, host: str, ports/poe/vlans/pvids/lldp/macs/
  sensors/stats tuples, mgmt_ip)` and `IpMode.STATIC` match `models.py`;
  `snapshot()` builds tuples from the readers' lists.
- Errors: `UnsupportedCapabilityError`, `CredentialError` from `errors.py`
  (both subclass `NetgearSwitchError`).
- VirtualSwitch: `.host`, `.port` (post-`start()`), `.community`, `.model`,
  driven by the existing `virtual_gsm7252ps` fixture in `conftest.py`.

**Deliberate design decisions (flagged for the controller):**

- **Constructor shape:** `SyncSwitch(model: SwitchModel, host: str, *,
  snmp_community=None, snmp_client=None)` + `from_config(cfg, *, env=None)`.
  Explicit `model` (already a `SwitchModel`, not a key) avoids a redundant
  registry lookup and matches `SwitchConfig.model`. Client injection (not a
  factory) is the testability seam; the default client is built lazily inside
  `_reader()` so import stays network-free.
- **`env` on `from_config` is currently unused** (reads need no secret
  resolution — the read community is a literal on the config). It is retained
  for signature stability so Slices 4-6 (write community / HTTP password) don't
  change the public classmethod signature. `_ = env` documents the intent;
  ruff's `ARG` rules are not enabled, so this is clean.
- **`snapshot()` is included in this slice** (all read ops exist), covering the
  §3 `SwitchData` aggregation. If the controller prefers to defer aggregation
  until write ops land, it can move to Slice 4 — but nothing here depends on
  writes, so shipping it now maximizes read-path value.
