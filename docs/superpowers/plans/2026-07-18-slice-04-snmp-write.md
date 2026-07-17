# Slice 4: SNMP write/control Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add SNMP SET-based write/control (PoE on/off/cycle/clear-fault, port enable/disable, PVID, VLAN membership + create/delete, mgmt-IP) to `netgear_switch` with verify-after-write, library-level write safety, and a mutable virtual mock so every write is testable against a live agent through both the sync and async facades.

**Architecture:** A new write-capable client Protocol extends the existing read Protocols; both transports (net-snmp `snmpset` CLI, pysnmp `set_cmd`) implement `set`/`set_many` symmetrically. Pure encoding helpers do read-modify-write on Q-BRIDGE bitmaps. A new `SnmpWriter`/`AsyncSnmpWriter` (parallel to the existing `SnmpReader`/`AsyncSnmpReader`) performs each SET then re-reads to verify, raising `WriteVerificationError(before, after)` on mismatch, and enforces `protected_ports`. The `VirtualSwitchState` becomes mutable and the pysnmp face gains a SET responder, so writes mutate mock state and read back coherently (including PoE admin→detect→link coherence so `cycle_poe` terminates). The facades gain identical write methods wired through `from_config` with an `env`-resolved write community; a write-equivalence harness proves sync and async produce byte-identical mock state.

**Tech Stack:** Python ≥3.11, net-snmp CLI (`snmpset`, system dep), pysnmp v7 (`--extra testing`), uv, pytest, ruff, mypy --strict, coverage.

## Global Constraints

Python ≥3.11; import `netgear_switch`; uv (pysnmp/mock tests `--extra testing`, net-snmp CLI system dep for sync incl. `snmpset`); frozen/hashable public return types; strict ruff + mypy --strict + coverage≥90 ENFORCED, green locally; no blanket mypy ignores (pysnmp untyped via existing importlib seam); errors surfaced early (typed errors incl. WriteVerificationError with before/after — raised ONLY when a SET was attempted and the read-back diverged, never for a pure precondition like a missing VLAN, which is an SnmpError; verify-after-write compares EVERY column the op wrote — both egress+untagged for VLAN membership, all of address+netmask+gateway for mgmt-IP; commitFailed → SnmpError; NEVER silently succeed on a failed write); write community required for writes but resolved LAZILY on first write (never eagerly in from_config, so read-only construction with an unresolvable write-community spec never raises); protected_ports enforced on every disruptive op incl. VLAN delete (any protected member port refuses without force); never `git add -A` (overlay char-device dotfiles); no flaky tests (ephemeral ports, injectable cycle timeouts, clean VirtualSwitch teardown, pass under `-W error::ResourceWarning`); sync and async writes MUST produce identical mock state (write-equivalence harness enforces this); SNMP is the v1 write path for ALL managed models incl. M4300 (owner-confirmed; verify-after-write surfaces any real commitFailed).

---

## File Structure

**New source files:**
- `src/netgear_switch/protocols/snmp/write.py` — pure write encoding: `SetVarbind`, SET type-letter constants, bitmap read-modify-write helpers, membership-bitmap computation. No I/O.
- `src/netgear_switch/snmp_write.py` — `SnmpWriter` / `AsyncSnmpWriter`: model-driven write ops with verify-after-write and `protected_ports` enforcement (parallel to `snmp_read.py`).

**Modified source files:**
- `src/netgear_switch/protocols/snmp/client.py` — add `SnmpWriteClient` / `AsyncSnmpWriteClient` Protocols (extend the read Protocols with `set`/`set_many`).
- `src/netgear_switch/protocols/snmp/oids.py` — add `DOT1Q_VLAN_STATIC_ROW_STATUS`, RowStatus constants, and UNVERIFIED mgmt-IP write OIDs on `VendorOids`.
- `src/netgear_switch/transport/sync/snmp_netsnmp_cli.py` — add `set`/`set_many` (net-snmp `snmpset`).
- `src/netgear_switch/transport/aio/snmp_pysnmp.py` — add `set`/`set_many` (pysnmp `set_cmd`).
- `src/netgear_switch/virtual/state.py` — add `VirtualSwitchState.apply_write` + coherence; `PoeSim` unchanged.
- `src/netgear_switch/virtual/faces/mibview.py` — `StateMibView` keeps a live state ref, gains `rebuild()` + `apply_write()`.
- `src/netgear_switch/virtual/faces/snmp.py` — `_StateInstrum.write_variables` + `SetCommandResponder` + `writeSubTree` VACM + SMI→python conversion.
- `src/netgear_switch/errors.py` — add `ProtectedPortError`.
- `src/netgear_switch/_dispatch.py` — add `build_sync_snmp_write_client` / `build_async_snmp_write_client` (write community required).
- `src/netgear_switch/sync_api.py` / `aio_api.py` — add write methods + write-client wiring + `env`-resolved write community in `from_config`.
- `tests/equivalence.py` — extend `facades_for` to inject write clients; add `assert_write_equivalent`.

**New test files:**
- `tests/protocols/snmp/test_write_encode.py`
- `tests/transport/test_set_transport.py`
- `tests/virtual/test_mutable_state.py`
- `tests/test_snmp_write.py`
- `tests/test_write_equivalence.py`

---

### Task 1: Write encoding helpers + write OID constants

**Files:**
- Create: `src/netgear_switch/protocols/snmp/write.py`
- Modify: `src/netgear_switch/protocols/snmp/oids.py`
- Modify: `src/netgear_switch/virtual/state.py` (make its `encode_port_bitmap` delegate to the new canonical bytes encoder — single source of truth for the bit-packing)
- Test: `tests/protocols/snmp/test_write_encode.py`

**Interfaces:**
- Consumes: `parse.decode_port_bitmap` (existing, in `protocols/snmp/parse.py`); `models.VlanMode`.
- Produces:
  - `SetVarbind(oid: str, value: int | str | bytes, type_letter: str)` — frozen dataclass; `type_letter` ∈ `{"i","u","s","x","a"}`; raises `ValueError` on any other letter.
  - `SET_TYPE_LETTERS: frozenset[str]`
  - `encode_port_bitmap(ports: Iterable[int], width_bytes: int = 8) -> bytes` (MSB-first, port 1 = bit 7 of byte 0) — the CANONICAL bit-packing; `virtual/state.encode_port_bitmap` is refactored to delegate to it (no second copy of the algorithm).
  - `set_port_bit(current: bytes | str, port: int, present: bool) -> bytes`
  - `membership_bitmaps(*, mode: VlanMode, port: int, egress: bytes | str, untagged: bytes | str) -> tuple[bytes, bytes]`
  - In `oids.py`: `DOT1Q_VLAN_STATIC_ROW_STATUS = "1.3.6.1.2.1.17.7.1.4.3.1.5"`, `ROW_STATUS_CREATE_AND_GO = 4`, `ROW_STATUS_DESTROY = 6`; `VendorOids` fields `mgmt_write_addr_unverified`, `mgmt_write_netmask_unverified`, `mgmt_write_gateway_unverified`.

- [ ] **Step 1: Write the failing test**

Create `tests/protocols/snmp/test_write_encode.py`:

```python
from __future__ import annotations

import pytest

from netgear_switch.models import VlanMode
from netgear_switch.protocols.snmp.parse import decode_port_bitmap
from netgear_switch.protocols.snmp.write import (
    SET_TYPE_LETTERS,
    SetVarbind,
    encode_port_bitmap,
    membership_bitmaps,
    set_port_bit,
)


def test_set_varbind_rejects_unknown_type_letter():
    with pytest.raises(ValueError):
        SetVarbind("1.3.6", 1, "z")
    assert SetVarbind("1.3.6", 1, "i").type_letter == "i"
    assert "u" in SET_TYPE_LETTERS


def test_encode_is_inverse_of_decode():
    ports = {1, 8, 9, 52}
    assert decode_port_bitmap(encode_port_bitmap(ports)) == frozenset(ports)


def test_set_port_bit_only_changes_target_bit():
    base = encode_port_bitmap({1, 2, 10, 48})  # a "trunk" set
    added = set_port_bit(base, 25, present=True)
    assert decode_port_bitmap(added) == frozenset({1, 2, 10, 25, 48})
    removed = set_port_bit(base, 10, present=False)
    assert decode_port_bitmap(removed) == frozenset({1, 2, 48})


def test_membership_bitmaps_untagged_tagged_excluded():
    egress = encode_port_bitmap({1, 2})
    untagged = encode_port_bitmap({1})
    # UNTAGGED: port in egress AND untagged.
    e, u = membership_bitmaps(mode=VlanMode.UNTAGGED, port=5, egress=egress, untagged=untagged)
    assert decode_port_bitmap(e) == frozenset({1, 2, 5})
    assert decode_port_bitmap(u) == frozenset({1, 5})
    # TAGGED: port in egress, NOT untagged.
    e, u = membership_bitmaps(mode=VlanMode.TAGGED, port=1, egress=egress, untagged=untagged)
    assert decode_port_bitmap(e) == frozenset({1, 2})
    assert decode_port_bitmap(u) == frozenset()
    # EXCLUDED: port in neither; other ports preserved.
    e, u = membership_bitmaps(mode=VlanMode.EXCLUDED, port=1, egress=egress, untagged=untagged)
    assert decode_port_bitmap(e) == frozenset({2})
    assert decode_port_bitmap(u) == frozenset()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run --extra testing pytest tests/protocols/snmp/test_write_encode.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'netgear_switch.protocols.snmp.write'`

- [ ] **Step 3: Write minimal implementation**

Create `src/netgear_switch/protocols/snmp/write.py`:

```python
"""Pure SNMP write encoding: SET varbinds and Q-BRIDGE bitmap read-modify-write.

No I/O and transport-agnostic. ``SetVarbind`` carries a net-snmp-style type
letter (``i`` INTEGER, ``u`` Gauge32/unsigned, ``s`` string, ``x`` hex/octets,
``a`` IpAddress) that both transports map onto their own SET call. The bitmap
helpers do a read-modify-write so only the target port's bit changes, leaving
trunks and other access ports untouched (design spec §6).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ...models import VlanMode
from .parse import decode_port_bitmap

if TYPE_CHECKING:
    from collections.abc import Iterable

SET_TYPE_LETTERS: frozenset[str] = frozenset({"i", "u", "s", "x", "a"})


@dataclass(frozen=True)
class SetVarbind:
    """One SNMP SET varbind: full numeric OID, value, and net-snmp type letter."""

    oid: str
    value: int | str | bytes
    type_letter: str

    def __post_init__(self) -> None:
        if self.type_letter not in SET_TYPE_LETTERS:
            raise ValueError(
                f"unknown SET type letter {self.type_letter!r}; "
                f"expected one of {sorted(SET_TYPE_LETTERS)}"
            )


def encode_port_bitmap(ports: Iterable[int], width_bytes: int = 8) -> bytes:
    """Inverse of ``parse.decode_port_bitmap``: a port set -> a wire bitmap.

    Bit 7 (MSB) of byte 0 is port 1. The buffer grows past ``width_bytes`` if a
    port number needs it, so callers never pre-size for the actual port count.
    """
    data = bytearray(width_bytes)
    for p in ports:
        byte_idx, bit = divmod(p - 1, 8)
        while byte_idx >= len(data):
            data.append(0)
        data[byte_idx] |= 0x80 >> bit
    return bytes(data)


def set_port_bit(current: bytes | str, port: int, present: bool) -> bytes:
    """Read-modify-write one port's bit in a VLAN bitmap; all others preserved."""
    ports = set(decode_port_bitmap(current))
    if present:
        ports.add(port)
    else:
        ports.discard(port)
    return encode_port_bitmap(ports)


def membership_bitmaps(
    *, mode: VlanMode, port: int, egress: bytes | str, untagged: bytes | str
) -> tuple[bytes, bytes]:
    """Compute (new_egress, new_untagged) for one port's VLAN membership change.

    UNTAGGED -> egress bit on + untagged bit on; TAGGED -> egress on, untagged
    off; EXCLUDED -> both off. Read-modify-write on the current bitmaps, so
    every other port's membership is preserved.
    """
    in_egress = mode in (VlanMode.UNTAGGED, VlanMode.TAGGED)
    in_untagged = mode is VlanMode.UNTAGGED
    return (
        set_port_bit(egress, port, in_egress),
        set_port_bit(untagged, port, in_untagged),
    )
```

Then in `src/netgear_switch/protocols/snmp/oids.py`, add after the `DOT1Q_PVID` line (line 33):

```python
DOT1Q_VLAN_STATIC_ROW_STATUS = "1.3.6.1.2.1.17.7.1.4.3.1.5"  # dot1qVlanStaticRowStatus
ROW_STATUS_CREATE_AND_GO = 4  # RowStatus createAndGo
ROW_STATUS_DESTROY = 6        # RowStatus destroy
```

And add the UNVERIFIED mgmt-IP write OIDs to `VendorOids`. Add three fields to the dataclass (after `dhcp_mode_unverified`, line 73-76):

```python
    mgmt_write_addr_unverified: str
    mgmt_write_netmask_unverified: str
    mgmt_write_gateway_unverified: str
    """UNVERIFIED writable management-IP OIDs — placeholders pending Slice 7
    hardware capture. They are NEVER trusted on real hardware (set_mgmt_ip is
    force-gated and documented UNVERIFIED); they exist so the mutable mock and
    the writer agree under test, mirroring the ``dhcp_mode_unverified``
    precedent above. No call site may hard-code these literals."""
```

And populate them in `vendor_oids()` (inside the returned `VendorOids(...)`, after `dhcp_mode_unverified=...`):

```python
        mgmt_write_addr_unverified=f"{base}.98.1",
        mgmt_write_netmask_unverified=f"{base}.98.2",
        mgmt_write_gateway_unverified=f"{base}.98.3",
```

Finally, de-duplicate the bit-packing so there is ONE source of truth. `src/netgear_switch/virtual/state.py` already defines its own `encode_port_bitmap` (returning a latin-1 `str`) with the identical MSB-first algorithm; leaving two independent copies risks a future off-by-one desync between what the writer computes and what the mock projects. Make the state helper delegate to the new canonical bytes encoder and just decode to `str`. Replace the body of `encode_port_bitmap` in `state.py` (keep its `-> str` signature and docstring intact for its callers):

```python
def encode_port_bitmap(ports: set[int], width_bytes: int = 8) -> str:
    """Inverse of ``parse.decode_port_bitmap``: a port set -> a latin-1 bitmap.

    Delegates to the canonical bytes encoder in
    ``protocols/snmp/write.encode_port_bitmap`` (single source of truth for the
    MSB-first bit-packing) and decodes to the latin-1 ``str`` this module's
    callers expect.
    """
    from ..protocols.snmp.write import encode_port_bitmap as _encode_bytes

    return _encode_bytes(ports, width_bytes).decode("latin-1")
```

(`write.encode_port_bitmap` takes any `Iterable[int]`, so the `set[int]` argument is accepted unchanged. The import is function-local to avoid a package import cycle at module load.)

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run --extra testing pytest tests/protocols/snmp/test_write_encode.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add src/netgear_switch/protocols/snmp/write.py src/netgear_switch/protocols/snmp/oids.py src/netgear_switch/virtual/state.py tests/protocols/snmp/test_write_encode.py
git commit -m "feat(snmp): pure write encoding helpers + write OID constants (single bitmap encoder)"
```

---

### Task 2: Write-client Protocols + sync SET transport

**Files:**
- Modify: `src/netgear_switch/protocols/snmp/client.py`
- Modify: `src/netgear_switch/transport/sync/snmp_netsnmp_cli.py`
- Test: `tests/transport/test_set_transport.py`

**Interfaces:**
- Consumes: `SetVarbind` from `protocols/snmp/write.py`; `SnmpError`, `SnmpClient`, `AsyncSnmpClient` from `client.py`.
- Produces:
  - `SnmpWriteClient(SnmpClient, Protocol)` with `set(varbind: SetVarbind) -> None` and `set_many(varbinds: list[SetVarbind]) -> None`.
  - `AsyncSnmpWriteClient(AsyncSnmpClient, Protocol)` with async `set` / `set_many`.
  - `NetsnmpCliClient.set` / `.set_many` (net-snmp `snmpset`); atomic (one PDU). Raises `SnmpError` on non-zero exit / stderr (covers commitFailed, noSuchName, wrong type).

- [ ] **Step 1: Write the failing test**

Create `tests/transport/test_set_transport.py`:

```python
from __future__ import annotations

import pytest

from netgear_switch.protocols.snmp.client import SnmpError
from netgear_switch.protocols.snmp.write import SetVarbind
from netgear_switch.transport.sync.snmp_netsnmp_cli import NetsnmpCliClient


class _Proc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_set_builds_snmpset_argv_with_type_letters():
    captured: list[list[str]] = []

    def runner(argv, **kwargs):
        captured.append(argv)
        # snmpset echoes the varbind back on success.
        return _Proc(stdout="1.3.6.1.2.1.2.2.1.7.5 = INTEGER: 2\n")

    client = NetsnmpCliClient("host", "writecomm", runner=runner)
    client.set(SetVarbind("1.3.6.1.2.1.2.2.1.7.5", 2, "i"))

    argv = captured[0]
    assert argv[0].endswith("snmpset")
    assert "-c" in argv and "writecomm" in argv
    # trailing: <host> <oid> <type> <value>
    assert argv[-4:] == ["host", "1.3.6.1.2.1.2.2.1.7.5", "i", "2"]


def test_set_many_is_one_pdu_with_hex_for_x_type():
    captured: list[list[str]] = []

    def runner(argv, **kwargs):
        captured.append(argv)
        return _Proc(stdout="")

    client = NetsnmpCliClient("host", "w", runner=runner)
    client.set_many([
        SetVarbind("1.3.6.1.2.1.17.7.1.4.5.1.1.5", 90, "u"),
        SetVarbind("1.3.6.1.2.1.17.7.1.4.3.1.2.90", bytes([0xC0, 0x00]), "x"),
    ])
    assert len(captured) == 1  # single snmpset invocation = atomic PDU
    argv = captured[0]
    assert argv[-6:] == [
        "1.3.6.1.2.1.17.7.1.4.5.1.1.5", "u", "90",
        "1.3.6.1.2.1.17.7.1.4.3.1.2.90", "x", "c000",
    ]


def test_set_raises_snmperror_on_commit_failed():
    def runner(argv, **kwargs):
        return _Proc(returncode=1, stderr="Error in packet.\nReason: commitFailed")

    client = NetsnmpCliClient("host", "w", runner=runner)
    with pytest.raises(SnmpError) as exc:
        client.set(SetVarbind("1.3.6.1.2.1.2.2.1.7.5", 2, "i"))
    assert "commitFailed" in str(exc.value)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run --extra testing pytest tests/transport/test_set_transport.py -v`
Expected: FAIL with `AttributeError: 'NetsnmpCliClient' object has no attribute 'set'`

- [ ] **Step 3: Write minimal implementation**

In `src/netgear_switch/protocols/snmp/client.py`, add after the `AsyncSnmpClient` Protocol (end of file). First extend the imports at the top — add under the existing `from typing import Protocol`:

```python
from typing import TYPE_CHECKING, Protocol
```

and after the existing `if`-free import block, add a guarded import for the type-only reference:

```python
if TYPE_CHECKING:
    from .write import SetVarbind
```

Then append the two write Protocols to the end of the file:

```python
class SnmpWriteClient(SnmpClient, Protocol):
    """Synchronous SNMP v2c read+write client for a single switch.

    Extends the read client with SET. ``set_many`` is one PDU (atomic). A write
    RW community can also read, so a single write client verifies its own
    writes via the inherited ``get``/``walk``.
    """

    def set(self, varbind: SetVarbind) -> None: ...

    def set_many(self, varbinds: list[SetVarbind]) -> None: ...


class AsyncSnmpWriteClient(AsyncSnmpClient, Protocol):
    """Asynchronous SNMP v2c read+write client for a single switch."""

    async def set(self, varbind: SetVarbind) -> None: ...

    async def set_many(self, varbinds: list[SetVarbind]) -> None: ...
```

In `src/netgear_switch/transport/sync/snmp_netsnmp_cli.py`, add the import near the top (with the existing `from ...protocols.snmp.client import SnmpError, SnmpRow`):

```python
from ...protocols.snmp.write import SetVarbind
```

Add a module-level helper (after `_TIMETICKS_RE`, before `_CompletedProcess`):

```python
def _format_set_value(vb: SetVarbind) -> str:
    """Render a SetVarbind value as the string snmpset expects for its type.

    ``x`` (hex/octets) is emitted as lowercase hex digits; every other type is
    stringified directly (net-snmp parses ``i``/``u``/``s``/``a`` from text).
    """
    if vb.type_letter == "x":
        data = vb.value if isinstance(vb.value, bytes) else str(vb.value).encode("latin-1")
        return data.hex()
    return str(vb.value)
```

Add `set`/`set_many` methods to `NetsnmpCliClient` (after `walk`, before `_invoke`):

```python
    def set(self, varbind: SetVarbind) -> None:
        self.set_many([varbind])

    def set_many(self, varbinds: list[SetVarbind]) -> None:
        if not varbinds:
            return
        triples: list[str] = []
        for vb in varbinds:
            triples += [vb.oid, vb.type_letter, _format_set_value(vb)]
        argv = [*self._base_args("snmpset"), self.host, *triples]
        # _invoke raises SnmpError on non-zero exit or any stderr (commitFailed,
        # noSuchName, wrong type). The echoed varbinds it parses are discarded.
        self._invoke(argv)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run --extra testing pytest tests/transport/test_set_transport.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add src/netgear_switch/protocols/snmp/client.py src/netgear_switch/transport/sync/snmp_netsnmp_cli.py tests/transport/test_set_transport.py
git commit -m "feat(snmp): write-client Protocols + sync snmpset transport"
```

---

### Task 3: Async SET transport (pysnmp set_cmd)

**Files:**
- Modify: `src/netgear_switch/transport/aio/snmp_pysnmp.py`
- Test: `tests/transport/test_set_transport.py` (add async-value-mapping cases)

**Interfaces:**
- Consumes: `SetVarbind`; the lazy `_pysnmp_asyncio()` hlapi seam.
- Produces:
  - `_to_set_value(hlapi: Any, vb: SetVarbind) -> Any` — maps a type letter to a pysnmp SMI value (testable offline with a fake hlapi).
  - `PysnmpClient.set` / `.set_many` (one `set_cmd` PDU); errors → `SnmpError`.

- [ ] **Step 1: Write the failing test**

Append to `tests/transport/test_set_transport.py`:

```python
from netgear_switch.transport.aio.snmp_pysnmp import _to_set_value


class _FakeHlapi:
    """Records which SMI constructor was used, mirroring the value_parity fake."""

    class Integer32:
        def __init__(self, v): self.kind, self.v = "Integer32", v

    class Gauge32:
        def __init__(self, v): self.kind, self.v = "Gauge32", v

    class OctetString:
        def __init__(self, v): self.kind, self.v = "OctetString", v

    class IpAddress:
        def __init__(self, v): self.kind, self.v = "IpAddress", v


def test_to_set_value_maps_type_letters():
    h = _FakeHlapi()
    assert (_to_set_value(h, SetVarbind("o", 2, "i")).kind, _to_set_value(h, SetVarbind("o", 2, "i")).v) == ("Integer32", 2)
    assert _to_set_value(h, SetVarbind("o", 90, "u")).kind == "Gauge32"
    assert _to_set_value(h, SetVarbind("o", "iot", "s")).v == b"iot"
    assert _to_set_value(h, SetVarbind("o", bytes([0xC0, 0x00]), "x")).v == bytes([0xC0, 0x00])
    ip = _to_set_value(h, SetVarbind("o", "10.1.5.20", "a"))
    assert (ip.kind, ip.v) == ("IpAddress", "10.1.5.20")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run --extra testing pytest tests/transport/test_set_transport.py::test_to_set_value_maps_type_letters -v`
Expected: FAIL with `ImportError: cannot import name '_to_set_value'`

- [ ] **Step 3: Write minimal implementation**

In `src/netgear_switch/transport/aio/snmp_pysnmp.py`, add the import (with the existing `from ...protocols.snmp.client import ...`):

```python
from ...protocols.snmp.write import SetVarbind
```

Add the pure mapping helper (after `_normalize_varbind`, before `class PysnmpClient`):

```python
def _to_set_value(hlapi: Any, vb: SetVarbind) -> Any:
    """Map a SetVarbind's type letter to the matching pysnmp SMI value object.

    ``s`` and ``x`` both become OctetString (bytes on the wire); ``s`` str
    values are latin-1 encoded (the inverse of the read normalizer). Kept as a
    plain function taking ``hlapi`` so it is unit-testable with a fake module,
    with no live pysnmp import.
    """
    if vb.type_letter == "i":
        return hlapi.Integer32(int(vb.value))
    if vb.type_letter == "u":
        return hlapi.Gauge32(int(vb.value))
    if vb.type_letter == "a":
        return hlapi.IpAddress(str(vb.value))
    if vb.type_letter in ("s", "x"):
        data = vb.value if isinstance(vb.value, bytes) else str(vb.value).encode("latin-1")
        return hlapi.OctetString(data)
    raise SnmpError(f"unsupported SET type letter {vb.type_letter!r}")
```

Add `set`/`set_many` to `PysnmpClient` (after `walk`, end of class):

```python
    async def _do_set(self, varbinds: list[SetVarbind]) -> None:
        hlapi = _pysnmp_asyncio()
        engine = hlapi.SnmpEngine()
        try:
            target = await hlapi.UdpTransportTarget.create(
                (self.host, self.port), timeout=self.timeout, retries=self.retries
            )
            objects = [
                hlapi.ObjectType(hlapi.ObjectIdentity(vb.oid), _to_set_value(hlapi, vb))
                for vb in varbinds
            ]
            err_ind, err_stat, _idx, _binds = await hlapi.set_cmd(
                engine, hlapi.CommunityData(self.community), target,
                hlapi.ContextData(), *objects,
            )
            if err_ind or err_stat:
                raise SnmpError(
                    f"SET {[vb.oid for vb in varbinds]} on {self.host}: "
                    f"{err_ind or err_stat}"
                )
        finally:
            engine.close_dispatcher()

    async def set(self, varbind: SetVarbind) -> None:
        await self.set_many([varbind])

    async def set_many(self, varbinds: list[SetVarbind]) -> None:
        if not varbinds:
            return
        try:
            await self._do_set(varbinds)
        except SnmpError:
            raise
        except Exception as exc:
            raise SnmpError(
                f"SET {[vb.oid for vb in varbinds]} on {self.host} failed: {exc}"
            ) from exc
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run --extra testing pytest tests/transport/test_set_transport.py -v`
Expected: PASS (4 tests total)

- [ ] **Step 5: Commit**

```bash
git add src/netgear_switch/transport/aio/snmp_pysnmp.py tests/transport/test_set_transport.py
git commit -m "feat(snmp): async pysnmp set_cmd transport with SMI value mapping"
```

---

### Task 4: Mutable virtual mock (state SET + coherence + face SetCommandResponder)

**Files:**
- Modify: `src/netgear_switch/virtual/state.py`
- Modify: `src/netgear_switch/virtual/faces/mibview.py`
- Modify: `src/netgear_switch/virtual/faces/snmp.py`
- Test: `tests/virtual/test_mutable_state.py`

**Interfaces:**
- Consumes: `parse.decode_port_bitmap`; `oids` constants incl. `DOT1Q_VLAN_STATIC_ROW_STATUS`, `ROW_STATUS_CREATE_AND_GO`, `ROW_STATUS_DESTROY`, mgmt-write OIDs.
- Produces:
  - `VirtualSwitchState.apply_write(oid: str, value: int | bytes | str) -> None` — mutates state with coherence (PoE admin off → detect=1 + link down; on → detect=3).
  - `StateMibView.rebuild() -> None` and `StateMibView.apply_write(oid, value) -> None` (mutate state then rebuild).
  - `_StateInstrum.write_variables(*var_binds, **context)` (guards each `apply_write`, mapping any unexpected exception to a pysnmp `WrongValueError` so it never leaks into the dispatcher) and a `SetCommandResponder` bound in `_run`; `writeSubTree=(1, 3, 6, 1)` VACM.

- [ ] **Step 1: Write the failing test** (pure state-level, no pysnmp)

Create `tests/virtual/test_mutable_state.py`:

```python
from __future__ import annotations

from netgear_switch.protocols.snmp import oids
from netgear_switch.protocols.snmp.parse import decode_port_bitmap
from netgear_switch.protocols.snmp.write import encode_port_bitmap
from netgear_switch.virtual.seed import seed_gsm7252ps


def test_apply_write_poe_admin_off_sets_detect_and_link_down():
    st = seed_gsm7252ps()
    assert st.poe[1].admin is True and st.poe[1].detect == 3
    st.apply_write(f"{oids.PETH_PSE_PORT_TABLE}.3.1.1", 2)  # admin disable
    assert st.poe[1].admin is False
    assert st.poe[1].detect == 1        # unused/disabled
    assert st.ports[1].link is False    # coherence: link drops
    st.apply_write(f"{oids.PETH_PSE_PORT_TABLE}.3.1.1", 1)  # admin enable
    assert st.poe[1].admin is True
    assert st.poe[1].detect == 3        # delivering


def test_apply_write_ifadmin_and_pvid():
    st = seed_gsm7252ps()
    st.apply_write(f"{oids.IF_ADMIN_STATUS}.3", 2)
    assert st.ports[3].admin is False
    st.apply_write(f"{oids.DOT1Q_PVID}.10", 90)
    assert st.pvids[10] == 90


def test_apply_write_vlan_membership_rmw_and_rowstatus():
    st = seed_gsm7252ps()
    new_egress = encode_port_bitmap({1, 2, 10, 25})  # add port 25 to vlan 90
    st.apply_write(f"{oids.DOT1Q_VLAN_STATIC_EGRESS}.90", new_egress)
    assert decode_port_bitmap(encode_port_bitmap(st.vlans[90].member)) == frozenset({1, 2, 10, 25})
    # create VLAN 200 via RowStatus + name.
    st.apply_write(f"{oids.DOT1Q_VLAN_STATIC_ROW_STATUS}.200", oids.ROW_STATUS_CREATE_AND_GO)
    st.apply_write(f"{oids.DOT1Q_VLAN_STATIC_NAME}.200", b"guests")
    assert st.vlans[200].name == "guests"
    # destroy it.
    st.apply_write(f"{oids.DOT1Q_VLAN_STATIC_ROW_STATUS}.200", oids.ROW_STATUS_DESTROY)
    assert 200 not in st.vlans


def test_apply_write_mgmt_ip_updates_read_projection():
    st = seed_gsm7252ps()
    v = oids.vendor_oids.__wrapped__ if hasattr(oids.vendor_oids, "__wrapped__") else None
    from netgear_switch.registry import get_model
    vo = oids.vendor_oids(get_model("gsm7252ps"))
    st.apply_write(vo.mgmt_write_addr_unverified, "10.9.9.9")
    assert st.mgmt.address == "10.9.9.9"
    # read projection now advertises the new address in ipAddrTable.
    assert any(k.startswith(f"{oids.IP_ADENT_ADDR}.10.9.9.9") for k in st.oid_map())
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run --extra testing pytest tests/virtual/test_mutable_state.py -v`
Expected: FAIL with `AttributeError: 'VirtualSwitchState' object has no attribute 'apply_write'`

- [ ] **Step 3: Write minimal implementation**

In `src/netgear_switch/virtual/state.py`, add `apply_write` as a method on `VirtualSwitchState` (after `oid_map`). It dispatches by OID prefix; unknown writable OIDs are echoed (no-op) so the mock never fabricates state:

```python
    def apply_write(self, oid: str, value: int | bytes | str) -> None:
        """Mutate this state from one SNMP SET varbind, with device coherence.

        Dispatches on the OID's column prefix. Applies the same coherence a real
        PoE switch shows so ``cycle_poe`` terminates against the mock: admin off
        -> detect=1 (unused) + data-port link down; admin on -> detect=3
        (delivering). Unhandled writable OIDs are a deliberate no-op (the write
        "succeeds" but reads back unchanged), which is exactly what a
        verify-after-write must catch.
        """
        from ..protocols.snmp import oids
        from ..registry import get_model

        v = oids.vendor_oids(get_model(self.model_key))

        def _tail(base: str) -> int | None:
            prefix = base + "."
            if oid.startswith(prefix) and oid[len(prefix):].isdigit():
                return int(oid[len(prefix):])
            return None

        def _as_bytes(val: int | bytes | str) -> bytes:
            if isinstance(val, bytes):
                return val
            if isinstance(val, str):
                return val.encode("latin-1")
            return bytes([val])

        # ifAdminStatus.<port>
        port = _tail(oids.IF_ADMIN_STATUS)
        if port is not None and port in self.ports:
            self.ports[port].admin = int(value) == 1
            if int(value) != 1:
                self.ports[port].link = False
            return

        # pethPsePortAdminEnable = <table>.3.1.<port>
        poe_prefix = f"{oids.PETH_PSE_PORT_TABLE}.3.1."
        if oid.startswith(poe_prefix) and oid[len(poe_prefix):].isdigit():
            p = int(oid[len(poe_prefix):])
            if p in self.poe:
                on = int(value) == 1
                self.poe[p].admin = on
                self.poe[p].detect = 3 if on else 1  # delivering / unused
                if not on and p in self.ports:
                    self.ports[p].link = False
            return

        # dot1qPvid.<port>
        port = _tail(oids.DOT1Q_PVID)
        if port is not None:
            self.pvids[port] = int(value)
            return

        # dot1qVlanStaticEgressPorts.<vid>
        vid = _tail(oids.DOT1Q_VLAN_STATIC_EGRESS)
        if vid is not None and vid in self.vlans:
            from ..protocols.snmp.parse import decode_port_bitmap
            self.vlans[vid].member = set(decode_port_bitmap(_as_bytes(value)))
            return

        # dot1qVlanStaticUntaggedPorts.<vid>
        vid = _tail(oids.DOT1Q_VLAN_STATIC_UNTAGGED)
        if vid is not None and vid in self.vlans:
            from ..protocols.snmp.parse import decode_port_bitmap
            self.vlans[vid].untagged = set(decode_port_bitmap(_as_bytes(value)))
            return

        # dot1qVlanStaticRowStatus.<vid>  (createAndGo=4 / destroy=6)
        vid = _tail(oids.DOT1Q_VLAN_STATIC_ROW_STATUS)
        if vid is not None:
            if int(value) == oids.ROW_STATUS_DESTROY:
                self.vlans.pop(vid, None)
            elif int(value) == oids.ROW_STATUS_CREATE_AND_GO and vid not in self.vlans:
                self.vlans[vid] = VlanSim(name="")
            return

        # dot1qVlanStaticName.<vid>
        vid = _tail(oids.DOT1Q_VLAN_STATIC_NAME)
        if vid is not None:
            name = value.decode("latin-1") if isinstance(value, bytes) else str(value)
            if vid in self.vlans:
                self.vlans[vid].name = name
            else:
                self.vlans[vid] = VlanSim(name=name)
            return

        # UNVERIFIED mgmt-IP write OIDs -> MgmtSim (read projection follows).
        if oid == v.mgmt_write_addr_unverified:
            self.mgmt.address = str(value)
            return
        if oid == v.mgmt_write_netmask_unverified:
            self.mgmt.netmask = str(value)
            return
        if oid == v.mgmt_write_gateway_unverified:
            self.mgmt.gateway = str(value)
            return
        # Unhandled writable OID: deliberate no-op (verify-after-write catches it).
```

In `src/netgear_switch/virtual/faces/mibview.py`, keep a live state ref and add `rebuild`/`apply_write`. Replace `StateMibView.__init__` and add the two methods:

```python
    def __init__(self, state: VirtualSwitchState) -> None:
        self._state = state
        self._load()

    def _load(self) -> None:
        entries: list[_Entry] = [
            (_oid_to_tuple(oid), snmp_type, value)
            for oid, (snmp_type, value) in self._state.oid_map().items()
        ]
        entries.sort(key=lambda e: e[0])
        self._entries = entries
        self._oids = [e[0] for e in entries]

    def rebuild(self) -> None:
        """Recompute the sorted view from current state (call after a write)."""
        self._load()

    def apply_write(self, oid: str, value: int | bytes | str) -> None:
        """Mutate the underlying state then rebuild so reads reflect the write."""
        self._state.apply_write(oid, value)
        self.rebuild()
```

In `src/netgear_switch/virtual/faces/snmp.py`:

Add a SMI→python converter (after `_to_smi_value`):

```python
def _from_smi_value(value: Any) -> int | bytes | str:
    """Convert an incoming pysnmp SET value to a plain Python value for the mock."""
    cls = value.__class__.__name__
    if cls in ("Integer", "Integer32", "Gauge32", "Unsigned32"):
        return int(value)
    if cls == "OctetString":
        return bytes(value.asOctets())
    if cls == "IpAddress":
        return str(value.prettyPrint())
    return str(value.prettyPrint())
```

Add a lazy seam for the pysnmp SMI error module (next to `_pysnmp_rfc1905`):

```python
def _pysnmp_smi_error() -> Any:
    return importlib.import_module("pysnmp.smi.error")
```

Extend `_StateInstrum.__init__` to also capture the SMI error class used to signal a failed SET (keep the existing NoSuchInstance/EndOfMibView capture):

```python
    def __init__(self, view: StateMibView) -> None:
        self._view = view
        rfc1905 = _pysnmp_rfc1905()
        self._no_such_instance = rfc1905.noSuchInstance
        self._end_of_mib_view = rfc1905.endOfMibView
        self._write_error = _pysnmp_smi_error().WrongValueError
```

Add `write_variables` to `_StateInstrum` (after `read_next_variables`). Each varbind's `apply_write` is wrapped so any unexpected exception (e.g. a malformed bitmap or bad value type) is mapped to a proper pysnmp SMI error — which the command responder turns into a clean SNMP error-status — instead of propagating into the asyncio dispatcher (which would surface to the client as a *timeout*, i.e. a flaky failure). The read paths' NoSuchObject/NoSuchInstance handling above is unchanged:

```python
    def write_variables(
        self, *var_binds: tuple[Any, Any], **_context: Any
    ) -> list[tuple[Any, Any]]:
        """Answer a SET: mutate state per varbind, echo the written varbinds.

        A failure in ``apply_write`` (malformed value, unexpected type, ...) is
        converted to a pysnmp ``WrongValueError`` so the responder returns a
        clean SNMP error-status; it is never allowed to escape into the
        dispatcher (which the client would observe as a timeout = flaky test).
        """
        out: list[tuple[Any, Any]] = []
        for name, val in var_binds:
            oid = ".".join(str(x) for x in tuple(name))
            try:
                self._view.apply_write(oid, _from_smi_value(val))
            except Exception as exc:  # noqa: BLE001 - map to SMI error, never leak
                # A pysnmp MibOperationError subclass carries name/idx kwargs and
                # is turned into a clean SNMP error-status by the responder. (If
                # the pysnmp v7 kwargs differ, adjust here — same duck-typing risk
                # noted for write_variables in the Self-Review Notes.)
                raise self._write_error(name=name, idx=None) from exc
            out.append((name, val))
        return out
```

In `VirtualSnmpFace._run`, add the SET responder and grant write access. Change the `add_vacm_user` call to include `writeSubTree`:

```python
            config.add_vacm_user(
                engine,
                _SNMP_V2C_SECURITY_MODEL,
                "netgear-virtual",
                "noAuthNoPriv",
                readSubTree=(1, 3, 6, 1),
                writeSubTree=(1, 3, 6, 1),
            )
```

and after `cmdrsp.BulkCommandResponder(engine, snmp_context)` add:

```python
            cmdrsp.SetCommandResponder(engine, snmp_context)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run --extra testing pytest tests/virtual/test_mutable_state.py -v`
Expected: PASS (4 tests). Simplify the `v = oids.vendor_oids.__wrapped__...` line in the mgmt test to just use the `vo` computed below it (delete the unused `v` line before committing).

- [ ] **Step 5: Commit**

```bash
git add src/netgear_switch/virtual/state.py src/netgear_switch/virtual/faces/mibview.py src/netgear_switch/virtual/faces/snmp.py tests/virtual/test_mutable_state.py
git commit -m "feat(virtual): mutable state + pysnmp SET responder with device coherence"
```

---

### Task 5: SnmpWriter core — set_poe / set_port_enabled + verify-after-write + protected-port guard

**Files:**
- Create: `src/netgear_switch/snmp_write.py`
- Modify: `src/netgear_switch/errors.py`
- Test: `tests/test_snmp_write.py`

**Interfaces:**
- Consumes: `SnmpWriteClient` / `AsyncSnmpWriteClient`; `SnmpReader` / `AsyncSnmpReader` (verify reads); `SetVarbind`; `oids`; `WriteVerificationError`.
- Produces:
  - `errors.ProtectedPortError(NetgearSwitchError)`.
  - `SnmpWriter(client: SnmpWriteClient, model: SwitchModel, *, protected_ports: frozenset[int] = frozenset())`.
  - `SnmpWriter.set_poe(port: int, on: bool, *, force: bool = False) -> None`
  - `SnmpWriter.set_port_enabled(port: int, enabled: bool, *, force: bool = False) -> None`
  - `AsyncSnmpWriter` mirror (async methods).
  - Internal helpers reused by later tasks: `_guard(port, force)`, `_poe_status(port)`, `_verify(...)`.

- [ ] **Step 1: Write the failing test**

First add the error. In `src/netgear_switch/errors.py`, after `UnsupportedCapabilityError`:

```python
class ProtectedPortError(NetgearSwitchError):
    """A disruptive write targeted a protected port without force=True."""
```

Create `tests/test_snmp_write.py`:

```python
from __future__ import annotations

import pytest

from netgear_switch.errors import ProtectedPortError, WriteVerificationError
from netgear_switch.protocols.snmp import oids
from netgear_switch.protocols.snmp.client import SnmpRow
from netgear_switch.protocols.snmp.write import SetVarbind
from netgear_switch.registry import get_model
from netgear_switch.snmp_write import SnmpWriter


class FakeWriteClient:
    """Read tables keyed by base OID; SETs recorded and (optionally) applied."""

    def __init__(self, tables=None, apply=True):
        self._tables = tables or {}
        self.sets: list[SetVarbind] = []
        self._apply = apply

    def get(self, oids_):
        return [row for oid in oids_ for row in self.walk(oid)]

    def walk(self, base_oid):
        return list(self._tables.get(base_oid, []))

    def set(self, vb):
        self.set_many([vb])

    def set_many(self, vbs):
        self.sets.extend(vbs)
        if not self._apply:
            return
        for vb in vbs:  # crude apply: overwrite the exact leaf row
            base, _, idx = vb.oid.rpartition(".")
            self._tables.setdefault(base, [])
            self._tables[base] = [r for r in self._tables[base] if r.oid != vb.oid]
            self._tables[base].append(SnmpRow(vb.oid, int(vb.value), "INTEGER"))


def _poe_tables(admin=1, detect=3):
    return {
        oids.PETH_PSE_PORT_TABLE: [
            SnmpRow(f"{oids.PETH_PSE_PORT_TABLE}.3.1.5", admin, "INTEGER"),
            SnmpRow(f"{oids.PETH_PSE_PORT_TABLE}.6.1.5", detect, "INTEGER"),
        ],
    }


def test_set_poe_off_issues_correct_set_and_verifies():
    client = FakeWriteClient(_poe_tables(admin=1))
    w = SnmpWriter(client, get_model("gsm7252ps"))
    w.set_poe(5, on=False)
    assert client.sets == [SetVarbind(f"{oids.PETH_PSE_PORT_TABLE}.3.1.5", 2, "i")]


def test_set_poe_verification_failure_raises():
    client = FakeWriteClient(_poe_tables(admin=1), apply=False)  # device ignores write
    w = SnmpWriter(client, get_model("gsm7252ps"))
    with pytest.raises(WriteVerificationError) as exc:
        w.set_poe(5, on=False)
    assert exc.value.after is not None


def test_protected_port_blocks_disruptive_write_without_force():
    client = FakeWriteClient(_poe_tables())
    w = SnmpWriter(client, get_model("gsm7252ps"), protected_ports=frozenset({5}))
    with pytest.raises(ProtectedPortError):
        w.set_poe(5, on=False)
    assert client.sets == []            # nothing sent
    w.set_poe(5, on=False, force=True)  # force bypasses the guard
    assert client.sets


def test_set_port_enabled_disable_sets_ifadmin_2():
    tables = {oids.IF_ADMIN_STATUS: [SnmpRow(f"{oids.IF_ADMIN_STATUS}.5", 1, "INTEGER")],
              oids.IF_OPER_STATUS: [SnmpRow(f"{oids.IF_OPER_STATUS}.5", 1, "INTEGER")],
              oids.IF_HIGH_SPEED: [SnmpRow(f"{oids.IF_HIGH_SPEED}.5", 1000, "Gauge32")],
              oids.IF_NAME: [SnmpRow(f"{oids.IF_NAME}.5", "1/0/5", "STRING")]}
    client = FakeWriteClient(tables)
    w = SnmpWriter(client, get_model("gsm7252ps"))
    w.set_port_enabled(5, enabled=False, force=True)
    assert client.sets == [SetVarbind(f"{oids.IF_ADMIN_STATUS}.5", 2, "i")]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run --extra testing pytest tests/test_snmp_write.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'netgear_switch.snmp_write'`

- [ ] **Step 3: Write minimal implementation**

Create `src/netgear_switch/snmp_write.py`:

```python
"""Model-driven SNMP write/control over a write-capable sync or async client.

Parallel to ``snmp_read.py``. Every write performs the SET then re-reads and
verifies (``WriteVerificationError`` with before/after on mismatch — a real
``commitFailed`` surfaces as an ``SnmpError`` from the transport first).
Disruptive writes to a ``protected_ports`` port are refused unless ``force=True``
(design spec §6).
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from .errors import ProtectedPortError, UnsupportedCapabilityError, WriteVerificationError
from .protocols.snmp import oids
from .protocols.snmp.write import SetVarbind
from .registry import Backend
from .snmp_read import AsyncSnmpReader, SnmpReader

if TYPE_CHECKING:
    from .models import PoEStatus, PortStatus
    from .protocols.snmp.client import AsyncSnmpWriteClient, SnmpWriteClient
    from .registry import SwitchModel


def _require_snmp(model: SwitchModel) -> None:
    if Backend.SNMP not in model.backends:
        raise UnsupportedCapabilityError(f"model {model.key!r} has no SNMP backend")


def _poe_admin_oid(port: int) -> str:
    return f"{oids.PETH_PSE_PORT_TABLE}.3.1.{port}"


class SnmpWriter:
    """Synchronous SNMP write facade over one switch."""

    def __init__(
        self,
        client: SnmpWriteClient,
        model: SwitchModel,
        *,
        protected_ports: frozenset[int] = frozenset(),
    ) -> None:
        _require_snmp(model)
        self.client = client
        self.model = model
        self.protected_ports = protected_ports
        self._reader = SnmpReader(client, model)

    def _guard(self, port: int, force: bool) -> None:
        if port in self.protected_ports and not force:
            raise ProtectedPortError(
                f"port {port} is protected; pass force=True to override"
            )

    def _poe_status(self, port: int) -> PoEStatus | None:
        return next((p for p in self._reader.get_poe() if p.port == port), None)

    def _port_status(self, port: int) -> PortStatus | None:
        return next((p for p in self._reader.get_ports() if p.port == port), None)

    def set_poe(self, port: int, on: bool, *, force: bool = False) -> None:
        if not on:
            self._guard(port, force)  # turning PoE off is disruptive
        before = self._poe_status(port)
        self.client.set(SetVarbind(_poe_admin_oid(port), 1 if on else 2, "i"))
        after = self._poe_status(port)
        if after is None or after.admin_enabled != on:
            raise WriteVerificationError(
                f"PoE admin for port {port} did not read back as {on}",
                before=before, after=after,
            )

    def set_port_enabled(self, port: int, enabled: bool, *, force: bool = False) -> None:
        if not enabled:
            self._guard(port, force)  # disabling a port is disruptive
        before = self._port_status(port)
        self.client.set(SetVarbind(f"{oids.IF_ADMIN_STATUS}.{port}", 1 if enabled else 2, "i"))
        after = self._port_status(port)
        if after is None or after.admin_enabled != enabled:
            raise WriteVerificationError(
                f"admin state for port {port} did not read back as {enabled}",
                before=before, after=after,
            )


class AsyncSnmpWriter:
    """Asynchronous SNMP write facade (mirror of SnmpWriter)."""

    def __init__(
        self,
        client: AsyncSnmpWriteClient,
        model: SwitchModel,
        *,
        protected_ports: frozenset[int] = frozenset(),
    ) -> None:
        _require_snmp(model)
        self.client = client
        self.model = model
        self.protected_ports = protected_ports
        self._reader = AsyncSnmpReader(client, model)

    def _guard(self, port: int, force: bool) -> None:
        if port in self.protected_ports and not force:
            raise ProtectedPortError(
                f"port {port} is protected; pass force=True to override"
            )

    async def _poe_status(self, port: int) -> PoEStatus | None:
        return next((p for p in await self._reader.get_poe() if p.port == port), None)

    async def _port_status(self, port: int) -> PortStatus | None:
        return next((p for p in await self._reader.get_ports() if p.port == port), None)

    async def set_poe(self, port: int, on: bool, *, force: bool = False) -> None:
        if not on:
            self._guard(port, force)
        before = await self._poe_status(port)
        await self.client.set(SetVarbind(_poe_admin_oid(port), 1 if on else 2, "i"))
        after = await self._poe_status(port)
        if after is None or after.admin_enabled != on:
            raise WriteVerificationError(
                f"PoE admin for port {port} did not read back as {on}",
                before=before, after=after,
            )

    async def set_port_enabled(self, port: int, enabled: bool, *, force: bool = False) -> None:
        if not enabled:
            self._guard(port, force)
        before = await self._port_status(port)
        await self.client.set(SetVarbind(f"{oids.IF_ADMIN_STATUS}.{port}", 1 if enabled else 2, "i"))
        after = await self._port_status(port)
        if after is None or after.admin_enabled != enabled:
            raise WriteVerificationError(
                f"admin state for port {port} did not read back as {enabled}",
                before=before, after=after,
            )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run --extra testing pytest tests/test_snmp_write.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add src/netgear_switch/snmp_write.py src/netgear_switch/errors.py tests/test_snmp_write.py
git commit -m "feat(write): SnmpWriter/AsyncSnmpWriter core with verify + protected-port guard"
```

---

### Task 6: VLAN membership (read-modify-write) + PVID

**Files:**
- Modify: `src/netgear_switch/snmp_write.py`
- Test: `tests/test_snmp_write.py`

**Interfaces:**
- Consumes: `write.encode_port_bitmap`, `write.membership_bitmaps`; `models.VlanMode`, `models.VLANInfo`; `SnmpReader.get_vlans` / `get_pvids`.
- Produces:
  - `SnmpWriter.set_pvid(port: int, vlan: int, *, force: bool = False) -> None`
  - `SnmpWriter.set_vlan_membership(vlan: int, port: int, mode: VlanMode, *, force: bool = False) -> None` (RMW egress+untagged, one atomic `set_many`, other ports preserved; verify-after-write checks BOTH the egress `member_ports` and the `untagged_ports` columns; a missing VLAN is an `SnmpError` precondition, not a `WriteVerificationError`)
  - `AsyncSnmpWriter` mirrors.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_snmp_write.py`:

```python
from netgear_switch.models import VlanMode
from netgear_switch.protocols.snmp.parse import decode_port_bitmap
from netgear_switch.protocols.snmp.write import encode_port_bitmap


def _vlan_tables(vid=90, member=(1, 2, 10), untagged=(1, 2)):
    return {
        oids.DOT1Q_VLAN_STATIC_NAME: [SnmpRow(f"{oids.DOT1Q_VLAN_STATIC_NAME}.{vid}", "iot", "STRING")],
        oids.DOT1Q_VLAN_STATIC_EGRESS: [
            SnmpRow(f"{oids.DOT1Q_VLAN_STATIC_EGRESS}.{vid}", encode_port_bitmap(member), "Hex-STRING")],
        oids.DOT1Q_VLAN_STATIC_UNTAGGED: [
            SnmpRow(f"{oids.DOT1Q_VLAN_STATIC_UNTAGGED}.{vid}", encode_port_bitmap(untagged), "Hex-STRING")],
        oids.DOT1Q_PVID: [SnmpRow(f"{oids.DOT1Q_PVID}.10", 1, "Gauge32")],
    }


def test_set_pvid_sets_gauge32():
    client = FakeWriteClient(_vlan_tables())
    w = SnmpWriter(client, get_model("gsm7252ps"))
    w.set_pvid(10, 90, force=True)
    sv = client.sets[0]
    assert sv.oid == f"{oids.DOT1Q_PVID}.10"
    assert sv.type_letter == "u" and sv.value == 90


def test_set_vlan_membership_rmw_preserves_other_ports():
    client = FakeWriteClient(_vlan_tables(member=(1, 2, 10), untagged=(1, 2)))
    w = SnmpWriter(client, get_model("gsm7252ps"))
    w.set_vlan_membership(90, 25, VlanMode.TAGGED, force=True)
    egress_sv = next(s for s in client.sets if s.oid == f"{oids.DOT1Q_VLAN_STATIC_EGRESS}.90")
    assert egress_sv.type_letter == "x"
    assert decode_port_bitmap(egress_sv.value) == frozenset({1, 2, 10, 25})  # existing kept
    untag_sv = next(s for s in client.sets if s.oid == f"{oids.DOT1Q_VLAN_STATIC_UNTAGGED}.90")
    assert decode_port_bitmap(untag_sv.value) == frozenset({1, 2})           # 25 tagged only
```

Note: these two tests only assert the emitted SETs (the crude `FakeWriteClient.set_many` apply only handles integer leaf rows, so bitmap verify-after-write is exercised against the live mock in Task 11, not here). To keep verify from failing on the fake, override the fake for these cases by passing `apply=False` and expecting the SET payload only — update the test to construct `SnmpWriter` with a client whose verify read returns the post-write state. Simplest: use `apply=False` and wrap the assertion in `pytest.raises(WriteVerificationError)` is wrong; instead assert on `client.sets` captured *before* the verification read raises. Implement `set_pvid`/`set_vlan_membership` so the SET is issued before the verify read, then in these unit tests pass a fake that returns the *updated* tables. Use this fake helper appended to the test file:

```python
class ApplyingVlanClient(FakeWriteClient):
    """Applies bitmap/pvid SETs into the read tables so verify passes."""

    def set_many(self, vbs):
        self.sets.extend(vbs)
        for vb in vbs:
            if vb.oid.startswith(oids.DOT1Q_VLAN_STATIC_EGRESS):
                self._tables[oids.DOT1Q_VLAN_STATIC_EGRESS] = [SnmpRow(vb.oid, vb.value, "Hex-STRING")]
            elif vb.oid.startswith(oids.DOT1Q_VLAN_STATIC_UNTAGGED):
                self._tables[oids.DOT1Q_VLAN_STATIC_UNTAGGED] = [SnmpRow(vb.oid, vb.value, "Hex-STRING")]
            elif vb.oid.startswith(oids.DOT1Q_PVID):
                self._tables[oids.DOT1Q_PVID] = [SnmpRow(vb.oid, int(vb.value), "Gauge32")]
```

Use `ApplyingVlanClient(_vlan_tables(...))` in both new tests instead of `FakeWriteClient`.

Also append these two tests. The first proves the verify-after-write catches a device/mock that accepts the egress SET but silently drops the untagged SET (review item 1); the second proves a genuine precondition ("VLAN does not exist") raises `SnmpError`, NOT `WriteVerificationError` (review item 9):

```python
from netgear_switch.protocols.snmp.client import SnmpError


class EgressOnlyVlanClient(FakeWriteClient):
    """Applies the egress SET but IGNORES the untagged SET (buggy device)."""

    def set_many(self, vbs):
        self.sets.extend(vbs)
        for vb in vbs:
            if vb.oid.startswith(oids.DOT1Q_VLAN_STATIC_EGRESS):
                self._tables[oids.DOT1Q_VLAN_STATIC_EGRESS] = [
                    SnmpRow(vb.oid, vb.value, "Hex-STRING")]
            # untagged column deliberately not applied


def test_set_vlan_membership_catches_dropped_untagged_write():
    # UNTAGGED mode sets both egress AND untagged; the client drops untagged.
    client = EgressOnlyVlanClient(_vlan_tables(member=(1, 2, 10), untagged=(1, 2)))
    w = SnmpWriter(client, get_model("gsm7252ps"))
    with pytest.raises(WriteVerificationError) as exc:
        w.set_vlan_membership(90, 25, VlanMode.UNTAGGED, force=True)
    assert "untagged" in str(exc.value)


def test_set_vlan_membership_missing_vlan_is_precondition_not_verify_error():
    client = ApplyingVlanClient({})  # no VLAN 90 present
    w = SnmpWriter(client, get_model("gsm7252ps"))
    with pytest.raises(SnmpError):
        w.set_vlan_membership(90, 25, VlanMode.TAGGED, force=True)
    assert client.sets == []  # precondition failed before any SET
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run --extra testing pytest tests/test_snmp_write.py -k "pvid or membership" -v`
Expected: FAIL with `AttributeError: 'SnmpWriter' object has no attribute 'set_pvid'`

- [ ] **Step 3: Write minimal implementation**

Add imports at the top of `src/netgear_switch/snmp_write.py`:

```python
from .protocols.snmp.client import SnmpError
from .protocols.snmp.parse import decode_port_bitmap
from .protocols.snmp.write import encode_port_bitmap, membership_bitmaps
```

`SnmpError` (runtime import) is raised for a genuine device/SNMP-level *precondition* discovered before any SET is attempted (e.g. "VLAN does not exist"). It is deliberately distinct from `WriteVerificationError`, which means a SET *was* issued and the read-back diverged — so `WriteVerificationError` is never raised with `before=None, after=None` (review item 9).

and under `TYPE_CHECKING` add `VLANInfo`, `VlanMode`:

```python
    from .models import PoEStatus, PortStatus, VLANInfo, VlanMode
```

Add to `SnmpWriter` a VLAN lookup helper and the two methods:

```python
    def _vlan(self, vlan: int) -> VLANInfo | None:
        return next((v for v in self._reader.get_vlans() if v.vlan_id == vlan), None)

    def set_pvid(self, port: int, vlan: int, *, force: bool = False) -> None:
        self._guard(port, force)  # changing a port's PVID is disruptive
        before = self._reader.get_pvids()
        self.client.set(SetVarbind(f"{oids.DOT1Q_PVID}.{port}", vlan, "u"))
        after = self._reader.get_pvids()
        if (port, vlan) not in after:
            raise WriteVerificationError(
                f"PVID for port {port} did not read back as {vlan}",
                before=before, after=after,
            )

    def set_vlan_membership(
        self, vlan: int, port: int, mode: VlanMode, *, force: bool = False
    ) -> None:
        self._guard(port, force)
        before = self._vlan(vlan)
        if before is None:
            # Precondition failure: no SET has been attempted, so this is NOT a
            # verification divergence (review item 9).
            raise SnmpError(f"VLAN {vlan} does not exist")
        new_egress, new_untagged = membership_bitmaps(
            mode=mode, port=port,
            egress=encode_port_bitmap(before.member_ports),
            untagged=encode_port_bitmap(before.untagged_ports),
        )
        self.client.set_many([
            SetVarbind(f"{oids.DOT1Q_VLAN_STATIC_EGRESS}.{vlan}", new_egress, "x"),
            SetVarbind(f"{oids.DOT1Q_VLAN_STATIC_UNTAGGED}.{vlan}", new_untagged, "x"),
        ])
        after = self._vlan(vlan)
        # Verify BOTH columns this op wrote: egress membership AND the untagged
        # set. A mock/device that accepts the egress SET but silently drops the
        # untagged SET must be caught (review item 1).
        want_egress = frozenset(decode_port_bitmap(new_egress))
        want_untagged = frozenset(decode_port_bitmap(new_untagged))
        if after is None:
            raise WriteVerificationError(
                f"VLAN {vlan} disappeared while setting membership for port {port}",
                before=before, after=after,
            )
        if after.member_ports != want_egress:
            raise WriteVerificationError(
                f"VLAN {vlan} egress (member_ports) for port {port} did not "
                f"verify: wanted {sorted(want_egress)}, got {sorted(after.member_ports)}",
                before=before, after=after,
            )
        if after.untagged_ports != want_untagged:
            raise WriteVerificationError(
                f"VLAN {vlan} untagged_ports for port {port} did not verify: "
                f"wanted {sorted(want_untagged)}, got {sorted(after.untagged_ports)}",
                before=before, after=after,
            )
```

Add the async mirror to `AsyncSnmpWriter`:

```python
    async def _vlan(self, vlan: int) -> VLANInfo | None:
        return next((v for v in await self._reader.get_vlans() if v.vlan_id == vlan), None)

    async def set_pvid(self, port: int, vlan: int, *, force: bool = False) -> None:
        self._guard(port, force)
        before = await self._reader.get_pvids()
        await self.client.set(SetVarbind(f"{oids.DOT1Q_PVID}.{port}", vlan, "u"))
        after = await self._reader.get_pvids()
        if (port, vlan) not in after:
            raise WriteVerificationError(
                f"PVID for port {port} did not read back as {vlan}",
                before=before, after=after,
            )

    async def set_vlan_membership(
        self, vlan: int, port: int, mode: VlanMode, *, force: bool = False
    ) -> None:
        self._guard(port, force)
        before = await self._vlan(vlan)
        if before is None:
            # Precondition failure (review item 9): no SET attempted.
            raise SnmpError(f"VLAN {vlan} does not exist")
        new_egress, new_untagged = membership_bitmaps(
            mode=mode, port=port,
            egress=encode_port_bitmap(before.member_ports),
            untagged=encode_port_bitmap(before.untagged_ports),
        )
        await self.client.set_many([
            SetVarbind(f"{oids.DOT1Q_VLAN_STATIC_EGRESS}.{vlan}", new_egress, "x"),
            SetVarbind(f"{oids.DOT1Q_VLAN_STATIC_UNTAGGED}.{vlan}", new_untagged, "x"),
        ])
        after = await self._vlan(vlan)
        # Verify BOTH written columns (egress AND untagged) — review item 1.
        want_egress = frozenset(decode_port_bitmap(new_egress))
        want_untagged = frozenset(decode_port_bitmap(new_untagged))
        if after is None:
            raise WriteVerificationError(
                f"VLAN {vlan} disappeared while setting membership for port {port}",
                before=before, after=after,
            )
        if after.member_ports != want_egress:
            raise WriteVerificationError(
                f"VLAN {vlan} egress (member_ports) for port {port} did not "
                f"verify: wanted {sorted(want_egress)}, got {sorted(after.member_ports)}",
                before=before, after=after,
            )
        if after.untagged_ports != want_untagged:
            raise WriteVerificationError(
                f"VLAN {vlan} untagged_ports for port {port} did not verify: "
                f"wanted {sorted(want_untagged)}, got {sorted(after.untagged_ports)}",
                before=before, after=after,
            )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run --extra testing pytest tests/test_snmp_write.py -v`
Expected: PASS (8 tests)

- [ ] **Step 5: Commit**

```bash
git add src/netgear_switch/snmp_write.py tests/test_snmp_write.py
git commit -m "feat(write): set_pvid + read-modify-write set_vlan_membership"
```

---

### Task 7: VLAN create/delete via RowStatus

**Files:**
- Modify: `src/netgear_switch/snmp_write.py`
- Test: `tests/test_snmp_write.py`

**Interfaces:**
- Consumes: `oids.DOT1Q_VLAN_STATIC_ROW_STATUS`, `oids.ROW_STATUS_CREATE_AND_GO`, `oids.ROW_STATUS_DESTROY`; `SnmpReader.get_vlans`.
- Produces:
  - `SnmpWriter.create_vlan(vlan: int, name: str, *, force: bool = False) -> None` (createAndGo=4 + name; verify present with name; creating an empty VLAN is non-disruptive so `force` is accepted only for signature symmetry with `delete_vlan`)
  - `SnmpWriter.delete_vlan(vlan: int, *, force: bool = False) -> None` (destroy=6; verify absent; guarded — refuses with `ProtectedPortError` if any current member port is in `protected_ports` unless `force=True`)
  - `AsyncSnmpWriter` mirrors.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_snmp_write.py`:

```python
class ApplyingRowStatusClient(FakeWriteClient):
    """Applies RowStatus create/destroy + name into read tables so verify passes."""

    def set_many(self, vbs):
        self.sets.extend(vbs)
        names = self._tables.setdefault(oids.DOT1Q_VLAN_STATIC_NAME, [])
        for vb in vbs:
            if vb.oid.startswith(oids.DOT1Q_VLAN_STATIC_ROW_STATUS):
                vid = vb.oid.rsplit(".", 1)[1]
                if int(vb.value) == oids.ROW_STATUS_DESTROY:
                    self._tables[oids.DOT1Q_VLAN_STATIC_NAME] = [
                        r for r in names if not r.oid.endswith(f".{vid}")]
                elif int(vb.value) == oids.ROW_STATUS_CREATE_AND_GO:
                    names.append(SnmpRow(f"{oids.DOT1Q_VLAN_STATIC_NAME}.{vid}", "", "STRING"))
            elif vb.oid.startswith(oids.DOT1Q_VLAN_STATIC_NAME):
                vid = vb.oid.rsplit(".", 1)[1]
                self._tables[oids.DOT1Q_VLAN_STATIC_NAME] = [
                    r for r in self._tables[oids.DOT1Q_VLAN_STATIC_NAME]
                    if not r.oid.endswith(f".{vid}")]
                val = vb.value.decode() if isinstance(vb.value, bytes) else str(vb.value)
                self._tables[oids.DOT1Q_VLAN_STATIC_NAME].append(
                    SnmpRow(vb.oid, val, "STRING"))


def test_create_vlan_sets_rowstatus_and_name():
    client = ApplyingRowStatusClient({})
    w = SnmpWriter(client, get_model("gsm7252ps"))
    w.create_vlan(200, "guests")
    kinds = {(s.oid, s.type_letter, s.value) for s in client.sets}
    assert (f"{oids.DOT1Q_VLAN_STATIC_ROW_STATUS}.200", "i", oids.ROW_STATUS_CREATE_AND_GO) in kinds
    assert (f"{oids.DOT1Q_VLAN_STATIC_NAME}.200", "s", "guests") in kinds


def test_delete_vlan_destroys_and_verifies_absent():
    client = ApplyingRowStatusClient(
        {oids.DOT1Q_VLAN_STATIC_NAME: [SnmpRow(f"{oids.DOT1Q_VLAN_STATIC_NAME}.200", "guests", "STRING")]})
    w = SnmpWriter(client, get_model("gsm7252ps"))
    w.delete_vlan(200)
    assert client.sets == [SetVarbind(f"{oids.DOT1Q_VLAN_STATIC_ROW_STATUS}.200", oids.ROW_STATUS_DESTROY, "i")]


def test_delete_vlan_protected_member_requires_force():
    # VLAN 90 has member ports {1, 2, 10}; port 1 is protected. Deleting it would
    # strip membership from the protected port (review item 3).
    client = ApplyingRowStatusClient(_vlan_tables(vid=90, member=(1, 2, 10), untagged=(1, 2)))
    w = SnmpWriter(client, get_model("gsm7252ps"), protected_ports=frozenset({1}))
    with pytest.raises(ProtectedPortError):
        w.delete_vlan(90)
    assert client.sets == []           # nothing sent when the guard fires
    w.delete_vlan(90, force=True)      # force bypasses the guard
    assert any(s.oid == f"{oids.DOT1Q_VLAN_STATIC_ROW_STATUS}.90" for s in client.sets)
```

(`_vlan_tables` is defined in the Task 6 test additions and projects `member_ports` from the egress column, so `before.member_ports` sees `{1, 2, 10}`. `ApplyingRowStatusClient`'s destroy removes the name row, so `get_vlans` reports VLAN 90 absent and the force path's verify passes.)

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run --extra testing pytest tests/test_snmp_write.py -k "create_vlan or delete_vlan" -v`
Expected: FAIL with `AttributeError: 'SnmpWriter' object has no attribute 'create_vlan'`

- [ ] **Step 3: Write minimal implementation**

Add to `SnmpWriter`:

```python
    def create_vlan(self, vlan: int, name: str, *, force: bool = False) -> None:
        # Creating an EMPTY VLAN adds no port membership, so it is
        # non-disruptive and does NOT require force. ``force`` exists only for
        # signature symmetry with delete_vlan (review item 3).
        before = self._vlan(vlan)
        self.client.set_many([
            SetVarbind(f"{oids.DOT1Q_VLAN_STATIC_ROW_STATUS}.{vlan}",
                       oids.ROW_STATUS_CREATE_AND_GO, "i"),
            SetVarbind(f"{oids.DOT1Q_VLAN_STATIC_NAME}.{vlan}", name, "s"),
        ])
        after = self._vlan(vlan)
        if after is None or (after.name or "") != name:
            raise WriteVerificationError(
                f"VLAN {vlan} was not created with name {name!r}",
                before=before, after=after,
            )

    def delete_vlan(self, vlan: int, *, force: bool = False) -> None:
        before = self._vlan(vlan)
        # Destroying a VLAN strips membership from EVERY member port; if any is a
        # protected (uplink/mgmt) port, refuse without force (review item 3).
        if before is not None and not force:
            clash = before.member_ports & self.protected_ports
            if clash:
                raise ProtectedPortError(
                    f"VLAN {vlan} includes protected port(s) {sorted(clash)}; "
                    f"pass force=True to delete it anyway"
                )
        self.client.set(SetVarbind(
            f"{oids.DOT1Q_VLAN_STATIC_ROW_STATUS}.{vlan}", oids.ROW_STATUS_DESTROY, "i"))
        after = self._vlan(vlan)
        if after is not None:
            raise WriteVerificationError(
                f"VLAN {vlan} still exists after destroy", before=before, after=after)
```

Add to `AsyncSnmpWriter`:

```python
    async def create_vlan(self, vlan: int, name: str, *, force: bool = False) -> None:
        # Empty VLAN creation is non-disruptive; force is for symmetry only.
        before = await self._vlan(vlan)
        await self.client.set_many([
            SetVarbind(f"{oids.DOT1Q_VLAN_STATIC_ROW_STATUS}.{vlan}",
                       oids.ROW_STATUS_CREATE_AND_GO, "i"),
            SetVarbind(f"{oids.DOT1Q_VLAN_STATIC_NAME}.{vlan}", name, "s"),
        ])
        after = await self._vlan(vlan)
        if after is None or (after.name or "") != name:
            raise WriteVerificationError(
                f"VLAN {vlan} was not created with name {name!r}",
                before=before, after=after,
            )

    async def delete_vlan(self, vlan: int, *, force: bool = False) -> None:
        before = await self._vlan(vlan)
        # Refuse if a member port is protected, unless force (review item 3).
        if before is not None and not force:
            clash = before.member_ports & self.protected_ports
            if clash:
                raise ProtectedPortError(
                    f"VLAN {vlan} includes protected port(s) {sorted(clash)}; "
                    f"pass force=True to delete it anyway"
                )
        await self.client.set(SetVarbind(
            f"{oids.DOT1Q_VLAN_STATIC_ROW_STATUS}.{vlan}", oids.ROW_STATUS_DESTROY, "i"))
        after = await self._vlan(vlan)
        if after is not None:
            raise WriteVerificationError(
                f"VLAN {vlan} still exists after destroy", before=before, after=after)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run --extra testing pytest tests/test_snmp_write.py -v`
Expected: PASS (11 tests)

- [ ] **Step 5: Commit**

```bash
git add src/netgear_switch/snmp_write.py tests/test_snmp_write.py
git commit -m "feat(write): create_vlan/delete_vlan via dot1q RowStatus (+protected-port guard)"
```

---

### Task 8: PoE cycle state machine + clear-fault (injectable timeouts)

**Files:**
- Modify: `src/netgear_switch/snmp_write.py`
- Test: `tests/test_snmp_write.py`

**Interfaces:**
- Consumes: `models.PoEDetect`; PoE admin SET; `get_poe`/`get_ports` polls.
- Produces:
  - `PoeCycleTimeouts(off_timeout: float = 30.0, on_timeout: float = 60.0, poll_interval: float = 2.0)` frozen dataclass (exported from `snmp_write`).
  - `SnmpWriter.cycle_poe(port, *, force=False, timeouts=PoeCycleTimeouts(), sleep=time.sleep, clock=time.monotonic) -> None`
  - `SnmpWriter.clear_poe_fault(port, *, force=False, timeouts=PoeCycleTimeouts(), sleep=time.sleep, clock=time.monotonic) -> None` — same injectable poll/timeout structure as `cycle_poe`; polls for detect to leave FAULT (return to delivering/searching) before verifying, because real detect transitions take seconds (review item 5).
  - `AsyncSnmpWriter.cycle_poe(port, *, force=False, timeouts=..., sleep=asyncio.sleep, clock=time.monotonic)` and `clear_poe_fault(port, *, force=False, timeouts=..., sleep=asyncio.sleep, clock=time.monotonic)` (async).

- [ ] **Step 1: Write the failing test**

Append to `tests/test_snmp_write.py`:

```python
from netgear_switch.models import PoEDetect
from netgear_switch.snmp_write import PoeCycleTimeouts


class CoherentPoeClient(FakeWriteClient):
    """Mimics device coherence: admin off -> detect=1 + link down; on -> detect=3."""

    def set_many(self, vbs):
        self.sets.extend(vbs)
        for vb in vbs:
            if vb.oid.startswith(f"{oids.PETH_PSE_PORT_TABLE}.3.1."):
                port = int(vb.oid.rsplit(".", 1)[1])
                on = int(vb.value) == 1
                self._tables[oids.PETH_PSE_PORT_TABLE] = [
                    SnmpRow(f"{oids.PETH_PSE_PORT_TABLE}.3.1.{port}", 1 if on else 2, "INTEGER"),
                    SnmpRow(f"{oids.PETH_PSE_PORT_TABLE}.6.1.{port}", 3 if on else 1, "INTEGER"),
                ]
                self._tables[oids.IF_OPER_STATUS] = [
                    SnmpRow(f"{oids.IF_OPER_STATUS}.{port}", 1 if on else 2, "INTEGER")]


def _poe_full_tables(port=5):
    return {
        oids.PETH_PSE_PORT_TABLE: [
            SnmpRow(f"{oids.PETH_PSE_PORT_TABLE}.3.1.{port}", 1, "INTEGER"),
            SnmpRow(f"{oids.PETH_PSE_PORT_TABLE}.6.1.{port}", 3, "INTEGER"),
        ],
        oids.IF_ADMIN_STATUS: [SnmpRow(f"{oids.IF_ADMIN_STATUS}.{port}", 1, "INTEGER")],
        oids.IF_OPER_STATUS: [SnmpRow(f"{oids.IF_OPER_STATUS}.{port}", 1, "INTEGER")],
        oids.IF_HIGH_SPEED: [SnmpRow(f"{oids.IF_HIGH_SPEED}.{port}", 1000, "Gauge32")],
        oids.IF_NAME: [SnmpRow(f"{oids.IF_NAME}.{port}", "1/0/5", "STRING")],
    }


def test_cycle_poe_off_then_on_terminates_fast():
    client = CoherentPoeClient(_poe_full_tables())
    w = SnmpWriter(client, get_model("gsm7252ps"))
    calls: list[float] = []
    w.cycle_poe(5, force=True,
                timeouts=PoeCycleTimeouts(off_timeout=1, on_timeout=1, poll_interval=0),
                sleep=calls.append)
    admin_sets = [s.value for s in client.sets if s.oid.startswith(f"{oids.PETH_PSE_PORT_TABLE}.3.1.")]
    assert admin_sets == [2, 1]  # off then on


def test_clear_poe_fault_recovers_detect():
    tables = _poe_full_tables()
    tables[oids.PETH_PSE_PORT_TABLE] = [
        SnmpRow(f"{oids.PETH_PSE_PORT_TABLE}.3.1.5", 1, "INTEGER"),
        SnmpRow(f"{oids.PETH_PSE_PORT_TABLE}.6.1.5", 4, "INTEGER"),  # FAULT
    ]
    client = CoherentPoeClient(tables)
    w = SnmpWriter(client, get_model("gsm7252ps"))
    calls: list[float] = []
    w.clear_poe_fault(5, force=True,
                      timeouts=PoeCycleTimeouts(on_timeout=1, poll_interval=0),
                      sleep=calls.append)
    detect = next(p.detect for p in w._reader.get_poe() if p.port == 5)
    assert detect is not PoEDetect.FAULT
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run --extra testing pytest tests/test_snmp_write.py -k "cycle or clear" -v`
Expected: FAIL with `ImportError: cannot import name 'PoeCycleTimeouts'`

- [ ] **Step 3: Write minimal implementation**

Add imports at the top of `src/netgear_switch/snmp_write.py`:

```python
import asyncio
import time
from dataclasses import dataclass
```

and under `TYPE_CHECKING`:

```python
    from collections.abc import Awaitable, Callable
```

and import `PoEDetect` at runtime (needed for comparisons) — add near the other model import; since models are only in `TYPE_CHECKING`, import `PoEDetect` at runtime:

```python
from .models import PoEDetect
```

Add the timeouts dataclass (after the `_poe_admin_oid` helper):

```python
@dataclass(frozen=True)
class PoeCycleTimeouts:
    """Injectable PoE-cycle deadlines (seconds). Defaults match design spec §6;
    tests pass tiny values so cycles run fast against the coherent mock."""

    off_timeout: float = 30.0
    on_timeout: float = 60.0
    poll_interval: float = 2.0


def _poe_is_off(status: PoEStatus | None, port_up: bool) -> bool:
    return (
        status is not None
        and status.detect in (PoEDetect.DISABLED, PoEDetect.SEARCHING)
        and not port_up
    )


def _poe_recovered(status: PoEStatus | None) -> bool:
    """True once detect has left FAULT and settled to delivering/searching."""
    return status is not None and status.detect in (
        PoEDetect.DELIVERING,
        PoEDetect.SEARCHING,
    )
```

Add to `SnmpWriter`:

```python
    def cycle_poe(
        self,
        port: int,
        *,
        force: bool = False,
        timeouts: PoeCycleTimeouts = PoeCycleTimeouts(),
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._guard(port, force)
        before = self._poe_status(port)
        # Phase 1: off, poll until unused/searching + link down.
        self.client.set(SetVarbind(_poe_admin_oid(port), 2, "i"))
        deadline = clock() + timeouts.off_timeout
        while not _poe_is_off(self._poe_status(port), self._port_up(port)):
            if clock() >= deadline:
                raise WriteVerificationError(
                    f"PoE port {port} did not turn off within {timeouts.off_timeout}s",
                    before=before, after=self._poe_status(port))
            sleep(timeouts.poll_interval)
        # Phase 2: on, poll until delivering.
        self.client.set(SetVarbind(_poe_admin_oid(port), 1, "i"))
        deadline = clock() + timeouts.on_timeout
        while not (self._poe_status(port) and self._poe_status(port).delivering):
            if clock() >= deadline:
                raise WriteVerificationError(
                    f"PoE port {port} did not return to delivering within "
                    f"{timeouts.on_timeout}s",
                    before=before, after=self._poe_status(port))
            sleep(timeouts.poll_interval)

    def clear_poe_fault(
        self,
        port: int,
        *,
        force: bool = False,
        timeouts: PoeCycleTimeouts = PoeCycleTimeouts(),
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._guard(port, force)
        before = self._poe_status(port)
        # Re-arm detection: disable then enable, then POLL for detect to leave
        # FAULT. An immediate single re-read false-negatives on real hardware
        # because detect transitions take seconds (review item 5); tests inject
        # tiny timeouts so this is fast against the coherent mock.
        self.client.set_many([
            SetVarbind(_poe_admin_oid(port), 2, "i"),
            SetVarbind(_poe_admin_oid(port), 1, "i"),
        ])
        deadline = clock() + timeouts.on_timeout
        while not _poe_recovered(self._poe_status(port)):
            if clock() >= deadline:
                raise WriteVerificationError(
                    f"PoE port {port} still in FAULT after clear within "
                    f"{timeouts.on_timeout}s",
                    before=before, after=self._poe_status(port))
            sleep(timeouts.poll_interval)

    def _port_up(self, port: int) -> bool:
        status = self._port_status(port)
        return bool(status and status.link_up)
```

Add to `AsyncSnmpWriter`:

```python
    async def _port_up(self, port: int) -> bool:
        status = await self._port_status(port)
        return bool(status and status.link_up)

    async def cycle_poe(
        self,
        port: int,
        *,
        force: bool = False,
        timeouts: PoeCycleTimeouts = PoeCycleTimeouts(),
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._guard(port, force)
        before = await self._poe_status(port)
        await self.client.set(SetVarbind(_poe_admin_oid(port), 2, "i"))
        deadline = clock() + timeouts.off_timeout
        while not _poe_is_off(await self._poe_status(port), await self._port_up(port)):
            if clock() >= deadline:
                raise WriteVerificationError(
                    f"PoE port {port} did not turn off within {timeouts.off_timeout}s",
                    before=before, after=await self._poe_status(port))
            await sleep(timeouts.poll_interval)
        await self.client.set(SetVarbind(_poe_admin_oid(port), 1, "i"))
        deadline = clock() + timeouts.on_timeout
        while True:
            st = await self._poe_status(port)
            if st and st.delivering:
                break
            if clock() >= deadline:
                raise WriteVerificationError(
                    f"PoE port {port} did not return to delivering within "
                    f"{timeouts.on_timeout}s",
                    before=before, after=st)
            await sleep(timeouts.poll_interval)

    async def clear_poe_fault(
        self,
        port: int,
        *,
        force: bool = False,
        timeouts: PoeCycleTimeouts = PoeCycleTimeouts(),
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._guard(port, force)
        before = await self._poe_status(port)
        # Poll for detect to leave FAULT (review item 5); tiny timeouts in tests.
        await self.client.set_many([
            SetVarbind(_poe_admin_oid(port), 2, "i"),
            SetVarbind(_poe_admin_oid(port), 1, "i"),
        ])
        deadline = clock() + timeouts.on_timeout
        while not _poe_recovered(await self._poe_status(port)):
            if clock() >= deadline:
                raise WriteVerificationError(
                    f"PoE port {port} still in FAULT after clear within "
                    f"{timeouts.on_timeout}s",
                    before=before, after=await self._poe_status(port))
            await sleep(timeouts.poll_interval)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run --extra testing pytest tests/test_snmp_write.py -v`
Expected: PASS (13 tests)

- [ ] **Step 5: Commit**

```bash
git add src/netgear_switch/snmp_write.py tests/test_snmp_write.py
git commit -m "feat(write): PoE cycle state machine + clear-fault (injectable timeouts)"
```

---

### Task 9: Management-IP set (UNVERIFIED, force-gated)

**Files:**
- Modify: `src/netgear_switch/snmp_write.py`
- Test: `tests/test_snmp_write.py`

**Interfaces:**
- Consumes: `oids.vendor_oids(model).mgmt_write_{addr,netmask,gateway}_unverified`; `SnmpReader.get_mgmt_ip`.
- Produces:
  - `SnmpWriter.set_mgmt_ip(address: str, netmask: str, gateway: str, *, force: bool = False) -> None` — one atomic `set_many` of three IpAddress (`a`) SETs; verify via `get_mgmt_ip` compares ALL three fields (address, netmask, gateway), naming whichever diverged (highest strand-risk op). Raises `ProtectedPortError` unless `force=True` (strand risk). DHCP-mode switching is intentionally NOT offered (out-of-scope-until-verified).
  - `AsyncSnmpWriter.set_mgmt_ip` mirror.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_snmp_write.py`:

```python
from netgear_switch.errors import ProtectedPortError as _PPE  # already imported; alias for clarity


def _mgmt_tables(addr="10.1.5.20", mask="255.255.255.0", gw="10.1.5.1"):
    return {
        oids.IP_ADENT_ADDR: [SnmpRow(f"{oids.IP_ADENT_ADDR}.{addr}", addr, "IpAddress")],
        oids.IP_ADENT_NETMASK: [SnmpRow(f"{oids.IP_ADENT_NETMASK}.{addr}", mask, "IpAddress")],
        oids.IP_ROUTE_DEST: [SnmpRow(f"{oids.IP_ROUTE_DEST}.0.0.0.0", "0.0.0.0", "IpAddress")],
        oids.IP_ROUTE_NEXTHOP: [SnmpRow(f"{oids.IP_ROUTE_NEXTHOP}.0.0.0.0", gw, "IpAddress")],
    }


def test_set_mgmt_ip_requires_force():
    client = FakeWriteClient(_mgmt_tables())
    w = SnmpWriter(client, get_model("gsm7252ps"))
    with pytest.raises(_PPE):
        w.set_mgmt_ip("10.9.9.9", "255.255.255.0", "10.9.9.1")
    assert client.sets == []


class _MgmtApply(FakeWriteClient):
    """Applies all three mgmt-IP write OIDs into the read projection.

    Optionally skips one field (``skip``) to simulate a device that accepts the
    address but silently drops the netmask/gateway write.
    """

    def __init__(self, tables, *, skip=None):
        super().__init__(tables)
        self._vo = oids.vendor_oids(get_model("gsm7252ps"))
        self._skip = skip
        self._addr = "10.1.5.20"  # current mgmt address key for the ip tables

    def set_many(self, vbs):
        self.sets.extend(vbs)
        for vb in vbs:
            val = str(vb.value)
            if vb.oid == self._vo.mgmt_write_addr_unverified and self._skip != "address":
                self._addr = val
                self._tables[oids.IP_ADENT_ADDR] = [SnmpRow(f"{oids.IP_ADENT_ADDR}.{val}", val, "IpAddress")]
            elif vb.oid == self._vo.mgmt_write_netmask_unverified and self._skip != "netmask":
                self._tables[oids.IP_ADENT_NETMASK] = [SnmpRow(f"{oids.IP_ADENT_NETMASK}.{self._addr}", val, "IpAddress")]
            elif vb.oid == self._vo.mgmt_write_gateway_unverified and self._skip != "gateway":
                self._tables[oids.IP_ROUTE_NEXTHOP] = [SnmpRow(f"{oids.IP_ROUTE_NEXTHOP}.0.0.0.0", val, "IpAddress")]


def test_set_mgmt_ip_emits_three_ipaddress_sets():
    vo = oids.vendor_oids(get_model("gsm7252ps"))
    client = _MgmtApply(_mgmt_tables())
    w = SnmpWriter(client, get_model("gsm7252ps"))
    w.set_mgmt_ip("10.9.9.9", "255.255.255.0", "10.9.9.1", force=True)
    letters = {(s.oid, s.type_letter) for s in client.sets}
    assert (vo.mgmt_write_addr_unverified, "a") in letters
    assert (vo.mgmt_write_netmask_unverified, "a") in letters
    assert (vo.mgmt_write_gateway_unverified, "a") in letters


def test_set_mgmt_ip_verifies_gateway_not_just_address():
    # Device accepts address+netmask but drops the gateway write; verify must
    # catch it and name the gateway field (review item 2).
    client = _MgmtApply(_mgmt_tables(), skip="gateway")
    w = SnmpWriter(client, get_model("gsm7252ps"))
    with pytest.raises(WriteVerificationError) as exc:
        w.set_mgmt_ip("10.9.9.9", "255.255.255.0", "10.9.9.1", force=True)
    assert "gateway" in str(exc.value)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run --extra testing pytest tests/test_snmp_write.py -k mgmt -v`
Expected: FAIL with `AttributeError: 'SnmpWriter' object has no attribute 'set_mgmt_ip'`

- [ ] **Step 3: Write minimal implementation**

Add to `SnmpWriter`:

```python
    def set_mgmt_ip(
        self, address: str, netmask: str, gateway: str, *, force: bool = False
    ) -> None:
        """Set the switch's own management IP (address/netmask/gateway).

        UNVERIFIED write path (see oids.VendorOids mgmt_write_* fields): the
        exact writable OIDs are placeholders pending Slice 7 hardware capture,
        so this is force-gated (a wrong mgmt-IP write can strand the switch —
        design spec §11.1). DHCP-mode switching is intentionally NOT offered
        here because even its read OID is unverified; do not fabricate it.
        """
        if not force:
            raise ProtectedPortError(
                "set_mgmt_ip can strand the switch and uses UNVERIFIED OIDs; "
                "pass force=True to proceed"
            )
        vo = oids.vendor_oids(self.model)
        before = self._reader.get_mgmt_ip()
        self.client.set_many([
            SetVarbind(vo.mgmt_write_addr_unverified, address, "a"),
            SetVarbind(vo.mgmt_write_netmask_unverified, netmask, "a"),
            SetVarbind(vo.mgmt_write_gateway_unverified, gateway, "a"),
        ])
        after = self._reader.get_mgmt_ip()
        # Highest strand-risk op: verify EVERY field written (address, netmask,
        # AND gateway), naming whichever diverged (review item 2).
        for field, want, got in (
            ("address", address, after.address),
            ("netmask", netmask, after.netmask),
            ("gateway", gateway, after.gateway),
        ):
            if got != want:
                raise WriteVerificationError(
                    f"management {field} did not read back as {want!r} (got {got!r})",
                    before=before, after=after)
```

Add to `AsyncSnmpWriter`:

```python
    async def set_mgmt_ip(
        self, address: str, netmask: str, gateway: str, *, force: bool = False
    ) -> None:
        if not force:
            raise ProtectedPortError(
                "set_mgmt_ip can strand the switch and uses UNVERIFIED OIDs; "
                "pass force=True to proceed"
            )
        vo = oids.vendor_oids(self.model)
        before = await self._reader.get_mgmt_ip()
        await self.client.set_many([
            SetVarbind(vo.mgmt_write_addr_unverified, address, "a"),
            SetVarbind(vo.mgmt_write_netmask_unverified, netmask, "a"),
            SetVarbind(vo.mgmt_write_gateway_unverified, gateway, "a"),
        ])
        after = await self._reader.get_mgmt_ip()
        # Verify EVERY field written (address, netmask, AND gateway) — item 2.
        for field, want, got in (
            ("address", address, after.address),
            ("netmask", netmask, after.netmask),
            ("gateway", gateway, after.gateway),
        ):
            if got != want:
                raise WriteVerificationError(
                    f"management {field} did not read back as {want!r} (got {got!r})",
                    before=before, after=after)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run --extra testing pytest tests/test_snmp_write.py -v`
Expected: PASS (16 tests)

- [ ] **Step 5: Commit**

```bash
git add src/netgear_switch/snmp_write.py tests/test_snmp_write.py
git commit -m "feat(write): force-gated UNVERIFIED set_mgmt_ip"
```

---

### Task 10: Write-client builders + facade write methods + from_config env

**Files:**
- Modify: `src/netgear_switch/_dispatch.py`
- Modify: `src/netgear_switch/sync_api.py`
- Modify: `src/netgear_switch/aio_api.py`
- Test: `tests/test_dispatch.py`, `tests/test_sync_api.py`, `tests/test_aio_api.py`

**Interfaces:**
- Consumes: `SnmpWriteClient`/`AsyncSnmpWriteClient`; `SnmpWriter`/`AsyncSnmpWriter`; `SwitchConfig.snmp_write_community(env=...)`, `SwitchConfig.protected_ports`.
- Produces:
  - `_dispatch.build_sync_snmp_write_client(host, write_community) -> SnmpWriteClient`
  - `_dispatch.build_async_snmp_write_client(host, write_community) -> AsyncSnmpWriteClient`
  - `SyncSwitch.__init__(..., snmp_write_community=None, snmp_write_client=None, protected_ports=frozenset())`
  - `SyncSwitch` write methods: `set_poe`, `set_port_enabled`, `set_pvid`, `set_vlan_membership`, `create_vlan`, `delete_vlan`, `cycle_poe`, `clear_poe_fault`, `set_mgmt_ip`.
  - `AsyncSwitch` identical (async) surface.
  - `from_config(cfg, *, env=...)` stashes a LAZY write-community resolver closure (`cfg.snmp_write_community(env=env or os.environ)` called only on first write) and passes `cfg.protected_ports`. It performs NO eager write-community resolution, so read-only construction of a config with an unresolvable write-community spec never raises.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_dispatch.py`:

```python
import pytest

from netgear_switch._dispatch import build_sync_snmp_write_client
from netgear_switch.errors import CredentialError


def test_build_sync_write_client_requires_write_community():
    with pytest.raises(CredentialError):
        build_sync_snmp_write_client("host", None)
    client = build_sync_snmp_write_client("host", "wcomm")
    assert client.community == "wcomm"
```

Append to `tests/test_sync_api.py`:

```python
from netgear_switch.protocols.snmp.write import SetVarbind


class RecordingWriteClient(FakeClient):
    def __init__(self, tables):
        super().__init__(tables)
        self.sets: list[SetVarbind] = []

    def set(self, vb):
        self.set_many([vb])

    def set_many(self, vbs):
        self.sets.extend(vbs)
        for vb in vbs:  # apply ifAdminStatus so verify passes
            if vb.oid.startswith(oids.IF_ADMIN_STATUS):
                self._tables[oids.IF_ADMIN_STATUS] = [SnmpRow(vb.oid, int(vb.value), "INTEGER")]


def test_sync_switch_set_port_enabled_delegates_to_writer():
    tables = _ports_tables()
    client = RecordingWriteClient(tables)
    sw = SyncSwitch(get_model("gsm7252ps"), "host", snmp_write_client=client)
    sw.set_port_enabled(1, enabled=False, force=True)
    assert client.sets == [SetVarbind(f"{oids.IF_ADMIN_STATUS}.1", 2, "i")]


def test_from_config_write_community_resolves_lazily_not_at_construction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A read-only consumer with an unresolvable write-community spec must still
    construct and read; only the first write resolves it and raises (item 4)."""
    from netgear_switch.errors import CredentialError

    cfg = SwitchConfig(
        name="core",
        model=get_model("gsm7252ps"),
        host="10.0.0.9",
        snmp_community="public",
        snmp_write_community_spec="${NETGEAR_WRITE_UNSET}",  # unresolvable
        http_password_spec=None,
        nsdp_interface=None,
        protected_ports=frozenset(),
    )
    monkeypatch.delenv("NETGEAR_WRITE_UNSET", raising=False)
    monkeypatch.setattr(
        "netgear_switch.sync_api.build_sync_snmp_client",
        lambda host, community: FakeClient(_ports_tables()),
    )

    # Construction resolves nothing -> no CredentialError here.
    sw = SyncSwitch.from_config(cfg)
    # Read ops still work.
    assert sw.get_ports()[0].port == 1
    # First write resolves the spec lazily -> now it raises.
    with pytest.raises(CredentialError):
        sw.set_port_enabled(1, enabled=False, force=True)
```

Append to `tests/test_aio_api.py` an analogous async test (mirror the sync one, `await sw.set_port_enabled(...)` via `asyncio.run`), plus an async mirror of `test_from_config_write_community_resolves_lazily_not_at_construction` (patch `netgear_switch.aio_api.build_async_snmp_client`, construct via `AsyncSwitch.from_config`, assert an awaited read works and the first awaited write raises `CredentialError`). Follow the existing async-test style in that file.

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run --extra testing pytest tests/test_dispatch.py::test_build_sync_write_client_requires_write_community tests/test_sync_api.py::test_sync_switch_set_port_enabled_delegates_to_writer -v`
Expected: FAIL with `ImportError: cannot import name 'build_sync_snmp_write_client'`

- [ ] **Step 3: Write minimal implementation**

In `src/netgear_switch/_dispatch.py`, add to the `TYPE_CHECKING` block:

```python
    from .protocols.snmp.client import (
        AsyncSnmpClient,
        AsyncSnmpWriteClient,
        SnmpClient,
        SnmpWriteClient,
    )
```

and add builders (after `build_async_snmp_client`):

```python
def _require_write_community(host: str, community: str | None) -> str:
    if community is None:
        raise CredentialError(
            f"no SNMP write community configured for {host!r}"
        )
    return community


def build_sync_snmp_write_client(
    host: str, write_community: str | None
) -> SnmpWriteClient:
    """Default sync SNMP write client (net-snmp CLI). Imported lazily."""
    from .transport.sync.snmp_netsnmp_cli import NetsnmpCliClient

    return NetsnmpCliClient(host, _require_write_community(host, write_community))


def build_async_snmp_write_client(
    host: str, write_community: str | None
) -> AsyncSnmpWriteClient:
    """Default async SNMP write client (pysnmp). Imported lazily."""
    from .transport.aio.snmp_pysnmp import PysnmpClient

    return PysnmpClient(host, _require_write_community(host, write_community))
```

In `src/netgear_switch/sync_api.py`:

Add imports:

```python
import os
from ._dispatch import (
    build_sync_snmp_client,
    build_sync_snmp_write_client,
    require_mac_table,
    require_snmp_backend,
)
from .snmp_read import SnmpReader
from .snmp_write import PoeCycleTimeouts, SnmpWriter
```

and under `TYPE_CHECKING` add `VlanMode` to the models import and `SnmpWriteClient`:

```python
    from .models import (
        LLDPNeighbor, MacEntry, MgmtIpConfig, PoEStatus, PortStats,
        PortStatus, Sensor, VLANInfo, VlanMode,
    )
    from .protocols.snmp.client import SnmpClient, SnmpWriteClient
```

Extend `__init__`:

```python
    def __init__(
        self,
        model: SwitchModel,
        host: str,
        *,
        snmp_community: str | None = None,
        snmp_client: SnmpClient | None = None,
        snmp_write_community: str | None = None,
        snmp_write_client: SnmpWriteClient | None = None,
        snmp_write_community_resolver: Callable[[], str | None] | None = None,
        protected_ports: frozenset[int] = frozenset(),
    ) -> None:
        self.model = model
        self.host = host
        self._snmp_community = snmp_community
        self._snmp_client = snmp_client
        self._snmp_write_community = snmp_write_community
        self._snmp_write_client = snmp_write_client
        # Deferred write-community resolution: from_config stashes a closure here
        # instead of resolving eagerly, so read-only construction never raises a
        # CredentialError for an unresolvable write-community spec (review item 4).
        self._snmp_write_community_resolver = snmp_write_community_resolver
        self.protected_ports = protected_ports
```

Add `Callable` to the `TYPE_CHECKING` imports in `sync_api.py` (e.g. `from collections.abc import Callable, Mapping`).

Replace `from_config`:

```python
    @classmethod
    def from_config(
        cls, cfg: SwitchConfig, *, env: Mapping[str, str] | None = None
    ) -> SyncSwitch:
        # Resolve the SNMP write community LAZILY (on first write), never here.
        # A read-only consumer whose env lacks a resolvable write-community spec
        # (e.g. ``${UNSET_VAR}``) must still be able to construct the facade and
        # read; only an actual write attempt may raise CredentialError/ConfigError
        # (review item 4). We stash a closure that reads the spec + env on demand.
        def _resolve_write_community() -> str | None:
            return cfg.snmp_write_community(env=env if env is not None else os.environ)

        return cls(
            cfg.model, cfg.host,
            snmp_community=cfg.snmp_community,
            snmp_write_community_resolver=_resolve_write_community,
            protected_ports=cfg.protected_ports,
        )
```

Add the writer accessor and write methods (after `snapshot`):

```python
    def _resolve_write_community(self) -> str | None:
        # First write triggers resolution; an explicit community wins, else the
        # stashed from_config resolver runs now (may raise), else None.
        if self._snmp_write_community is not None:
            return self._snmp_write_community
        if self._snmp_write_community_resolver is not None:
            return self._snmp_write_community_resolver()
        return None

    def _writer(self) -> SnmpWriter:
        require_snmp_backend(self.model)
        client = self._snmp_write_client
        if client is None:
            client = build_sync_snmp_write_client(self.host, self._resolve_write_community())
        return SnmpWriter(client, self.model, protected_ports=self.protected_ports)

    def set_poe(self, port: int, on: bool, *, force: bool = False) -> None:
        self._writer().set_poe(port, on, force=force)

    def set_port_enabled(self, port: int, enabled: bool, *, force: bool = False) -> None:
        self._writer().set_port_enabled(port, enabled, force=force)

    def set_pvid(self, port: int, vlan: int, *, force: bool = False) -> None:
        self._writer().set_pvid(port, vlan, force=force)

    def set_vlan_membership(
        self, vlan: int, port: int, mode: VlanMode, *, force: bool = False
    ) -> None:
        self._writer().set_vlan_membership(vlan, port, mode, force=force)

    def create_vlan(self, vlan: int, name: str, *, force: bool = False) -> None:
        self._writer().create_vlan(vlan, name, force=force)

    def delete_vlan(self, vlan: int, *, force: bool = False) -> None:
        self._writer().delete_vlan(vlan, force=force)

    def cycle_poe(
        self, port: int, *, force: bool = False,
        timeouts: PoeCycleTimeouts = PoeCycleTimeouts(),
    ) -> None:
        self._writer().cycle_poe(port, force=force, timeouts=timeouts)

    def clear_poe_fault(
        self, port: int, *, force: bool = False,
        timeouts: PoeCycleTimeouts = PoeCycleTimeouts(),
    ) -> None:
        self._writer().clear_poe_fault(port, force=force, timeouts=timeouts)

    def set_mgmt_ip(
        self, address: str, netmask: str, gateway: str, *, force: bool = False
    ) -> None:
        self._writer().set_mgmt_ip(address, netmask, gateway, force=force)
```

Mirror all of the above in `src/netgear_switch/aio_api.py` (async `def`, `await self._writer_client()...`). Use an `AsyncSnmpWriter` accessor:

```python
    def _resolve_write_community(self) -> str | None:
        if self._snmp_write_community is not None:
            return self._snmp_write_community
        if self._snmp_write_community_resolver is not None:
            return self._snmp_write_community_resolver()
        return None

    def _writer(self) -> AsyncSnmpWriter:
        require_snmp_backend(self.model)
        client = self._snmp_write_client
        if client is None:
            client = build_async_snmp_write_client(self.host, self._resolve_write_community())
        return AsyncSnmpWriter(client, self.model, protected_ports=self.protected_ports)

    async def set_poe(self, port: int, on: bool, *, force: bool = False) -> None:
        await self._writer().set_poe(port, on, force=force)

    async def set_port_enabled(self, port: int, enabled: bool, *, force: bool = False) -> None:
        await self._writer().set_port_enabled(port, enabled, force=force)

    async def set_pvid(self, port: int, vlan: int, *, force: bool = False) -> None:
        await self._writer().set_pvid(port, vlan, force=force)

    async def set_vlan_membership(
        self, vlan: int, port: int, mode: VlanMode, *, force: bool = False
    ) -> None:
        await self._writer().set_vlan_membership(vlan, port, mode, force=force)

    async def create_vlan(self, vlan: int, name: str, *, force: bool = False) -> None:
        await self._writer().create_vlan(vlan, name, force=force)

    async def delete_vlan(self, vlan: int, *, force: bool = False) -> None:
        await self._writer().delete_vlan(vlan, force=force)

    async def cycle_poe(
        self, port: int, *, force: bool = False,
        timeouts: PoeCycleTimeouts = PoeCycleTimeouts(),
    ) -> None:
        await self._writer().cycle_poe(port, force=force, timeouts=timeouts)

    async def clear_poe_fault(
        self, port: int, *, force: bool = False,
        timeouts: PoeCycleTimeouts = PoeCycleTimeouts(),
    ) -> None:
        await self._writer().clear_poe_fault(port, force=force, timeouts=timeouts)

    async def set_mgmt_ip(
        self, address: str, netmask: str, gateway: str, *, force: bool = False
    ) -> None:
        await self._writer().set_mgmt_ip(address, netmask, gateway, force=force)
```

with the matching `__init__`/`from_config` changes and imports (`build_async_snmp_write_client`, `AsyncSnmpWriter`, `PoeCycleTimeouts`, `os`, `Callable`, `VlanMode`, `AsyncSnmpWriteClient`). In particular the async `__init__` gains the same `snmp_write_community_resolver` parameter and `from_config` stashes the same lazy closure (write community resolved only on first write, never at construction — review item 4).

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run --extra testing pytest tests/test_dispatch.py tests/test_sync_api.py tests/test_aio_api.py -v`
Expected: PASS (existing tests + the new write tests)

- [ ] **Step 5: Commit**

```bash
git add src/netgear_switch/_dispatch.py src/netgear_switch/sync_api.py src/netgear_switch/aio_api.py tests/test_dispatch.py tests/test_sync_api.py tests/test_aio_api.py
git commit -m "feat(api): facade write methods + write-client builders + env-resolved write community"
```

---

### Task 11: Write-equivalence harness + live integration tests

**Files:**
- Modify: `tests/equivalence.py`
- Create: `tests/test_write_equivalence.py`

**Interfaces:**
- Consumes: `VirtualSwitch` (mutable mock), `facades_for`, both facades' write methods.
- Produces:
  - `facades_for` also injects write clients (same transport instances serve read + write).
  - `assert_write_equivalent(perform_sync, perform_async, expect, *, model="gsm7252ps", community="public")` — applies the same write via the sync facade on one fresh `VirtualSwitch` and via the async facade on a second; asserts both post-write `snapshot()`s are byte-identical and `expect(snapshot)` (non-vacuous change) holds.

- [ ] **Step 1: Write the failing test**

Create `tests/test_write_equivalence.py`:

```python
"""Sync/async write-equivalence against the live mutable VirtualSwitch."""
from __future__ import annotations

from equivalence import assert_write_equivalent

from netgear_switch.models import VlanMode
from netgear_switch.snmp_write import PoeCycleTimeouts

_FAST = PoeCycleTimeouts(off_timeout=2, on_timeout=2, poll_interval=0)


def test_write_equiv_set_poe_off():
    assert_write_equivalent(
        lambda s: s.set_poe(1, on=False, force=True),
        lambda a: a.set_poe(1, on=False, force=True),
        lambda snap: not next(p for p in snap.poe if p.port == 1).admin_enabled,
    )


def test_write_equiv_set_port_enabled():
    assert_write_equivalent(
        lambda s: s.set_port_enabled(5, enabled=False, force=True),
        lambda a: a.set_port_enabled(5, enabled=False, force=True),
        lambda snap: not next(p for p in snap.ports if p.port == 5).admin_enabled,
    )


def test_write_equiv_set_pvid():
    assert_write_equivalent(
        lambda s: s.set_pvid(10, 90, force=True),
        lambda a: a.set_pvid(10, 90, force=True),
        lambda snap: (10, 90) in snap.pvids,
    )


def test_write_equiv_set_vlan_membership():
    assert_write_equivalent(
        lambda s: s.set_vlan_membership(90, 25, VlanMode.TAGGED, force=True),
        lambda a: a.set_vlan_membership(90, 25, VlanMode.TAGGED, force=True),
        lambda snap: 25 in next(v for v in snap.vlans if v.vlan_id == 90).member_ports,
    )


def test_write_equiv_create_then_delete_vlan():
    assert_write_equivalent(
        lambda s: s.create_vlan(200, "guests"),
        lambda a: a.create_vlan(200, "guests"),
        lambda snap: any(v.vlan_id == 200 and v.name == "guests" for v in snap.vlans),
    )


def test_write_equiv_cycle_poe():
    assert_write_equivalent(
        lambda s: s.cycle_poe(1, force=True, timeouts=_FAST),
        lambda a: a.cycle_poe(1, force=True, timeouts=_FAST),
        lambda snap: next(p for p in snap.poe if p.port == 1).delivering,
    )


def test_write_equiv_set_mgmt_ip():
    assert_write_equivalent(
        lambda s: s.set_mgmt_ip("10.9.9.9", "255.255.255.0", "10.9.9.1", force=True),
        lambda a: a.set_mgmt_ip("10.9.9.9", "255.255.255.0", "10.9.9.1", force=True),
        lambda snap: snap.mgmt_ip is not None and snap.mgmt_ip.address == "10.9.9.9",
    )
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run --extra testing pytest tests/test_write_equivalence.py -v`
Expected: FAIL with `ImportError: cannot import name 'assert_write_equivalent'`

- [ ] **Step 3: Write minimal implementation**

In `tests/equivalence.py`, extend `facades_for` to inject write clients (reuse the same transport instances — they now implement `set`/`set_many`):

```python
def facades_for(sw: VirtualSwitch) -> tuple[SyncSwitch, AsyncSwitch]:
    """Build both facades wired to a running VirtualSwitch via injected clients.

    The injected net-snmp CLI / pysnmp clients implement both read and write, so
    each is passed as the read client AND the write client; the mock grants the
    same community read+write access (writeSubTree in the SNMP face).
    """
    model = get_model(sw.model)
    sync_client = NetsnmpCliClient(f"{sw.host}:{sw.port}", sw.community)
    aio_client = PysnmpClient(sw.host, sw.community, port=sw.port)
    sync = SyncSwitch(
        model, sw.host,
        snmp_community=sw.community, snmp_client=sync_client,
        snmp_write_client=sync_client,
    )
    aio = AsyncSwitch(
        model, sw.host,
        snmp_community=sw.community, snmp_client=aio_client,
        snmp_write_client=aio_client,
    )
    return sync, aio
```

Add the write-equivalence helper (with the imports it needs — `Callable`, `Awaitable` — added under `TYPE_CHECKING` and `VirtualSwitch` imported at runtime for construction):

```python
def assert_write_equivalent(perform_sync, perform_async, expect, *,
                            model="gsm7252ps", community="public"):
    """Apply the same write via sync (on one mock) and async (on a second, fresh
    mock), then assert both post-write snapshots are byte-identical and the
    write actually took effect (``expect``)."""
    from netgear_switch.virtual.server import VirtualSwitch

    sw_sync = VirtualSwitch(model=model, community=community)
    sw_async = VirtualSwitch(model=model, community=community)
    sw_sync.start()
    sw_async.start()
    try:
        sync_facade, _ = facades_for(sw_sync)
        _, async_facade = facades_for(sw_async)
        perform_sync(sync_facade)
        asyncio.run(perform_async(async_facade))

        # Read both back through the SYNC transport for a like-for-like compare.
        snap_from_sync = sync_facade.snapshot()
        snap_from_async = facades_for(sw_async)[0].snapshot()
        assert snap_from_sync == snap_from_async, "sync and async writes diverged"
        assert expect(snap_from_sync), "write did not take effect"
    finally:
        sw_sync.stop()
        sw_async.stop()
    gc.collect()  # finalize pysnmp transports before -W error::ResourceWarning
```

(Note: `VirtualSwitch` is already imported only under `TYPE_CHECKING` in this file; the local runtime `import` inside the helper is deliberate to keep the module-level import type-only.)

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run --extra testing pytest tests/test_write_equivalence.py -W error::ResourceWarning -v`
Expected: PASS (7 tests), no ResourceWarning

- [ ] **Step 5: Run the full suite + gates**

Run: `uv run --extra testing pytest -W error::ResourceWarning` then `uv run ruff check .` and `uv run mypy --strict src`
Expected: all green, coverage ≥90%.

- [ ] **Step 6: Commit**

```bash
git add tests/equivalence.py tests/test_write_equivalence.py
git commit -m "test(write): sync/async write-equivalence against live mutable mock"
```

---

## Self-Review Notes

**1. Spec coverage:**
- §3.1 write surface (`set_poe`, `cycle_poe`, `set_port_enabled`, `set_pvid`, `set_vlan_membership`) — Tasks 5, 6, 8, 10. `clear_poe_fault` (§11.1) — Task 8. `create_vlan`/`delete_vlan` (§11.1) — Task 7. `set_mgmt_ip` (§11.1) — Task 9.
- §6 write safety: RMW bitmaps (Tasks 1, 6) with a SINGLE canonical bitmap encoder (`write.encode_port_bitmap`; `state.encode_port_bitmap` delegates — Task 1), PVID as Gauge32 `u` (Task 6), verify-after-write → `WriteVerificationError(before, after)` comparing every written column (Task 6 egress+untagged, Task 9 address+netmask+gateway) with genuine preconditions raised as `SnmpError` (Task 6), PoE cycle state machine + polled `clear_poe_fault` with injectable timeouts (Task 8), `protected_ports` refuse-without-force on every disruptive op incl. VLAN create/delete (Tasks 5-9). CLI dry-run/confirm is explicitly a LATER slice (7) and out of scope here.
- §1 SET transport with type letters `i/u/s/x/a`, commitFailed → `SnmpError` — Tasks 2, 3. Sync/async symmetry — Tasks 2, 3, 11.
- §7 mutable virtual mock (writes visible on read-back) — Task 4. §11.2 sync/async identical device-state effects — Task 11.
- Global constraints: write community required (`_dispatch` builders, Task 10), `-W error::ResourceWarning` (Tasks 4, 11 fixtures + `gc.collect`), injectable cycle timeouts (Task 8), no blanket mypy ignores (pysnmp stays behind the existing importlib seam; the new `_to_set_value`/`_from_smi_value` take `Any` from that seam).

**2. Placeholder scan:** No TBD/TODO/"add error handling"/"similar to Task N" — every code step is complete and repeated where needed. The one honest UNVERIFIED area (mgmt-IP write OIDs, DHCP-mode set) is documented as a decision, not a gap.

**3. Type consistency:** `SetVarbind(oid, value, type_letter)` used identically in Tasks 1-11. `SnmpWriteClient`/`AsyncSnmpWriteClient` names consistent across client.py, transports, `_dispatch`, writer, facades. `SnmpWriter`/`AsyncSnmpWriter` constructor signature `(client, model, *, protected_ports=...)` identical in Tasks 5-10. `PoeCycleTimeouts` fields (`off_timeout`, `on_timeout`, `poll_interval`) consistent between Task 8 and Tasks 10-11. `apply_write(oid, value)` consistent between state, mibview, and face.

**Design decisions & risks for the controller:**
- **Writer as a separate class** (`snmp_write.py`), parallel to `snmp_read.py`, rather than methods on the reader: the reader is read-only and read-community-scoped; the writer needs a write-capable client and constructs an internal `SnmpReader`/`AsyncSnmpReader` from that same client for verify-after-write. A single RW write community reads and writes, so one client instance is both the read and write client (documented; mirrored in `facades_for`).
- **pysnmp face SET:** `_StateInstrum.write_variables` mutates `VirtualSwitchState.apply_write` then `StateMibView.rebuild()` reprojects the OID map, so subsequent GET/GETNEXT reflect the write. A `SetCommandResponder` is registered and VACM gains `writeSubTree`. Each per-varbind `apply_write` is wrapped so an unexpected exception (malformed bitmap/value) is mapped to a pysnmp `WrongValueError` (clean SNMP error-status) rather than escaping into the asyncio dispatcher — where it would surface to the client as a timeout = flaky test (review item 8); the read paths' NoSuchObject/NoSuchInstance handling is unchanged. Risk: pysnmp v7 callback name is `write_variables` (assumed by symmetry with the confirmed `read_variables`/`read_next_variables`); if it differs, Task 4 must adjust the duck-typed method name (verify against `pysnmp.entity.rfc3413.cmdrsp.SetCommandResponder`).
- **VLAN RowStatus in the mock:** create (createAndGo=4) adds an empty `VlanSim`; destroy (6) pops it; name SET fills/creates the name. The mock never emits a RowStatus read column (real agents show active=1), which is fine because no read path queries RowStatus — verification uses `get_vlans` (name/egress/untagged) only.
- **mgmt-IP set honesty & verify:** address/netmask/gateway are written to UNVERIFIED vendor OIDs (`.98.1/.2/.3`, mirroring the existing `.99.1` `dhcp_mode_unverified` placeholder precedent), force-gated because a wrong write can strand the switch, and the mock coherently updates `MgmtSim` so the standard read projection verifies. As the highest strand-risk op, verify-after-write compares ALL THREE fields (address, netmask, gateway) and names whichever diverged (review item 2). DHCP-mode switching is deliberately NOT implemented (out-of-scope-until-verified) since even its read OID is unverified — no fabricated write. Slice 7's capture utility must confirm the real OIDs before these are trusted on hardware.
- **Lazy write-community resolution:** `from_config` stashes a resolver closure (spec + env) and resolves the write community only inside `_writer()` on the first write, so a read-only consumer whose env lacks a resolvable write-community spec (`${UNSET_VAR}`) constructs and reads fine; a missing/unresolvable write community raises `CredentialError`/`ConfigError` only when a write is actually attempted (review item 4). The `_dispatch` write-client builders still require a non-None community (raising `CredentialError`), but that check now fires at write time, not construction.
- **VLAN create/delete protected-port guard:** `delete_vlan` looks up the VLAN's current member ports via the internal reader and refuses with `ProtectedPortError` if any is in `protected_ports` unless `force=True` (it strips membership from every member port, possibly an uplink/mgmt port). `create_vlan` gains a `force` parameter for signature symmetry only — creating an empty VLAN touches no existing membership and is non-disruptive, so it does not require force (review item 3).
- **PoE coherence & cycle termination:** the mock applies admin-off → detect=1 + data-port link-down and admin-on → detect=3, so `cycle_poe` terminates immediately against the mock; timeouts are injected tiny in tests. `clear_poe_fault` uses the SAME injectable timeout/poll structure (review item 5) — it polls for detect to leave FAULT (return to delivering/searching) rather than doing a single immediate re-read, which would false-negative on real hardware where detect transitions take seconds. Risk: real hardware detect transitions take seconds — the default 30/60s timeouts (spec §6) cover that in production.
- **Write-equivalence** uses two independent fresh mocks (not one shared) so sync and async each apply the write once from an identical seed, then compares full `snapshot()`s — proving identical device-state effects without double-application.
