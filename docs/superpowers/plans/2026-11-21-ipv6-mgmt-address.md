# IPv6 management address — handover plan (issue #28)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Date:** 2026-11-21
**Issue:** https://github.com/mithro/python-netgear-switch-library/issues/28
**Spec:** the issue is the spec. Its captured `IPConf_master.xml` read and the
page's own submit JavaScript (`getAddPostData`, the gateway `Apply`, the
address `delete`) are the ONLY grounding for Part A; copy them, do not
re-derive them. Everything in Parts B and C that is not yet captured says so.

**Goal:** make the library able to read and set a switch's IPv6 management
address and default gateway, first on the GS728TPP (GoAhead `wcd` XML API),
then make the existing IPv4 `set_mgmt_ip` actually work on the GS728TPP and
become live-verified on the FASTPATH models, then give every registered model
and backend the same IPv6 surface or an owner-recorded exemption.

**Architecture:** one new read op (`get_ipv6_config`) and three new write ops
(`set_ipv6_address`, `delete_ipv6_address`, `set_ipv6_gateway`) plumbed the
same way `get_mgmt_ip`/`set_mgmt_ip`/`set_hostname` already are: a pure body
builder in `protocols/http/goahead.py`, a parser in `protocols/http/parse.py`,
reader/writer methods in `http_read.py`/`http_write.py` (sync + async twins),
capability declarations in `capabilities.py`, facade methods in
`sync_api.py`/`aio_api.py`, an MCP tool per op in `mcp/server.py`, an `ngsw`
subcommand, and the virtual switch grown to project and accept the same
objects so the mock keeps proving the writer.

**Tech Stack:** Python 3.11+, `uv`, pytest (one file at a time, `--no-cov`),
ruff, mypy. Live hardware: `gs728tpp-monarto` (10.2.5.10, firmware 6.0.1.30).

## Why this exists (from the issue)

The GS728TPP has IPv6 enabled but no DHCPv6 client (SLAAC and static only).
The site's router advertisements are `managed, other stateful` with the prefix
`onlink` only, so SLAAC never forms a global address and the switch's DNS /
`dhcp-host` reservation is never satisfied. The fix is a static IPv6 address
plus gateway on the switch — the exact write the library lacks. Until Part A
lands that write is a one-off `wcd` POST done outside the library.

## Global Constraints (from `CLAUDE.md`)

- Fail fast and loud; never switch backend mid-operation; an unsupported
  combination raises `UnsupportedCapabilityError` naming model + backend + op.
- Backend parity and every-model parity. A missing backend/model implementation
  is a TODO, not a device limitation, until a captured device response proves
  it; exemptions are recorded in the registry entry with the reason and
  firmware, and only the owner grants them.
- The virtual switch must reproduce measured behaviour (including refusals) and
  must be seeded from captured values, never from the formula under test.
- `force=True` on every write that can change how the caller reaches the switch
  (all three IPv6 writes, and `set_mgmt_ip`).
- Never persist configuration while testing. Persisting is an OPERATOR action
  the operator asks for explicitly (see owner decision D4).
- Credentials: `sudo -n .venv/bin/gdoc2netcfg password --type password -q
  <host>` from `/opt/gdoc2netcfg`. **The GS728TPP's password exists only in
  ten64.monarto's gdoc2netcfg, not welland's** — run live steps on
  ten64.monarto, or fetch the secret there and pass it via `--http-password`.
  Never print one, never commit one.
- Run tests as `PYTHONPATH=src .venv/bin/python -m pytest <file> -q --no-cov`,
  one pytest process at a time. `uv run ruff check src/ tests/` and
  `uv run mypy` clean before every commit. No `2>/dev/null`.
- Small commits, one per task step that produces a green test.

## Review Focus

Inputs the spec implies but no existing test exercises, most likely to bite
first; each has its pinning test named in the owning task.

1. **A second global address when one already exists** (operator re-runs
   `set_ipv6_address` with a different address): the page ADDS rather than
   replaces. Expected: the library adds, reports both on read-back, and never
   silently deletes the old one. Pinned in Task A5 (`test_second_global_address_is_added_not_replaced`).
2. **A link-local address given to `set_ipv6_address`**: the page sends
   `type=1` for `fe80::/10`; the library must do the same and must NOT delete
   the switch's own auto link-local. Pinned in Task A2
   (`test_address_body_marks_fe80_as_link_local`).
3. **Gateway set when a gateway already exists**: the page deletes the old
   `GatewayEntry` first, in the SAME POST. Expected: one body with a `delete`
   list then a `set` list. Pinned in Task A2 (`test_gateway_body_deletes_previous_in_same_post`).
4. **Prefix length outside 1–128 or a non-IPv6 string**: must raise
   `ValueError` BEFORE any POST (the page's `Validation.pass` does this
   client-side, so the firmware's behaviour on garbage is unknown). Pinned in
   Task A5 (`test_set_ipv6_address_rejects_bad_input_before_posting`).
5. **Managed interface is not `VLAN5`**: the page computes it from
   `IPv4InterfaceList` (`owner` 2 or 5) at runtime. A hard-coded `VLAN5` would
   write to the wrong interface on any switch managed on another VLAN. Pinned
   in Task A3 (`test_managed_interface_follows_ipv4_owner_not_a_constant`).

---

# Part A (b.1) — GS728TPP IPv6 over the GoAhead `wcd` API

## File structure

| File | Responsibility |
|---|---|
| `src/netgear_switch/models.py` | `Ipv6Scope`, `Ipv6Origin`, `Ipv6Address`, `Ipv6Config` dataclasses |
| `src/netgear_switch/protocols/http/goahead.py` | pure body builders for `IPv6AddressList` / `IPv6GatewayList` |
| `src/netgear_switch/protocols/http/parse.py` | `parse_goahead_ipv6`, `parse_goahead_managed_interface` |
| `src/netgear_switch/protocols/http/endpoints.py` | `HttpModelSpec.ipv6_path`; `_GS728TPP.ipv6_path` |
| `src/netgear_switch/http_read.py` | `HttpReader.get_ipv6_config` (+ async) |
| `src/netgear_switch/http_write.py` | `set_ipv6_address`, `delete_ipv6_address`, `set_ipv6_gateway` (+ async) |
| `src/netgear_switch/capabilities.py` | four `Operation`s, `_XML_API_WRITES`, `_http_path_for` |
| `src/netgear_switch/sync_api.py`, `aio_api.py`, `_dispatch.py` | facade methods; every other backend raises unsupported until Part C |
| `src/netgear_switch/mcp/server.py` | tools `get_ipv6_config`, `set_ipv6_address`, `delete_ipv6_address`, `set_ipv6_gateway` |
| `src/netgear_switch/cli/main.py`, `cli/format.py` | `ngsw ip6 show|add|del|gateway` |
| `src/netgear_switch/virtual/state.py` | `MgmtSim` IPv6 fields |
| `src/netgear_switch/virtual/web_gs728tpp.py` | `render_ipv6`, `apply_write` branches |
| `tests/fixtures/http/gs728tpp_ipv6.xml` | the issue's captured read, verbatim |
| `tests/protocols/http/test_goahead_write.py`, `test_parse.py`, `tests/test_http_write.py`, `tests/test_http_read.py`, `tests/virtual/test_gs728tpp_ipv6.py`, `tests/test_capabilities.py`, `tests/test_mcp_server.py`, `tests/test_write_equivalence.py`, `tests/test_sync_api.py` | tests |
| `docs/guide/reading.rst`, `docs/guide/writing.rst`, `docs/mcp.rst`, `docs/cli.rst`, `docs/models/*.rst` | documentation (`test_docs_coverage` enforces module docs) |

## Wire facts (copied from issue #28; do not re-derive)

Read: `wcd?{file=/System/Management/IPConf_master.xml}{IPv6InterfaceList}{IPv6AddressList}{IPv6GatewayList}{IPv4InterfaceList}`.
Braces are sent RAW (the transport already does this for the other wcd paths).

| Element | Meaning (measured on 10.2.5.10, 6.0.1.30) |
|---|---|
| `IPv6InterfaceList/InterfaceEntry/{interfaceID,interfaceType,interfaceName,status,statelessAutoconfigEnable}` | one entry, `VLAN5`/`5`/type `3`; `status` 1 = IPv6 admin on; autoconfig 1 = on |
| `IPv6AddressList/IPv6addressEntry/type` | 1 link-local, 2 global, 4 multicast |
| `.../origin` | 5 = autoconfigured (the only value captured; static will be measured in Task A7) |
| `.../EUI64Enable` | empty on every captured row |
| `IPv6GatewayList` | empty on the capture |
| `IPv4InterfaceList/ifEntry/owner` | 2 on the managed interface; the page's `calcManagedVlan()` picks the entry with owner `2` or `5` |

Write bodies (the page's `post` object, serialised by `goahead.write_body`):

```text
IPv6AddressList action=set    IPv6addressEntry{interfaceName, interfaceType="3", interfaceID, type("1"|"2"), IPv6Address, prefixLength, EUI64Enable}
IPv6AddressList action=delete IPv6addressEntry{interfaceName, IPv6Address, prefixLength, type}
IPv6GatewayList action=delete GatewayEntry{interfaceName, addrType, IPv6Address}   (only if a gateway exists; SAME POST as the set)
IPv6GatewayList action=set    GatewayEntry{interfaceName, addrType("3" if fe80 else "2"), IPv6Address}
```

`interfaceID` is `interfaceName` with the leading `VLAN` stripped
(`managedVlan.substr(4)`).

## Tasks

### Task A1: data model

**Files:** Modify `src/netgear_switch/models.py` (after `MgmtIpConfig`); Test `tests/test_models.py`.

**Produces:**
```python
class Ipv6Scope(enum.Enum): LINK_LOCAL = "link-local"; GLOBAL = "global"; MULTICAST = "multicast"; UNKNOWN = "unknown"
class Ipv6Origin(enum.Enum): STATIC = "static"; AUTOCONF = "autoconf"; DHCP = "dhcp"; LINK_LAYER = "link-layer"; UNKNOWN = "unknown"

@dataclass(frozen=True)
class Ipv6Address:
    address: str          # canonical lower-case, as ipaddress.IPv6Address(str) renders it
    prefix_len: int
    scope: Ipv6Scope
    origin: Ipv6Origin
    eui64: bool = False

@dataclass(frozen=True)
class Ipv6Config:
    enabled: bool | None           # None = backend cannot tell
    autoconfig: bool | None
    dhcp: bool | None              # DHCPv6 client; GS728TPP has none -> None
    addresses: tuple[Ipv6Address, ...]
    gateway: str | None
    interface: str | None          # "VLAN5" on GoAhead; "vlan 5" on M4300 CLI; None where unknown
```

Decision D1 (below) is pre-decided here as "separate `Ipv6Config`, do not widen
`MgmtIpConfig`": `MgmtIpConfig` is constructed positionally in eight places and
is one address; IPv6 is a list. Revisit only if the owner overrides D1.

- [ ] Write `test_ipv6_address_is_frozen_and_hashable` and
      `test_ipv6_config_round_trips_through_asdict` in `tests/test_models.py`.
- [ ] Run; expect `ImportError`.
- [ ] Add the four types; export them from `netgear_switch/__init__.py` next to `MgmtIpConfig`.
- [ ] Run `tests/test_models.py` and `tests/test_public_api.py`; both pass.
- [ ] Commit `models: Ipv6Address / Ipv6Config`.

### Task A2: GoAhead body builders

**Files:** Modify `src/netgear_switch/protocols/http/goahead.py`; Test `tests/protocols/http/test_goahead_write.py`.

**Produces:**
```python
INTERFACE_VLAN = "3"
IPV6_TYPE_LINK_LOCAL = "1"; IPV6_TYPE_GLOBAL = "2"; IPV6_TYPE_MULTICAST = "4"
IPV6_GW_TYPE_GLOBAL = "2"; IPV6_GW_TYPE_LINK_LOCAL = "3"

def ipv6_address_type(address: str) -> str          # "1" for fe80::/10, else "2"
def ipv6_gateway_type(address: str) -> str          # "3" for fe80::/10, else "2"
def ipv6_address_body(iface_name: str, iface_id: str, address: str, prefix_len: int, *, eui64: bool = False) -> str
def ipv6_address_delete_body(iface_name: str, address: str, prefix_len: int) -> str
def ipv6_gateway_body(iface_name: str, gateway: str, *, previous: str | None) -> str
```
`ipv6_gateway_body` with `previous` renders `<IPv6GatewayList action="delete">…</IPv6GatewayList><IPv6GatewayList action="set">…</IPv6GatewayList>`
inside ONE `DeviceConfiguration` — `write_body` renders one object, so add
`write_bodies(parts: Sequence[tuple[str, str, Sequence[Node]]]) -> str` beside it
rather than concatenating two documents. `EUI64Enable` renders `"1"` when
`eui64` else `""` (the capture shows `""` for off; `"1"` for on is the page's
checkbox value and is confirmed in Task A7 — do not change the test if the
firmware answers differently, change the constant AND record the measurement).

- [ ] Tests, each asserting the exact element sequence as the existing
      `test_membership_tagged_matches_the_pages_own_post_object` does:
      `test_address_body_matches_getAddPostData`,
      `test_address_body_marks_fe80_as_link_local`,
      `test_address_delete_body_carries_only_identity_fields`,
      `test_gateway_body_without_previous_is_a_single_set`,
      `test_gateway_body_deletes_previous_in_same_post`,
      `test_gateway_body_marks_fe80_gateway_type_3`.
- [ ] Run; fail on missing names.
- [ ] Implement.
- [ ] Run; pass. ruff + mypy clean.
- [ ] Commit `goahead: IPv6 address and gateway write bodies, transcribed from IPConf page JS`.

### Task A3: parser and fixture

**Files:** Create `tests/fixtures/http/gs728tpp_ipv6.xml` (the issue's capture, whole `<ResponseData>`, session path scrubbed); Modify `src/netgear_switch/protocols/http/parse.py` (beside `parse_goahead_mgmt_ip`); Test `tests/protocols/http/test_parse.py`.

**Produces:**
```python
def parse_goahead_managed_interface(body: str) -> tuple[str, str]   # ("VLAN5", "5"); raises HttpUnexpectedPageError if no ifEntry has owner in {"2","5"}
def parse_goahead_ipv6(body: str) -> Ipv6Config
```
Mapping: `type` 1→LINK_LOCAL, 2→GLOBAL, 4→MULTICAST, else UNKNOWN; `origin`
5→AUTOCONF, and the static value measured in Task A7 → STATIC (leave a
`_GOAHEAD_IPV6_ORIGIN` dict with a comment naming the measurement); multicast
rows are KEPT in `addresses` (the device reports them; dropping them would be a
degraded result) — callers filter by scope. `enabled` from `InterfaceEntry/status == "1"`,
`autoconfig` from `statelessAutoconfigEnable == "1"`, `dhcp=None`,
`gateway` = first `IPv6GatewayList/GatewayEntry/IPv6Address` or None.

- [ ] Tests on the fixture: `test_parse_goahead_ipv6_fixture_has_link_local_and_two_multicast`,
      `test_parse_goahead_ipv6_gateway_absent_is_none`,
      `test_parse_goahead_ipv6_flags`, `test_managed_interface_follows_ipv4_owner_not_a_constant`
      (feed a body whose managed entry is `VLAN7`/owner 5 and assert `("VLAN7","7")`),
      `test_parse_goahead_ipv6_raises_when_no_interface_entry`.
- [ ] Run; fail. Implement. Run; pass. Commit `parse: GoAhead IPConf IPv6 sections`.

### Task A4: read path

**Files:** Modify `endpoints.py` (`HttpModelSpec.ipv6_path: str | None = None`; set on `_GS728TPP` to the read query above), `http_read.py` (`HttpReader.get_ipv6_config(self) -> Ipv6Config`, `AsyncHttpReader` twin; raise `UnsupportedCapabilityError` naming the model when `ipv6_path is None`), `capabilities.py` (`Operation("get_ipv6_config", OperationKind.READ, "IPv6 management addresses and gateway")`; `_http_path_for`: `"get_ipv6_config": spec.ipv6_path`), `sync_api.py` / `aio_api.py` / `_dispatch.py` (`get_ipv6_config(backend=None)`), `virtual/state.py` (`MgmtSim.ipv6_enabled: bool = True`, `ipv6_autoconfig: bool = True`, `ipv6_addresses: list[Ipv6Address]`, `ipv6_gateway: str | None = None`; seed gs728tpp from the fixture values in `virtual/seed.py`), `virtual/web_gs728tpp.py` (`render_ipv6(state)` serving `ipv6_path`; register the path in `virtual/faces/http.py` beside `mgmt_ip_path`).

- [ ] `tests/test_http_read.py::test_get_ipv6_config_gs728tpp_parses_fixture` (fake session returning the fixture) and `::test_get_ipv6_config_unsupported_names_model` (gsm7252ps spec).
- [ ] `tests/virtual/test_gs728tpp_ipv6.py::test_http_read_matches_seed` through a real `VirtualSwitch(model="gs728tpp")` + `SyncSwitch(... http_client=...)` exactly as `test_sync_switch_upload_certificate_gs728tpp_records_on_mock` does.
- [ ] `tests/test_capabilities.py`: `get_ipv6_config` SUPPORTED for gs728tpp/http, UNSUPPORTED (with reason) for every other model/backend.
- [ ] Commit `http: get_ipv6_config on the GoAhead dialect`.

### Task A5: write path

**Files:** Modify `http_write.py` (sync + async): 
```python
def set_ipv6_address(self, address: str, prefix_len: int, *, eui64: bool = False, force: bool = False) -> None
def delete_ipv6_address(self, address: str, prefix_len: int, *, force: bool = False) -> None
def set_ipv6_gateway(self, gateway: str, *, force: bool = False) -> None
```
Each: validate with `ipaddress.IPv6Address` / `1 <= prefix_len <= 128` and raise
`ValueError` before any I/O; `ProtectedPortError` without `force` (same message
style as `set_mgmt_ip`); GET `ipv6_path`, `parse_goahead_managed_interface`,
`parse_goahead_ipv6` as `before`; `_goahead_write(body, what)`; GET again and
`WriteVerificationError(before=…, after=…)` unless the address (canonicalised) is
present / absent / the gateway equals. `set_ipv6_gateway` passes
`previous=before.gateway`. Add all three to `_XML_API_WRITES`; declare the
three `Operation`s (WRITE) in `capabilities.py`; facade methods in
`sync_api.py`/`aio_api.py`; `WRITE_ARGS` in `tests/test_capabilities.py`
(`("2001:db8::10", 64)`, `("2001:db8::10", 64)`, `("2001:db8::1",)`).
`virtual/web_gs728tpp.apply_write`: branches for `IPv6AddressList` (set appends
an `Ipv6Address(origin=STATIC, scope from type)`; a duplicate address+prefix is
answered with the statusCode measured in Task A7, placeholder `2` until then,
marked `# UNMEASURED`) and `IPv6GatewayList` (delete must name the current
gateway or statusCode 2; set replaces).

- [ ] `tests/test_http_write.py`: `test_set_ipv6_address_requires_force`,
      `test_set_ipv6_address_rejects_bad_input_before_posting` (fake session asserts zero POSTs),
      `test_set_ipv6_address_posts_grounded_body_and_verifies`,
      `test_set_ipv6_gateway_deletes_previous_when_one_exists`,
      `test_delete_ipv6_address_verifies_absence`, async twins for the first and third.
- [ ] `tests/virtual/test_gs728tpp_ipv6.py`: `test_add_then_delete_round_trip`,
      `test_second_global_address_is_added_not_replaced`,
      `test_gateway_set_replaces_previous`, `test_unsupported_object_is_nonzero_status` (unchanged behaviour, keep).
- [ ] `tests/test_write_equivalence.py`: `test_write_equiv_set_ipv6_address`, `test_write_equiv_set_ipv6_gateway`.
- [ ] `tests/test_sync_api.py`: the three facade methods dispatch with `backend=Backend.HTTP` and raise unsupported for `Backend.SNMP` on gs728tpp.
- [ ] Commit per green file: `http: set_ipv6_address/delete_ipv6_address/set_ipv6_gateway on GoAhead`, `virtual: GS728TPP IPv6 address and gateway objects`, `equivalence: ipv6 writes`.

### Task A6: MCP, CLI, docs

- [ ] `mcp/server.py`: read tool `get_ipv6_config`; write tools `set_ipv6_address(address, prefix_len, eui64=False, force=False, …)`, `delete_ipv6_address`, `set_ipv6_gateway`, under the same `NGSW_MCP_ALLOW_WRITES` gate. Tests in `tests/test_mcp_server.py` mirroring the `set_mgmt_ip` entries (tool registered; drives facade with `force`).
- [ ] `cli/main.py`: `ngsw … ip6 show`, `ip6 add <addr>/<len> [--eui64]`, `ip6 del <addr>/<len>`, `ip6 gateway <addr>`, all through `safety.do_write` with the strand warning; `cli/format.py::ipv6_text`. Test in `tests/cli/`.
- [ ] Docs: rows in `docs/guide/reading.rst` and `writing.rst` tables; `docs/mcp.rst` tool lists; `docs/cli.rst`; model page for the new dataclasses. `tests/test_docs_coverage.py` passes.
- [ ] Commit `mcp+cli+docs: IPv6 management address`.

### Task A7: live verification on gs728tpp-monarto (controller-only, from ten64.monarto)

Preconditions: Part A merged to a branch; `ngsw` installed from that branch in
a venv on ten64.monarto or driven through `uv run --project`. The inventory
name is `gs728tpp-monarto`. The switch is production: ports and VLANs are not
touched; only the IPv6 address list is.

- [ ] `ngsw --switch gs728tpp-monarto ip6 show` → record the output in
      `tmp/live-captures/gs728tpp_ipv6_before.txt` (gitignored).
- [ ] Add a THROWAWAY documentation-prefix address: `ngsw … ip6 add 2001:db8:4001::10/64 --force`. Expected: exit 0, read-back lists it with `origin` STATIC. Record the raw `origin` value the firmware reports → set `_GOAHEAD_IPV6_ORIGIN` accordingly (Task A3) and the mock's STATIC projection.
- [ ] Add the SAME address again → record the exact `statusCode`/`statusString` → replace the Task A5 `# UNMEASURED` placeholder in `web_gs728tpp.apply_write` and add `test_duplicate_address_status_matches_hardware`.
- [ ] `ngsw … ip6 del 2001:db8:4001::10/64 --force`; read-back shows it absent; the switch's own link-local and multicast rows are unchanged byte-for-byte versus the `before` capture.
- [ ] Gateway: if the operator has already set the production gateway (task (a) of the 2026-11-21 session), verify with an IDEMPOTENT write of the same value (`ip6 gateway <current> --force`): proves the delete+set body is accepted and reads back equal without ever leaving the switch gateway-less. If no gateway is set, set the production one ONLY on the owner's instruction (D4).
- [ ] Commit the fixture updates and measurement comments: `gs728tpp: IPv6 writes live-verified 2026-xx-xx on 10.2.5.10 fw 6.0.1.30`.
- [ ] Persistence: the operator step. Determine (D4) whether Apply persists across power loss on this firmware. Procedure: locate the Save/Copy page in the switch's `SiteMap.xml` (the site map capture from 2026-11-21 shows only the word "Save"; the page and its JS were not captured), capture its JS, and decide whether a `save_config(force=True)` op is wanted. **Do not reboot the switch to test persistence**; the g26/g28 LAG to ten64.monarto rides on it.

---

# Part B (b.2) — getting the IPv4 management writes going

## State of play (measured in code, 2026-11-21)

| Backend | gs728tpp | gsm7252ps / gsm7228ps | m4300-24x / -16x | gs110emx / gs305ep / gs105pe |
|---|---|---|---|---|
| HTTP `set_mgmt_ip` | **unsupported** — `_GS728TPP.mgmt_ip_fields is None`, and `_XML_API_WRITES` has no entry | XUI form implemented; APPLY **UNVERIFIED** (`http_write.set_mgmt_ip` docstring) | same as gsm72xx (`_M4300_MGMT_IP_FIELDS`) | Plus forms; unverified |
| CLI `set_mgmt_ip` | n/a (no CLI) | `network parms <ip> <mask> <gw>` implemented, **never live-run**; a DHCP-mode switch (both captures say `Configured IPv4 Protocol DHCP`) may need `network protocol none` first — unmeasured | `ip management address` + `ip default-gateway` implemented, never live-run | n/a |
| SNMP `set_mgmt_ip` | **unsupported** (no vendor subtree) | vendor `mgmt_write_*_unverified` placeholders (`…98.1/2/3`) — **never trusted** | same | n/a |
| NSDP `set_mgmt_ip` | n/a | n/a | n/a | implemented; live status per model in `nsdp_write.py` |

### Task B1: GoAhead IPv4 write (gs728tpp)

Grounding to capture first (nothing below is implemented until this exists):

- [ ] From ten64.monarto, logged in as the library does, GET `<sess>/Behaviour/IpConfig.js` (the IPConf page's `<jscript SRC>` in `tests/fixtures/http/gs728tpp_mgmt_ip.xml`) and save to `tmp/live-captures/gs728tpp_IpConfig.js`. Transcribe `IPConf.ApplyBtnClick` → which of `IPv4InterfaceList/ifEntry/{interfaceName,owner,IPAddr,subnetMask}` and `IPv4GatewayList/GWEntry/IPAddr` are posted, and the `owner` value that means static vs DHCP (the page's radios `rDhcp`/`rSt` bind to `owner`; the live static switch reports `owner=2`).
- [ ] `goahead.ipv4_interface_body(iface_name, address, netmask, *, owner: str)` and `goahead.ipv4_gateway_body(iface_name, gateway, *, previous: str | None)` in `goahead.py`; tests in `test_goahead_write.py` transcribed from the JS.
- [ ] `parse_goahead_mgmt_ip`: map `owner` → `IpMode` (currently always UNKNOWN) once the JS fixes the meaning; test on the existing fixture (`owner=2` → STATIC if the JS says so).
- [ ] `HttpWriter.set_mgmt_ip`: GoAhead branch before `_require_xui_mgmt_fields`; `_XML_API_WRITES["set_mgmt_ip"] = True`; `virtual/web_gs728tpp.apply_write` branch for `IPv4InterfaceList` / `IPv4GatewayList`; capability test flips gs728tpp/http to SUPPORTED.
- [ ] Commit per green file.

### Task B2: live-verifying IPv4 management writes without stranding a switch

Pick ONE of these per switch and record which was used in the writer docstring
(the docstring currently says "deliberately never applied"; change it only
with the evidence).

1. **Idempotent write** — same address/mask/gateway as currently configured.
   Proves the request is accepted and the read-back path works; proves nothing
   about change. Acceptable as the FIRST live step on every model.
2. **Gateway-only change from an on-link client.** Run from a host on the
   switch's management subnet (ten64.monarto for the GS728TPP, ten64.welland
   for the welland FASTPATH switches). Change the gateway to another address on
   the same subnet, read back, restore, read back. Replies to the on-link
   client never use the gateway, so the session survives. **Do this from the
   on-link host, never over the WireGuard tunnel** — tunnelled traffic is
   off-subnet and the switch's replies to it go via the gateway being changed.
3. **Console-backed address change.** Only on a switch with an out-of-band
   console that can issue `network parms` to restore: `gsm7252ps-s1` (console on
   rpiz-serial :4004). Change the address to a free address on the same subnet
   (reserve it in the sheet first), read back over the NEW address, restore
   from the old session or the console.
4. **Lab unit.** No spare GoAhead or FASTPATH unit is known; the Plus units
   (GS105PE/GS110EMX) are a different dialect and prove nothing about these
   pages. Owner decision D6.

- [ ] GS728TPP: strategy 1 then 2 via `ngsw … ip set 10.2.5.10 255.255.255.0 10.2.5.1 --force`.
- [ ] gsm7252ps-s1 (console-backed): strategy 1, then 3 if the owner agrees (D6); this also measures whether `network parms` is refused while `Configured IPv4 Protocol` is DHCP — if so add `mgmt_ip_mode_cmds` (`network protocol none` / `network protocol dhcp`) to `CliModelSpec`, grounded in the captured refusal text.
- [ ] m4300-16x-poe-s2 (`ip management address`): strategy 1 then 2.
- [ ] Record each result as `VERIFIED live @<ip> (fw <ver>) on <date>` in the writer docstrings and `docs/guide/writing.rst` "Management IP" (which currently says never applied).

### Task B3: SNMP IPv4 management write — find the real columns or record the exemption

- [ ] On gsm7252ps-s1 and m4300-16x-poe-s2: `ngsw … capture --output tmp/before.json` (full walk), change ONLY the gateway via the web UI (strategy 2), capture again, diff. The columns that moved are the write targets. Candidates to confirm, NOT to assume: NETGEAR-SWITCHING-MIB `agentNetworkConfigGroup` (`1.3.6.1.4.1.4526.10.1.1.1`): `.1` address, `.2` mask, `.3` gateway, `.7` config protocol.
- [ ] Replace `mgmt_write_*_unverified` with the measured OIDs (rename, drop the suffix) in `oids.py`; write-test with an SNMP SET of the SAME value (`noError` vs `notWritable` is the measurement); update `virtual/state.py` seeds and `docs/superpowers/specs/2026-08-03-snmp-vendor-oid-sweep.md`.
- [ ] gs728tpp SNMP: a walk of `4526` is `noSuchObject` (already recorded). Measure `ipAddressRowStatus` (`1.3.6.1.2.1.4.34.1.8`) writability with a SET of the existing row's value; expected `notWritable` → record the exemption in `registry.py` with the exact error.

---

# Part C (b.3) — IPv6 on every registered model and backend

## Model × backend matrix

Registered models (`registry.py`): m4300-24x, m4300-16x, gsm7252ps, gsm7228ps (alias s3300), gs110emx, gs305ep, m7300, xs748t, gs728tpp, gs105pe.

| Model | Backends | Read today | Write today | What must be captured |
|---|---|---|---|---|
| gs728tpp | SNMP, HTTP | HTTP after Part A | HTTP after Part A | SNMP: walk `1.3.6.1.2.1.4.34` (ipAddressTable) for type-2 rows → read-only `get_ipv6_config` over SNMP is likely possible; writes → B3 measurement |
| gsm7252ps | SNMP, HTTP, SSH, TELNET | CLI `show network` already prints `IPv6 Administrative Mode`, `IPv6 Prefix is` (one line per address, `/128` for the DHCP one), `IPv6 Default Router`, `Configured IPv6 Protocol`, `IPv6 AutoConfig Mode` (fixture `gsm7252ps_show_network.txt`) — parser missing | none | CLI write grammar via `show running-config` diff after a UI change (candidates: `network ipv6 enable`, `network ipv6 address <prefix>/<len> [eui64]`, `network ipv6 gateway <gw>`, `network ipv6 address dhcp`, `network ipv6 address autoconfig`); XE HTTP page (sibling of `/ipConfiguration.html`; name unknown); SNMP vendor columns (candidates under `agentNetworkConfigGroup`, likely an `agentNetworkIpv6AddrTable` — confirm by diff) |
| gsm7228ps (S3300) | SNMP, HTTP, TELNET(60000) | `gsm7228ps_network.txt` has the same IPv6 lines | none | as gsm7252ps; HTTP S3300 dialect page unknown |
| m4300-24x / -16x | SNMP, HTTP, SSH, TELNET | `show ip management` prints `IPv6 Management Interface`, `IPv6 Prefix is` with a continuation line and `[DHCP]` tag, `IPv6 Default Gateway` (fixture `m4300_16x_show_ip_management.txt`); the -24X fixture says `IPv6 Management Interface is not Configured.` — parser missing | none | CLI grammar (global config `ip management ipv6 …`? — capture, do not guess); XUI page (sibling of `/v1/mgmtVlanIpv4Configuration.html` — the obvious candidate `/v1/mgmtVlanIpv6Configuration.html` must be fetched and confirmed); SNMP as above |
| gs110emx, gs305ep | NSDP, HTTP | none | none | NSDP has no IPv6 TLV in the protocol as implemented; check the web UI for an IPv6 page at all. If absent on the firmware in the field, record the exemption with the page list that proves it |
| gs105pe | NSDP, HTTP | none | none | same as gs110emx |
| m7300, xs748t | SNMP | none | none | did not answer SNMP in the 2026-08-22 sweep; exemption "unreachable, unmeasured" until a unit answers |

### Task C1: CLI reads (parsers only, from existing fixtures)

- [ ] `protocols/cli/parse.py::parse_ipv6_config(text: str) -> Ipv6Config` over `labelled_values` PLUS a multi-line collector for repeated `IPv6 Prefix is` and `IPv6 Default Router` labels and the M4300 continuation line (`labelled_values` keeps the last value only — extend with `labelled_values_multi(text) -> dict[str, list[str]]`). Scope from the prefix (`fe80::/10` → LINK_LOCAL), origin from the `[DHCP]` tag or `Configured IPv6 Protocol`, `interface` from `IPv6 Management Interface`.
- [ ] Tests on the four fixtures in `tests/protocols/cli/test_cli_parse.py`; `CliReader.get_ipv6_config` using `network_cmd`; `virtual/cli_fastpath.render_network` grows the IPv6 lines from `MgmtSim`; parity test in `tests/virtual/test_cli_cross_backend.py`.
- [ ] Commit `cli: get_ipv6_config from show network / show ip management`.

### Task C2: CLI writes (FASTPATH), grounded per image

- [ ] On gsm7252ps-s1 (console-backed) and m4300-16x-poe-s2: `show running-config` → file; add a throwaway `2001:db8:4001::/64` address via the web UI; `show running-config` again; diff gives the exact grammar per image. Repeat for the gateway. Remove via the UI; diff shows the `no` form. Save NOTHING.
- [ ] `CliModelSpec.ipv6_address_cmds`, `ipv6_no_address_cmds`, `ipv6_gateway_cmds` (+ `_M4300_OVERRIDES`); `CliWriter.set_ipv6_address/delete_ipv6_address/set_ipv6_gateway` with read-back through `parse_ipv6_config`; `virtual/cli_fastpath` accepts the same commands; tests in `tests/test_cli_write.py` and `tests/virtual/test_cli_cross_backend.py`.
- [ ] Live A/B/A on the throwaway address through the library; record firmware versions in the spec comments.
- [ ] Commit per model dialect.

### Task C3: HTTP XUI / XE / S3300 reads and writes

- [ ] Capture each model's IPv6 page (login as the library does; save HTML + referenced JS under `tmp/live-captures/`, scrub `SID=`/session tokens, copy to `tests/fixtures/http/<model>_ipv6.html`). Add `ipv6_path` and an `XuiIpv6Fields` (mirroring `XuiMgmtIpFields`) per spec in `endpoints.py`.
- [ ] `parse_xui_ipv6` / `parse_xe_ipv6` / `parse_s3300_ipv6` grounded on the fixtures; `HttpReader.get_ipv6_config` dialect switch like `_mgmt_ip`.
- [ ] Writes through `forms.xui_form_apply_form` with the `submit_flag=8` machinery `set_mgmt_ip` already uses; `_raise_on_fastpath_err_flag`; verify-after-write.
- [ ] Virtual faces: `web_fastpath_xui.render_ipv6/apply_ipv6`; seeds from fixtures.
- [ ] Live-verify with the throwaway address (same as C2), reading back over CLI as the independent backend.

### Task C4: SNMP reads and writes

- [ ] Read: walk `ipAddressTable` (`1.3.6.1.2.1.4.34.1.{3,4,5,6}`) on every reachable SNMP model; rows indexed `.2.16.<16 bytes>` are IPv6. `parse_ipv6_addresses_rfc4293` → `Ipv6Config.addresses` (scope from the address; origin from `ipAddressOrigin` .6: 2 manual, 4 dhcp, 5 linklayer, 6 random → map to `Ipv6Origin`). Gateway: `inetCidrRouteTable` (`1.3.6.1.2.1.4.24.7`) default route for `inetCidrRouteDestType=2`, else vendor column. Flags (`enabled`, `autoconfig`, `dhcp`) from vendor columns found in B3/C2's diffs, else None.
- [ ] Write: the vendor columns the walk-diff in C2 reveals (candidate: an `agentNetworkIpv6…` table with a RowStatus). A SET of the existing value measures writability; `notWritable`/`noAccess` with the captured error is the exemption evidence for that model+backend.
- [ ] `virtual/state.py` SNMP projection of `MgmtSim.ipv6_*`; `tests/virtual/test_snmp_write_face.py`.

### Task C5: Plus-class and unreachable models — measure, then record

- [ ] gs110emx / gs305ep / gs105pe: list every page in the web UI (the existing `tests/fixtures/http/<model>_*.html` captures plus a fresh crawl); if no IPv6 page exists on the firmware in the field, add to each `registry.py` entry a comment `# IPv6 management: UNSUPPORTED on fw <ver> — web UI has no IPv6 page (crawled <date>); NSDP has no IPv6 TLV` and make `_nsdp_support` / `_http_support` in `capabilities.py` return `UNSUPPORTED` with that reason for the four IPv6 ops.
- [ ] m7300 / xs748t: `UNSUPPORTED, "unreachable during every sweep; unmeasured"` until a unit answers; owner decision D7.
- [ ] `tests/test_capabilities.py`: the full model × backend × op matrix for the four IPv6 ops has an explicit expectation per cell — no cell is left to default.

---

## Owner decisions needed (checklist)

- [ ] **D1 — data model:** separate `Ipv6Config` (plan default) vs widening `MgmtIpConfig`. Also whether `Snapshot` grows an `ipv6` field (plan default: yes, `ipv6: Ipv6Config | None`).
- [ ] **D2 — op names and shape:** `set_ipv6_address` / `delete_ipv6_address` / `set_ipv6_gateway` (plan default) vs a single `set_mgmt_ipv6(address, prefix_len, gateway)`.
- [ ] **D3 — first-cut exemption:** may Part A merge with HTTP/GoAhead as the ONLY implemented backend for the IPv6 ops, with every other model/backend returning `UNSUPPORTED, "not yet implemented — issue #28"`? The working agreement needs this said explicitly.
- [ ] **D4 — persistence:** is a `save_config(force=True)` operator op wanted on the GS728TPP (and `write memory` on FASTPATH), separate from the never-persist test rule? And who applies the production `2404:…::10/64` + gateway: the one-off script already in flight, or the library after A7?
- [ ] **D5 — multicast rows:** keep `ff02::…` rows in `Ipv6Config.addresses` (plan default) or filter them out at the parser.
- [ ] **D6 — IPv4 live-verify risk:** approve strategy 2 (gateway-only from on-link host) on gs728tpp and m4300-16x-poe-s2, and strategy 3 (console-backed address change) on gsm7252ps-s1; or restrict to strategy 1.
- [ ] **D7 — unreachable models:** accept `UNSUPPORTED, "unmeasured"` for m7300 / xs748t, or power one up for the sweep.
- [ ] **D8 — Plus-class:** if the crawl finds no IPv6 page on gs110emx/gs305ep/gs105pe, accept the recorded exemption without further hardware work.
