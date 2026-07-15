# Python Netgear Switch Interface Library — Design Spec

**Date:** 2026-07-15
**Status:** Approved (design), pending spec review
**Project:** Python Netgear Switch Interface Library
**Distribution:** `python-netgear-switch-library` · **Import:** `netgear_switch` · **CLI:** `ngsw`
**Repo:** `github.com/mithro/netgear-stupid-control` (git repo directory name differs from the project name)

## 1. Purpose

A Python library and set of command-line tools to query and control all of the
Netgear switches in the fleet, across the three management protocols those
switches speak (SNMP, NSDP, HTTP web-UI). This repo is the **canonical** Netgear
switch-control library: it consolidates switch-communication code that currently
lives duplicated and drifting across `gdoc2netcfg` (async pysnmp + a read-only
NSDP package) and `sensors2mqtt` (sync ezsnmp SNMP collector + PoE control). Once
this library is stable, those projects migrate to depend on it.

### Capabilities (per the request)

- Query port status: link, speed, PoE status, admin state.
- Control port status: enable/disable link, PoE on/off (and cycle).
- Query and control VLAN configuration for all ports (membership + PVID).
- LLDP neighbor information.
- MAC address per port (SNMP/managed switches only — see §3).
- Sensor information: temperature, power, fan speed.

## 2. The fleet

| Switch | Class | SNMP | NSDP | HTTP | PoE ports | Notes |
|--------|-------|:----:|:----:|:----:|:---------:|-------|
| `m4300-24x` (XSM4324CS) | Fully-managed | ✓ | — | cert-only | 0 | vendor OID base `4526.10.*` |
| `m4300-16x` (XSM4316*) | Fully-managed | ✓ | — | cert-only | 16 | seen at `10.1.5.19` on x1c-work; PoE+ variant |
| `gsm7252ps` (S1/S2) | Fully-managed | ✓ | — | — | 48 | vendor OID base `4526.10.*` |
| `gsm7228ps` / `s3300` | Smart-Managed-Pro | ✓ | cert-only | ✓ | 48 | vendor OID base `4526.11.*` |
| `gs110emx` (gs110emx1) | Plus | — | ✓ | ✓ | 0 | no SNMP; NSDP + web only; Marvell-based |
| `gs305ep` (poe-micro1) | Plus | — | ✓ | ✓ | 4/5 | no SNMP; NSDP + web only |

**Fleet is model-driven, not hard-coded to these six.** New models are added by
adding a `SwitchModel` entry to the registry (§5.2).

### Hard constraints carried from research

- **Plus switches expose no MAC/FDB table by any remote protocol.** MAC-per-port
  is SNMP-only, i.e. managed switches only. `get_macs()` on a Plus switch raises
  `UnsupportedCapability`, and the CLI says so rather than printing an empty table.
- **M4300 VLAN/PVID writes go over SNMP in v1.** A `sensors2mqtt` handoff doc
  reported `commitFailed` on Q-BRIDGE SNMP SET for the M4300 (FASTPATH 12.0.13.8)
  and recommended SSH CLI. The switch owner reports SNMP VLAN writes work in
  practice, so **SNMP is the v1 write path for all managed switches including the
  M4300.** An SSH/FASTPATH backend is a v2 alternative (§9), not a v1 dependency.
  The verify-after-write step (§6) will surface a genuine `commitFailed` clearly
  if a specific unit ever does reject the SET.
- **SNMP VLAN/PVID SET uses Gauge32 (`u` type), not integer (`i`).**
- **PoE control uses standard RFC 3621 `POWER-ETHERNET-MIB` OIDs** (admin =
  `pethPsePortAdminEnable` column 3, detect = `pethPsePortDetectionStatus`
  column 6), which are model-agnostic across managed switches.

## 3. Architecture

Two design shapes mirror each other:

- **Library:** three *transports* over one device *model* (`models.py`).
- **Virtual switch (§7):** three protocol *faces* over one device *state*.

The key structural decision — what makes a **dual sync/async** API tractable
without writing everything twice — is that all protocol *knowledge* lives in pure,
I/O-free code, and only the actual byte I/O is duplicated per sync/async transport.

```
netgear_switch/
  models.py        Frozen dataclasses (public return types): SwitchData, PortStatus,
                   VLANInfo, PoEStatus, Sensor, LLDPNeighbor, MacEntry. Shared by
                   both APIs; both APIs return identical instances.
  registry.py      SwitchModel table: port counts, PoE ports, backends supported,
                   vendor OID subtree, per-model quirks.
  config.py        TOML inventory + credential resolution (CLI/env/config/prompt).
  errors.py        Exception hierarchy.

  protocols/       PURE LOGIC — no sockets, no I/O; 100% unit-testable on fixtures.
    snmp/  oids.py  (OID constants + per-model tables)
           parse.py (SNMP rows -> models.py objects)
           encode.py (SET value construction: Gauge32 typing, VLAN bitmap RMW)
    nsdp/  protocol.py (TLV codec; lifted from gdoc2netcfg src/nsdp)
           parse.py    (TLV payload -> models.py objects)
           auth.py     (NEW: v1 XOR + v2 salt/hash for write requests)
    http/  endpoints.py (per-model CGI/form definitions)
           parse.py     (HTML/XML -> models.py objects)
           auth.py      (MD5-merge login)

  transport/       THIN I/O only.
    sync/  snmp_ezsnmp.py   nsdp_socket.py    http_httpx.py
    aio/   snmp_pysnmp.py   nsdp_asyncio.py   http_httpx.py   (httpx does both modes)

  sync_api.py      SyncSwitch  facade  ─┐ thin; delegate to protocols/ + transport/;
  aio_api.py       AsyncSwitch facade ─┘ both return the SAME models.py dataclasses.

  virtual/         Shipped virtual switch (§7), under the [testing] extra.

  cli/main.py      CLI (built on the sync API).
```

### 3.1 The `Switch` facade

`SyncSwitch` and `AsyncSwitch` present identical method names:

```
get_ports()            -> list[PortStatus]
set_port_enabled(port, enabled)
get_poe()              -> list[PoEStatus]
set_poe(port, on)
cycle_poe(port)
get_vlans()            -> list[VLANInfo]
get_pvid(port)         -> int
set_pvid(port, vlan)
set_vlan_membership(vlan, port, mode)   # mode: untagged | tagged | excluded
get_lldp()             -> list[LLDPNeighbor]
get_macs()             -> list[MacEntry]      # managed only
get_sensors()          -> list[Sensor]
```

A facade is constructed from an inventory entry (or explicit credentials), looks
up its `SwitchModel`, and dispatches each operation to whichever backend that
model supports. Backend selection is model-driven: a Plus switch routes port/PoE/
VLAN through NSDP or HTTP; a managed switch routes through SNMP.

## 4. Dual API + cross-check

Both APIs are first-class and provide identical functionality:

- **Sync API** — transport via **ezsnmp** (net-snmp C binding; apt-installable and
  uniform across the Debian fleet, per the `sensors2mqtt` native-snmp-library
  decision), NSDP via stdlib sockets, HTTP via httpx (sync mode). Parallelism via
  threads. This is what the CLI uses.
- **Async API** — transport via **pysnmp v7** (asyncio), NSDP via asyncio
  datagram endpoints, HTTP via httpx (async mode). Matches `gdoc2netcfg`.

**Cross-check (explicit requirement):** because both APIs share `protocols/` and
emit identical `models.py` dataclasses, a test harness runs every operation
through **both** APIs against the same target and asserts equal results, at the
dataclass level so ezsnmp-vs-pysnmp representation differences never leak in. Read
*and* write paths are cross-checked; write paths assert the resulting device-state
mutation is identical. The primary target is the virtual switch (§7).

## 5. Config & credentials

### 5.1 Resolution order

Credentials resolve **CLI flag → environment variable → config value → interactive
prompt**. A config value may itself be a literal, `${ENV_VAR}`, or `!command …`
(stdout is the secret, e.g. `pass`/`gopass`). When a literal secret is stored in
the config file, file permissions are enforced (`ensure_secure_file`, 0600-style,
lifted from `sensors2mqtt`). The library API also accepts credentials as plain
objects, so `gdoc2netcfg`/`sensors2mqtt` can supply their own without this file.

### 5.2 Inventory TOML

```toml
[switches.sw-netgear-m4300-24x]
model = "m4300-24x"
host  = "10.1.5.19"
snmp.community        = "public"
snmp.write_community  = "!pass show netgear/m4300/snmp-write"

[switches.sw-netgear-gsm7252ps-s1]
model = "gsm7252ps"
host  = "10.1.5.20"
snmp.community        = "public"
snmp.write_community  = "${GSM7252PS_S1_WRITE}"

[switches.sw-netgear-gs110emx1]
model = "gs110emx"
host  = "10.1.5.25"
http.password  = "${GS110EMX1_PW}"
nsdp.interface = "eth0"
protected_ports = [9, 10]        # refuse disruptive writes without --force
```

## 6. Write safety

- **VLAN membership writes:** read-modify-write on the Q-BRIDGE
  `dot1qVlanStaticEgressPorts` / `dot1qVlanStaticUntaggedPorts` bitmaps so only the
  target port's bit changes (trunks and other access ports preserved) — logic
  lifted from x1c-work `switch_vlan.py`. `dot1qPvid` SET as Gauge32 (`u`).
  **Verify-after-write:** re-read and confirm; a `commitFailed` or mismatch raises
  `WriteVerificationError` with the before/after state.
- **PoE cycle:** reuse the proven state machine from `sensors2mqtt`
  `snmp_control.py` — set admin off, poll until detect=unused + link down (30 s
  timeout), set admin on, poll until detect=delivering (60 s timeout).
- **CLI disruptive ops** (`poe off`, `port down`, `vlan set`, `pvid set`) require
  confirmation, support `--dry-run` (print the exact SET / NSDP packet / HTTP form
  without sending) and `--yes` to skip the prompt.
- **`protected_ports`** (per-switch config) refuse disruptive writes without
  `--force`; intended for uplinks and management ports.

## 7. Virtual switch (integration testing)

A shipped subpackage, `netgear_switch.virtual`, available under a
`[testing]` optional-dependency extra so `gdoc2netcfg` and `sensors2mqtt` can also
test their own switch code against it. It is a **stateful, model-parameterized**
device simulator: one authoritative mutable state with three protocol faces bound
to it, so a write on one protocol is immediately visible on the others.

```
netgear_switch/virtual/
  state.py       VirtualSwitchState — one source of truth: ports (link/speed/admin),
                 PoE (admin/detect/mW), VLANs + egress/untagged bitmaps, PVIDs,
                 sensors (fan/temp/PSU), MAC/FDB table, LLDP neighbors,
                 identity/firmware.
  behaviour.py   coherence rules: PoE admin=off -> detect=unused -> link down after
                 a delay; VLAN bitmap invariants; PVID SET rejects unknown VLAN;
                 per-model quirks (M4300 colon-STRING bridge MAC, "Not Supported"
                 sensor slots, Plus switch has NO MAC table, GSM7252PS four-PSU /
                 single-fan indexing).
  seed.py        build state from the model registry + hand-authored fixtures.
  faces/
    snmp.py      SNMP agent: GET/GETNEXT/BULK/SET with correct lexicographic walk,
                 Gauge32 typing, vendor 4526.{10,11}.* subtree — backed by state.
    nsdp.py      NSDP UDP responder: read + write TLVs (incl. auth) — backed by state.
    http.py      web-UI server: MD5-merge login + CGI endpoints — backed by state.
  server.py      VirtualSwitch(model=..., ...): binds only the faces the model
                 supports (Plus -> NSDP+HTTP, managed -> SNMP) to ephemeral ports.
```

- **SNMP face** is built on **pysnmp's agent / command-responder engine** with a
  custom MIB controller reading/writing `VirtualSwitchState` — correct
  GETNEXT/BULK/SET semantics without hand-rolling BER, and it exercises a
  *different* SNMP stack than the sync ezsnmp client under test, so the cross-check
  is not a library testing its own mirror.
- **Model-parameterized:** `VirtualSwitch(model="gs110emx")` presents exactly that
  model's backend availability, port counts, vendor OIDs, and quirks.
- **Integration test example:** `switch.set_poe(3, False)` then assert the SNMP
  face reports admin=disabled **and** the port transitions link-down per the
  behaviour rule.

### 7.1 Fixtures & capture

- **Committed fixtures are hand-authored** — clean, minimal, documented seed data
  per model — not raw protocol dumps. Existing `sensors2mqtt` `snmpwalk_*` captures
  are a starting reference.
- A **capture utility** (CLI subcommand, opt-in, live-switch access, never in CI)
  records real-switch SNMP/NSDP/HTTP request/response exchanges and a state
  snapshot for **reference**, from which fixtures are then hand-authored. This
  grounds fidelity in real device behaviour and helps refresh fixtures when
  firmware changes, without committing noisy raw dumps.

## 8. Packaging

- `uv` + `hatchling`; **Apache 2.0**; Python ≥ 3.11.
- Distribution name `python-netgear-switch-library`; import name
  `netgear_switch`. CLI command **`ngsw`** (subcommands: `ngsw ports`,
  `ngsw poe`, `ngsw vlan`, `ngsw lldp`, `ngsw macs`, `ngsw sensors`, `ngsw
  capture`, …). Any future companion tools share the `ngsw` prefix.
- Optional-dependency extras so consumers install only what they need:
  - `[sync]` → ezsnmp
  - `[async]` → pysnmp
  - `[http]` → httpx (shared sync/async)
  - `[testing]` → virtual switch deps (pysnmp agent engine, an HTTP test server)
- Lifted code (attribution preserved where relevant): `src/nsdp/` package from
  `gdoc2netcfg` (NSDP read); SNMP OID tables + parsers from `gdoc2netcfg`
  `bridge.py`/`snmp.py` and `sensors2mqtt` `collector/snmp.py`; the `SnmpClient`
  ezsnmp seam; the PoE control state machine; VLAN bitmap RMW from x1c-work
  `switch_vlan.py`; the `SwitchData` model shape; HTTP login/endpoint patterns from
  `certbot-hook-netgear-switches` and rcfiles `netgear-smp-vlan`.
- Written new: NSDP **write** path (v1 XOR / v2 salt-hash auth + WRITE_REQUEST —
  scaffolded but never implemented anywhere); the async pysnmp backend; the
  cross-check harness; the virtual switch; the native httpx HTTP backend; the CLI.

## 9. Scope: v1 vs v2

**v1**
- Backends: SNMP, NSDP, HTTP.
- Full read **and** write: port enable/disable, PoE on/off/cycle, VLAN membership +
  PVID; LLDP; MAC (SNMP); sensors.
- Dual sync + async APIs with cross-check harness.
- Virtual switch (three faces, stateful, model-parameterized) + hand-authored
  fixtures + capture utility.
- CLI with `--dry-run` / `--yes` / `--force` safety rails and `protected_ports`.
- TOML inventory + flexible credential resolution.

**v2 (deferred)**
- SSH / FASTPATH CLI backend (alternative VLAN path; richer M4300 control).
- NSDP v2-auth hardening.
- Trunk/tagged VLAN bitmap editing beyond access-port membership.
- Additional Plus/managed models.

## 10. Open items for spec review

1. **M4300 SNMP VLAN write** — trusting owner experience over the handoff doc.
2. **v1 write scope** — full read+write with the §6 rails; confirm not too large
   for the first cut.
