# gsm7252ps HTTP (XE_FASTPATH dialect) Implementation Plan

> **For agentic workers:** implement task-by-task, TDD, small commits.

**Goal:** Add a full HTTP read backend to gsm7252ps whose output agrees with its
SNMP backend, grounded in real captures. Design + live-verified XE format facts
are in `docs/superpowers/specs/2026-07-23-gsm7252ps-http-xe-dialect-design.md`
— READ THAT FIRST; it has the login scheme, page URLs, and the XE cell format.

**Template:** The M4300 dialect is the closest existing analogue. Mirror it:
`_M4300` spec in `protocols/http/endpoints.py`, `parse_m4300_*` +
`parse_cheetah_rows` in `protocols/http/parse.py`, `_is_m4300_dialect` wiring in
`http_read.py`, `web_m4300.py` mock face. The XE format differs (see spec §"XE
cell format") — cells are `NAME=<port>.v_<row>_<col> VALUE="…"` with NO
`<!-- field -->` comment, addressed by COLUMN INDEX.

## Global Constraints
- Honesty: `scheme_verified`/`reads_verified` only where grounded. Ops whose
  page is JS-populated (sensors, mgmt_ip on gsm7252ps) MUST raise
  `UnsupportedCapabilityError`, never fabricate. SNMP already covers those.
- Every column map hardcoded in a parser MUST be justified by a committed
  fixture; document the column→field mapping in a comment beside it.
- `uv run` for all python. Small commits per task.

## Grounding assets
Live captures are in `tmp/live-captures/gsm7252ps_*.html` (gitignored working
copies, session tokens present). Task 1 copies + scrubs them into fixtures.

---

### Task 1: Fixtures
- Copy these `tmp/live-captures/gsm7252ps_*` pages to
  `tests/fixtures/http/gsm7252ps_<name>.html`, SCRUBBING any `SID=`/session
  token to `SID=SCRUBBED`: portsConfiguration, portStatistics,
  portPvidConfiguration, vlanStatus, basicAddressTable,
  poeInterfaceConfiguration, lldpRemoteInventory, and the login page.
- Also copy `base_system_management_sysInfo.html` as
  `gsm7252ps_sysInfo.html` (evidence that sensors/mgmt-IP are JS-populated).
- Commit.

### Task 2: `parse_xe_rows` + get_ports parser (TDD)
- In `parse.py`: `parse_xe_rows(html) -> dict[int, dict[str,str]]` grouping
  `NAME=<u>.<s>.<p>.v_<row>_<col> VALUE="…"` cells by port number (the instance
  prefix `1.0.52` → port 52), value keyed by the `v_<row>_<col>` coord. Add
  `_XE_CELL_RE`. HTML-unescape values (interface names arrive escaped).
- `parse_xe_port_status(html) -> list[PortStatus]` using the column map decoded
  from `gsm7252ps_portsConfiguration.html` (spec shows v_1_2_8=autoneg,
  _9=speed, _10=link; CONFIRM the port-name/admin columns against the fixture).
- Test: `tests/protocols/http/test_parse.py` — assert exact port count (52) and
  a few transcribed rows (port 52 link/speed) from the fixture.
- Commit.

### Task 3: remaining XE parsers (TDD, one commit each)
For each, decode the column map from the fixture, implement, test vs fixture:
- `parse_xe_stats` ← portStatistics.html (confirm counter columns; if the page
  reports frames not octets, mirror parse_m4300_stats' honest None-bytes).
- `parse_xe_pvids` ← portPvidConfiguration.html → list[(port, pvid)].
- `parse_xe_vlans` ← vlanStatus.html → list[VLANInfo] (member/tagged/untagged).
- `parse_xe_macs` ← basicAddressTable.html → list[MacEntry] (skip non-physical;
  raise on truncated/paginated table like parse_m4300_macs).
- `parse_xe_poe` ← poeInterfaceConfiguration.html → list[PoEStatus].
- `parse_xe_lldp` ← lldpRemoteInventory.html → list[LLDPNeighbor] (if the
  fixture has no neighbours, return [] and note it; do not invent).
- `parse_xe_labelled_values` ← sysInfo.html: generic label-cell → value-cell
  extractor for the format-(B) page.
- `parse_xe_sensors` ← sysInfo.html → list[Sensor]: Temperature Status table,
  FAN Status table (Fan1..Fan8), and RPS / Power Module state.
- `parse_xe_mgmt_ip` ← sysInfo.html → MgmtIpConfig: `IPv4 Network Interface`
  is "addr/netmask" (10.1.5.22/255.255.255.0); base_mac from
  `System MAC Address` (E0:91:F5:0C:D6:DB on the fixture).
  NOTE: an earlier draft wrongly called these two ops HTTP-infeasible. They are
  NOT — see the design doc's CORRECTION section. Do not skip them.

### Task 4: endpoint spec + dialect
- `endpoints.py`: add `HtmlDialect.XE_FASTPATH`. Add `_GSM7252PS` HttpModelSpec:
  scheme=CHEETAH_FORM, login_path=`/base/cheetah_login.html`,
  username_field=`uname`, username=`admin`, password_field=`pwd`,
  cookie_name=`SID`, read paths at `/` prefix (dashboard_path=
  `/portsConfiguration.html`, stats_path=`/portStatistics.html`,
  pvid_path=`/portPvidConfiguration.html`, vlan_config_path=`/vlanStatus.html`,
  mac_table_path=`/basicAddressTable.html`, poe_status_path=
  `/poeInterfaceConfiguration.html`,
  sysinfo_path=`/base/system/management/sysInfo.html`), html_dialect=
  XE_FASTPATH, scheme_verified=True, reads_verified=False (flipped after live
  cross-verify). Register in `_SPECS`.
- Test `test_endpoints.py`: gsm7252ps has a spec; test_every_http_model_has_a_spec passes.

### Task 5: registry HTTP backend
- `registry.py`: gsm7252ps backends `{Backend.SNMP}` → `{Backend.SNMP, Backend.HTTP}`.
- Update the seed docstring/comment note. Test `test_registry.py`.

### Task 6: http_read dispatch
- `http_read.py`: add `_is_xe_fastpath_dialect(spec)`. Wire get_ports/stats/
  pvids/vlans/macs/poe/lldp to the XE parsers (parallel to the m4300 branches).
  get_sensors/get_mgmt_ip: wire to parse_xe_sensors / parse_xe_mgmt_ip via
  sysinfo_path. NO UnsupportedCapabilityError carve-out for this model.
  Mirror both Sync and Async readers.
- Tests `test_http_read.py` using the fixtures via a mock transport.

### Task 7: mock face + seed upgrade
- New `virtual/web_gsm7252ps.py`: render the XE (A) cell format from
  `VirtualSwitchState` (instance-prefixed v_ cells) for ports/stats/pvids/
  vlans/macs/poe pages.
- `faces/http.py`: CHEETAH_FORM login (uname+pwd → SID) + XE render dispatch
  for the gsm7252ps model.
- `seed.py`: upgrade `seed_gsm7252ps` from ILLUSTRATIVE → transcribed from the
  real 52-port capture (real link/speed/PVID/VLAN values from the fixtures).
- Test `test_virtual_http_face.py`.

### Task 8: cross-backend equivalence
- `test_cross_backend_equivalence.py`: parametrize gsm7252ps SNMP↔HTTP for
  ports/stats/pvids/vlans/macs/poe/lldp, driving both faces of one
  VirtualSwitch, asserting agreement.
- Full suite green: `uv run --extra http --extra async --extra mcp pytest`.

### Task 9 (CONTROLLER-ONLY, live): HTTP↔SNMP cross-verify
- The controller runs the real HTTP reads vs SNMP against 10.1.5.22, fixes any
  live discrepancy, then flips `_GSM7252PS.reads_verified=True`. Not a subagent
  task (needs the switch + credentials).
