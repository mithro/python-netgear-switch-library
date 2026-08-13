# SNMP vendor-OID sweep, 2026-08-03

Task #71. Every reachable switch's Netgear vendor subtree walked in full
(read-only, community `public`) and diffed against every vendor OID the
library declares. Raw walks are NOT committed (2-6 MB each); reproduce
with `snmpwalk -v2c -c public -On <host> <vendor root>`.

The first run of this sweep reported **100% coverage**, which is how its
own bug announced itself: the comparison set was built from `dir(vo)` and
so included `vo.base`, the vendor ROOT. Every walked OID starts with the
root, so everything matched. A coverage check that cannot fail is not a
coverage check -- the library declares 28 leaves against 41k+ rows, so a
perfect score was arithmetically impossible.

Library declares **28 vendor leaf OIDs** in total.

## Coverage

| model | host | rows walked | depth-2 groups | groups the library reads |
|---|---|---|---|---|
| gsm7252ps | 10.1.5.22 | 35389 | 75 | 3 (14.1, 15.1, 43.1) |
| gsm7228ps | 10.1.5.11 | 37006 | 54 | 3 (14.1, 15.1, 43.1) |
| m4300-24x | 10.1.5.13 | 71313 | 98 | 2 (14.1, 43.1) |

The library reads a deliberately narrow slice: it implements the
operations it offers, not the MIB. The list below is therefore NOT a
list of defects -- it is the map for deciding what is worth adding.

## Unused groups that name a feature

Only groups carrying human-readable STRING values are listed: an integer
column with no MIB file is not actionable, whereas a string usually names
the feature. Groups common to all three switches are marked `ALL`.

### gsm7252ps

- `1.1` `ALL` — 1208 rows; "Spanning Tree Topology Change Received: MSTID: 0 1/; "Spanning Tree Topology Change: 0, Unit: 1"; "Link Down: 1/0/9"
- `1.2` `ALL` — 25245 rows; "defaultList"; "image2"; "Password Successfully Configured for User 'admin'.
- `3.4` `ALL` — 242 rows; "SIEMENS"; "CISCO1"; "CISCO2"
- `13.2` `ALL` — 48 rows; "10.0.0.53"; "GSM7252PS 48-Port GE L2+ Managed Stackable PoE Swit; "GSM7328Sv2"
- `13.4` `ALL` — 33 rows; "GSM7328Sv2"; "GSM7352Sv2"; "GSM7228PS"
- `13.5` `ALL` — 178 rows; "SIM"; "NIM"; "TRAPMGR"
- `13.7` `ALL` — 36 rows; "0/49"; "0/50"; "0/51"
- `13.9` — 4 rows; "M5300"; "GSM73XXS/M5300"
- `14.3` `ALL` — 201 rows; "<14> AUG 03 04:47:37 10.1.5.22-1 CLI_WEB[127006912]; "<14> AUG 03 04:47:37 10.1.5.22-1 CLI_WEB[127006912]; "<14> AUG 03 04:42:27 10.1.5.22-1 CLI_WEB[127006912]
- `17.1` `ALL` — 36 rows; "10.1.5.1"; "NTP Bits: 0x13a06573"; "ten64.welland.mithis.com"
- `24.1` — 22 rows; "RTR_DISC"; "OSPF"; "RIP"
- `38.1` — 23 rows; "Default"; "Default-RADIUS-Server"
- `38.5` — 33 rows; "004300610070007400690076006500200050006F00720074006; "cp_bkg.jpg"; "main_logo.gif"
- `39.1` — 133 rows; "0.0.0.0"; "Linux"; "Router "
- `42.1` `ALL` — 4 rows; "05:05:46"; " Aug 3 2026 "
- `42.3` `ALL` — 19 rows; "00:00:00"

### gsm7228ps

- `1.1` `ALL` — 1066 rows; "PoE: 1/g42     power up"; "PoE: 1/g46     power down"; "PoE: 1/g42     power down"
- `1.2` `ALL` — 26859 rows; "defaultList"; "image1"; "0.0.0.0"
- `3.4` `ALL` — 245 rows; "SIEMENS"; "CISCO1"; "CISCO2"
- `11.3` — 33 rows; "defaultList"; "networkList"; "enableList"
- `11.4` — 14 rows; "dfltCmdAuthList"; "dfltExecAuthList"
- `11.5` — 9 rows; "dfltCmdList"; "dfltExecList"
- `13.2` `ALL` — 37 rows; "6.6.4.26"; "S3300-52X-PoE+ ProSAFE 48-Port Gigabit Stackable Sm; "S3300-28X"
- `13.4` `ALL` — 18 rows; "S3300-28X"; "S3300-28X-PoE+"; "S3300-52X"
- `13.5` `ALL` — 84 rows; "SIM"; "NIM"; "TRAPMGR"
- `13.7` `ALL` — 36 rows; "0/49"; "0/50"; "0/51"
- `14.3` `ALL` — 201 rows; "<13> Aug  3 05:06:56 sw-netgear-s3300-1-1 TRAPMGR[P; "<13> Aug  3 05:06:55 sw-netgear-s3300-1-1 TRAPMGR[P; "<13> Aug  3 05:06:52 sw-netgear-s3300-1-1 TRAPMGR[P
- `17.1` `ALL` — 37 rows; "10.1.1.1"; "NTP Bits: 0xf3c07af4"; "10.1.5.1"
- `24.1` — 10 rows; "MRP"; "MMRP"; "MVRP"
- `37.1` `ALL` — 10 rows; "net.welland.mithis.com"
- `42.1` `ALL` — 4 rows; "05:07:03"; " Aug 3 2026 "
- `42.3` `ALL` — 19 rows; "00:00:00"
- `55.1` — 642 rows; "No Energy Detected"; "Admin Down"; "03:22:27:26"

### m4300-24x

- `1.1` `ALL` — 3049 rows; "Session 0 of type 3 started for user admin connecte; "Session 0 of type 3 ended for user admin connected ; "Spanning Tree Topology Change: 0, Unit: 1"
- `1.2` `ALL` — 41103 rows; "defaultList"; "00:03:00:06:8c:3b:ad:6b:bb:e0"; "/var/lib/switchcert/staging/"
- `3.4` `ALL` — 133 rows; "SIEMENS"; "CISCO1"; "CISCO2"
- `11.3` — 33 rows; "defaultList"; "networkList"; "enableList"
- `11.4` — 14 rows; "dfltCmdAuthList"; "dfltExecAuthList"
- `11.5` — 9 rows; "dfltCmdList"; "dfltExecList"
- `13.2` `ALL` — 51 rows; "12.0.13.8"; "M4300-24X ProSAFE 20-port 10GBASE-T and 4-port 10G ; "M4300-28G"
- `13.4` `ALL` — 54 rows; "M4300-28G"; "M4300-28G-PoE+"; "M4300-52G"
- `13.5` `ALL` — 236 rows; "SIM"; "NIM"; "TRAPMGR"
- `13.7` `ALL` — 216 rows; "0/1"; "0/2"; "0/3"
- `14.3` `ALL` — 201 rows; "<13> Aug  3 13:14:46 sw-netgear-m4300-24x-1 TRAPMGR; "<13> Aug  3 13:14:46 sw-netgear-m4300-24x-1 TRAPMGR; "<13> Aug  3 13:13:57 sw-netgear-m4300-24x-1 TRAPMGR
- `17.1` `ALL` — 46 rows; "10.1.5.1"; "NTP Bits: 0x992b1eca"; "time-a.netgear.com"
- `30.1` — 290 rows; "00:01:00:01:31:fd:7f:37:00:0a:fa:24:28:25"
- `37.1` `ALL` — 11 rows; "net.welland.mithis.com"
- `38.1` — 23 rows; "Default"; "Default-RADIUS-Server"
- `39.1` — 75 rows; "Router "; "sw-netgear-m4300-24x"; "10.1.5.20"
- `42.1` `ALL` — 5 rows; "14:38:40"; " Aug 3 2026 "; "ACST"
- `42.2` `ALL` — 3 rows; "ACST"
- `42.3` `ALL` — 19 rows; "00:00:00"
- `55.1` — 147 rows; "Admin Down"; "Energy-Detect EEE LPI-History LLDP-Cap-Exchg Pwr-Us
- `100.1` — 9 rows; "ox5dd0abc5"


## What is worth adding, and what is not

Read off the strings above, not from a MIB. Each candidate is named by what
its own values say, and the marker is whether the library already offers a
neighbouring operation.

**Strong candidates — the library already serves the adjacent config:**

- `14.3` (`ALL`, 201 rows on every switch) — the BUFFERED LOG ITSELF, e.g.
  `<14> AUG 03 04:47:37 10.1.5.22-1 CLI_WEB[127006912]`. `get_syslog` already
  reports where logs are SENT; this is where they are KEPT. The same 201-row
  count on all three suggests a fixed-size ring, and the web UI's
  `bufferedLogs.html` / `persistentLogs.html` (seen in the nav sweep for #73)
  are the HTTP face of the same data.
- `17.1` (`ALL`) — SNTP: server address (`10.1.5.1`, `time-a.netgear.com`),
  plus a literal `NTP Bits: 0x...`. Time config sits naturally beside
  `get_hostname`/`get_mgmt_ip` in the "switch setup" surface.
- `13.2` / `13.4` / `13.7` (`ALL`) — stack unit inventory: firmware version
  (`12.0.13.8`, `6.6.4.26`), full product names, and the member-port list.
  `get_system_info` reports only sysDescr today; this is the structured form,
  and `13.2` is where a per-unit firmware version would come from.

**Plausible, but only on request:**

- `38.1` (RADIUS server names), `11.3`/`11.4`/`11.5` (AAA authentication and
  authorization lists — the same `networkList`/`enableList` names the
  ssh/telnet pages already show as their auth lists).
- `55.1` — EEE/green-ethernet per port (`No Energy Detected`, `Admin Down`,
  `Energy-Detect EEE LPI-History`). NOT uniform across the fleet, and that was
  CHECKED rather than inferred from the string list above: counting raw rows
  under group 55 gives gsm7228ps 642, m4300-24x 147, **gsm7252ps 0** — the
  group is genuinely absent there, not merely free of readable strings. So
  this cannot be built fleet-wide from one switch, which is principle 3 in its
  usual form.

**Deliberately NOT candidates:**

- `1.1` / `1.2` — the trap/event log and a very large mixed config dump
  (25k-41k rows). Interesting to read once, not an operation.
- `3.4` (OUI vendor names: `SIEMENS`, `CISCO1`), `24.1` (routing/MRP protocol
  names), `42.x` (clock display strings) — decoration for other tables, not
  data a caller would ask this library for.

None of the above is a defect. The library implements the operations it
offers; this file exists so the next feature is chosen from what the devices
actually publish rather than from a guess.
