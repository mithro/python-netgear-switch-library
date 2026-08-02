# GS728TPP: PoE and VLAN control over SNMP *and* HTTP — live findings

Target: `sw-netgear-gs728tpp.monarto.mithis.com` (10.2.5.10), firmware
**6.0.1.30**, sysObjectID `1.3.6.1.4.1.4526.100.4.27`.

Goal: complete PoE and VLAN control (read **and** write) on both the SNMP and
the HTTP backend, plus LLDP and port-status reads — every claim verified against
that switch.

## How the switch is reached

It is on the monarto network (10.2.5.0/24), which is **not routable** from the
development machine (the DNS name resolves to `2404:e80:a137:205::10`, which is
unreachable from here). Two independent paths, each driving one backend
**directly** — never through `SyncSwitch`, so a PASS cannot be another protocol
answering (principle 1):

| Backend | Path |
| --- | --- |
| SNMP | `net-snmp` binaries executed on the `ten64.monarto.mithis.com` jump host over ssh; stdout parsed by the library's own `parse_netsnmp_lines`, so `SnmpReader`/`SnmpWriter` see byte-identical rows to a local run. Community `public`, v2c. |
| HTTP | `ssh -L 127.0.0.1:18010:10.2.5.10:80`, so the real `HttpClient`/`HttpReader`/`HttpWriter` run unmodified. |

Harness: `tmp/gs728_live.py` (+ `gs728_baseline.py`, `gs728_diag.py`,
`gs728_diag2.py`, `gs728_compare.py`). The web password is read from
`tmp/.swpw` (mode 600, gitignored) and never printed.

## Read baseline — both backends, driven directly

All twelve reads answered on the first attempt:

```
SNMP  get_ports 28   get_lldp 4   get_poe 24   get_vlans 13   get_pvids 28   get_mgmt_ip OK
HTTP  get_ports 28   get_lldp 4   get_poe 24   get_vlans 13   get_pvids 28   get_mgmt_ip OK
```

After the two fixes below, a field-by-field diff of the two backends is **empty**
for ports, VLANs (ids, names, member/tagged/untagged sets) and PVIDs.

### LLDP is correct — the first apparent mismatch was mine, not the switch's

An early run showed SNMP 3 neighbours against HTTP 4, which looks exactly like a
parse bug. It is not: `lldpRemTable` is a *dynamic* table and the two reads were
minutes apart. Read back-to-back — SNMP, HTTP, SNMP — all three agree:

```
snmp #1 : [2, 24, 26, 28]
http    : [2, 24, 26, 28]
snmp #2 : [2, 24, 26, 28]
```

Neighbours: `reterm1` on port 2, and `ten64.monarto.mithis.com` eth7/eth8/eth9 on
ports 24/26/28. No code change was needed, and none was made.

## Defect 1 — SNMP reported a member port the switch does not have

`dot1qVlanStaticEgressPorts` is 126 bytes (1008 bits) on this switch, and **bit
1000 is set in 11 of its 13 VLANs**. `parse_vlans` decoded every set bit, so
`get_vlans()` reported `member port 1000` on a 28-port switch. The HTTP backend
never listed it.

Bit 1000 is a LAG, proved from the device rather than assumed:

* `ifName.1000` = `po 1` … `ifName.1007` = `po 8`
* `ifType` of all eight = **161** (`ieee8023adLag`)
* `dot1dBasePortIfIndex` is **identity-mapped** (`{1: 1, 2: 2, … 1007: 1007}`),
  so the Q-BRIDGE bridge-port bit position *is* the ifIndex.

`parse_port_status` and `parse_pvids` already filtered on `ifType`;
`parse_vlans` was simply the one that never did. It now takes the same
`if_types` argument.

**Coupled write hazard.** `SnmpWriter.set_vlan_membership` verifies by decoding
the bitmap it *sent* and comparing with what `get_vlans` reads back. Filtering
one side only would have made every membership write on this switch raise a
bogus `WriteVerificationError`, so the writer filters the expected sets through
the same `physical_ports()` helper. The write path itself was already safe — it
flips one bit in the device's own octets (`_raw_bitmap`), so the LAG bits ride
along untouched; `test_membership_write_preserves_the_lag_bits` now pins that,
because re-encoding from the (now LAG-free) decoded set would silently evict
`po 1` from the VLAN.

## Defect 2 — SNMP lost VLAN 1 entirely

The static and current VLAN tables disagree about how many VLANs exist:

```
dot1qVlanStaticName/Egress/Untagged/RowStatus : 12 rows — ids 2,3,4,5,6,7,10,20,31,41,90,99
dot1qVlanCurrentEgress/Untagged/Status        : 13 rows — the same 12 plus VLAN 1
dot1qVlanStatus.0.1  = 1 (other)      <- VLAN 1
dot1qVlanStatus.0.<other> = 2 (permanent)
```

VLAN 1 is the default VLAN and this firmware never gives it a
`dot1qVlanStaticTable` row, so a static-table-only reader loses it — and it is
not an empty VLAN: it is untagged on ports 24/25/27, the switch's own uplinks.
The web UI lists it, so the two backends disagreed.

`parse_vlans` now reads both tables and adds VLANs the static table omits. Such
a VLAN has no `dot1qVlanStaticName` row, so its name is `None` — which is
exactly what the HTTP backend reports for it.

The static bitmaps win where both tables carry the VLAN (static is the
*configured* membership). That ordering was **measured, not assumed**: static
and current were byte-for-byte identical for all 12 shared VLANs.

## What the mock now carries (principle 5)

`seed_gs728tpp` gained, all measured 2026-08-02:

* the eight LAG interfaces `po 1`..`po 8` at ifIndex 1000-1007, `if_type=161`
* their VLAN membership — all eight bits in VLAN 1, bit 1000 alone in every
  configured VLAN (VLAN 3's *only* member is the LAG)
* their `dot1qPvid` rows (the real walk returns 36 rows, not 28)
* `vlan_portlist_width=126` — the device's real width, seeded not derived
* `VlanSim.static_row=False` on VLAN 1, so the fake genuinely has **no** static
  row for it rather than an empty one

`VirtualSwitchState.oid_map()` now emits `dot1qVlanCurrentTable` (egress,
untagged, status) for every VLAN, and the GoAhead web face filters to physical
ports — the real wcd pages list 28 entries, never the LAGs.

## Honest per-backend difference: per-port PoE power

SNMP reports `power_mw=None` where HTTP reports live milliwatts (1900/1800 mW on
ports 1/4/21). This is the switch, not the library: a full walk of
`pethPsePortTable` returns exactly the RFC 3621 columns 3-14, none of which is a
consumption column, and this agent implements **zero** Netgear vendor OIDs (a
walk of `1.3.6.1.4.1.4526` answers noSuchObject). Everything else in `get_poe`
— admin state and detection status — matches HTTP port for port.

## Status

| Area | SNMP | HTTP |
| --- | --- | --- |
| get_ports / get_pvids / get_vlans / get_lldp | live-verified, cross-checked | live-verified, cross-checked |
| get_poe | live-verified (no per-port mW: device limit) | live-verified |
| PoE write (set/cycle/clear-fault) | to verify live | **not implemented** |
| VLAN create/delete/membership | to verify live | **not implemented** |
| set_pvid | to verify live | claimed supported, to verify live |

Test ports reserved for the write work: **port 17** (link-down, no description,
PoE `SEARCHING`, PVID 4) and throwaway VLAN id **4001**.
