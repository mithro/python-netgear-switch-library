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

## The write community — a timeout is not a dead agent

The first SNMP write attempt timed out on every SET while reads over the same
transport worked perfectly. That is exactly the failure mode principle 4 warns
about: an agent **silently drops** a request whose community lacks write access,
so an unauthorised community is indistinguishable from an unreachable host.

Rather than guess, the switch was asked. `wcd?{file=/System/SNMP/
CominityConf_master.xml}{SNMPv2CommunityList}{ViewList}` answers:

| community | accessMode | view |
| --- | --- | --- |
| `private` | 3 | DefaultSuper |
| `public` | 1 | Default |

`public` is read-only. Writes need `private`, and with it the SETs go through.
Both are restricted to management station 10.2.5.10/255.0.0.0 (i.e. 10/8), which
the jump host satisfies.

## The PoE MIB is very slow on this agent — and the library was over-fetching

`parse_poe` honours only columns 3 and 6 of `pethPsePortTable`, but `get_poe`
walked the whole table: 288 varbinds fetched to use 48. Measured on an idle
switch:

```
ifName (69 rows)                      1.5s
whole pethPsePortTable (288 rows)   102.0s
pethPsePortAdminEnable  (24 rows)    11.7s
pethPsePortDetectionStatus (24)      11.4s
```

The agent is fast for ordinary tables and answers the PoE MIB at ~0.35s per
varbind. Because `SnmpWriter` verifies by re-reading, `set_poe` cost over three
minutes and the first write probe could not complete a single operation in 25
minutes. Reading the two columns separately cuts it to ~23s.

Raising `max-repetitions` is not an alternative: `-Cr25` returned a **truncated**
50 rows in 44s, so this agent mishandles large GETBULKs on this table. Fetching
fewer varbinds is the only sound speed-up.

## The HTTP write protocol

The site map has exactly one POST target — `wcd` — repeated for all 100-odd
pages, so the **body** selects the operation, not the URL. Each page's own
JavaScript builds a `post` object which the framework serialises:

```js
// Switching/VLAN/VlanMembership_jq.htm
post.VLANMembershipList['set']    = [{VLAN:{VLANID, MembershipList:[
    {VLANMember:{interfaceName, interfaceType, membershipType, taggingMode}}]}}]
post.VLANMembershipList['delete'] = [{VLAN:{VLANID, MembershipList:[
    {VLANMember:{interfaceName, interfaceType}}]}}]

// Switching/Ports/portConfiguration_master_jq.htm
post.Standard802_3List = {set: [{Entry:{interfaceName, interfaceType,
    interfaceID, interfaceDescription, adminState, speedAdmin, duplexAdminMode}}]}
```

Combined with the library's existing `_build_gs728tpp_cert_xml` (whose envelope
came from the certbot hook that works against real GS728TPPs), the rule is:
the JS object key is the element name, the `set`/`delete` key becomes the
`action` attribute, and each list entry is one repeated child element.

Two asymmetries are the page's own and must be reproduced: removing a port from
a VLAN is a **delete** action carrying only the interface identity (not a `set`
with `taggingMode` 0, a mode the firmware does not have), and untouched fields
are omitted entirely rather than sent empty. `taggingMode` codes come from the
page's Group Operation select: 2 = Tag, 1 = Untag, 0 = Remove.
`interfaceType` is 1 for a physical port and 2 for a LAG.

Success is `<statusCode>0</statusCode>`, the same convention the cert upload
already checks.

## Honest per-backend difference: per-port PoE power

SNMP reports `power_mw=None` where HTTP reports live milliwatts (1900/1800 mW on
ports 1/4/21). This is the switch, not the library: a full walk of
`pethPsePortTable` returns exactly the RFC 3621 columns 3-14, none of which is a
consumption column, and this agent implements **zero** Netgear vendor OIDs (a
walk of `1.3.6.1.4.1.4526` answers noSuchObject). Everything else in `get_poe`
— admin state and detection status — matches HTTP port for port.

## SNMP cannot create a VLAN on this firmware — proven, not assumed

`create_vlan` over SNMP is refused. Before recording that as a device
limitation, every documented mechanism was tried; all five answer
`inconsistentValue` naming `.1.3.6.1.2.1.17.7.1.4.3.1.5.<vlan>`:

| attempt | result |
| --- | --- |
| `createAndGo(4)` alone | inconsistentValue |
| `createAndGo(4)` + `dot1qVlanStaticName` in ONE PDU (RFC 2579's requirement) | inconsistentValue |
| `createAndWait(5)` → name → `active(1)` | inconsistentValue at each step |
| `dot1qVlanStaticName` alone (implicit row creation) | inconsistentValue |
| `createAndGo(4)` + name + empty 126-byte egress PortList | inconsistentValue |

A sixth possibility — that the switch auto-creates a VLAN when a port's PVID is
set to an unknown id, as some firmware does — was tested and also eliminated:
`dot1qPvid.17 := 4002` for a **non-existent** VLAN 4002 is **accepted**, reads
back as 4002, and creates no VLAN.

> **Flagged, not changed.** That means this switch will happily leave a port
> with a PVID for a VLAN that does not exist, and the library does not stop it:
> `set_vlan_membership` raises "VLAN N does not exist" as a precondition, but
> `set_pvid` has no such check on any backend. Making them consistent is a
> behaviour change affecting every model, and one I could not live-verify on
> the other switches in this session — so it is recorded here for a decision
> rather than done quietly.

And it is neither a read-only table nor a rejected VLAN id. On the same switch,
in the same session:

* an **existing** row's membership was rewritten — VLAN 90 / port 17, tagged →
  excluded → tagged, verified and restored;
* `dot1qPvid` was written and read back;
* `destroy(6)` removed a VLAN;
* the **web UI created VLAN 4001** without complaint.

So row creation specifically is unimplemented in this agent.
`registry.snmp_can_create_vlan=False`, `SnmpWriter.create_vlan` refuses by name
before sending anything, and the capability table reuses the writer's own
reason. Creating a VLAN here is an HTTP operation — which is exactly why the
library keeps both backends.

## Two defects the hardware exposed in shared code

**`cycle_poe` reported failure on success.** Its recovery predicate demanded
`DELIVERING` whatever the port had been doing, so cycling port 17 — which has
nothing attached — polled the full 60s and raised `WriteVerificationError` on a
cycle that had worked. A port with no powered device can never reach
`DELIVERING`. Recovery is now relative to the port's prior state
(`models.poe_cycle_complete`, shared by both writers). `clear_poe_fault`
passing on the same port in the same run, driving the identical off/on
sequence, is what isolated it to the predicate rather than the write.

**A session that expires mid-run looked like a parser bug.** The switch answers
an expired session with HTTP **200** and a normal `<ResponseData>` envelope
whose ActionStatus carries `statusCode 4 / "Request Is not authenticated"`.
Reads now re-authenticate and re-issue once; writes never re-send, and say so.
A first attempt at detecting this keyed off the *absence* of `<ResponseData>`
— a guess, and wrong, since the unauthenticated reply has one. The signal was
settled by making a request with a stale cookie and reading the answer.

## Status — all live-verified on the switch

| operation | SNMP | HTTP |
| --- | --- | --- |
| get_ports / get_vlans / get_pvids | ✅ | ✅ (agree field-for-field) |
| get_lldp | ✅ | ✅ (agree back-to-back) |
| get_poe | ✅ (no per-port mW: device limit) | ✅ |
| set_poe | ✅ | ✅ |
| cycle_poe / clear_poe_fault | ✅ | ✅ (admin re-arm; no reset control exists) |
| set_port_enabled | ✅ | ✅ |
| set_vlan_membership (tagged/untagged/excluded) | ✅ | ✅ |
| set_pvid | ✅ | ✅ |
| delete_vlan | ✅ | ✅ |
| create_vlan | ❌ device refuses (proven above) | ✅ |

Throwaway resources used throughout: **port 17** (link-down, no description,
PoE idle) and VLAN **4001**. Every run recorded the prior state, restored it,
and proved the restore by re-reading on both backends. Nothing was ever saved
to startup configuration.

## Final end-to-end run — 35/35

`tmp/gs728_goal_verify.py` drives the PUBLIC facade (`SyncSwitch`) with the
backend named on every single call, so no result can be another protocol
answering:

```
PASS get_ports SNMP/HTTP · get_lldp SNMP/HTTP · get_poe SNMP/HTTP
PASS get_vlans SNMP/HTTP · get_pvids SNMP/HTTP
PASS get_ports agree · get_vlans agree · get_pvids agree   (field-for-field)
PASS set_poe off/on SNMP · cycle_poe SNMP · clear_poe_fault SNMP
PASS set_poe off/on HTTP · cycle_poe HTTP · clear_poe_fault HTTP
PASS set_port_enabled SNMP · set_port_enabled HTTP
PASS create_vlan refuses SNMP (by name, before sending)
PASS create_vlan HTTP  name='ngsw-tmp'
PASS membership tagged/untagged/excluded SNMP · set_pvid SNMP
PASS membership tagged/untagged/excluded HTTP · set_pvid HTTP
PASS delete_vlan SNMP · delete_vlan HTTP
PASS restore verified SNMP · restore verified HTTP
35/35 passed
```

Both backends read back the untouched prior configuration at the end:
`vlans=[1,2,3,4,5,6,7,10,20,31,41,90,99]`, port 17 PVID 4, PoE and port admin
enabled.
