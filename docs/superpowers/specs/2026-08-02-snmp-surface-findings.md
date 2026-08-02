# Measured SNMP surface — hostname, logging, users, ports

Ground truth for expanding the library's functional coverage. Everything here
was **measured**, not inferred: each OID below was read from a live switch, and
where a CLI equivalent exists the two were compared.

Captured 2026-08-02 by `snmpbulkwalk -v2c -c public -On <host> 1.3.6.1`.
All five reachable switches answer on community `public`.

| Host | Model | OIDs walked |
|---|---|---|
| 10.1.5.11 | `gsm7228ps` (S3300-52X) | 103071 |
| 10.1.5.13 | `m4300-24x` | 190448 |
| 10.1.5.20 | `m4300-16x` | (walk in progress) |
| 10.1.5.22 | `gsm7252ps` | (walk in progress) |
| 10.2.5.10 | `gs728tpp` | (walk in progress) |

## How the vendor OIDs were located

Not by guessing at a MIB — no Netgear MIB file is available here, and
`snmptranslate` cannot name even the standard subtrees because only the
NET-SNMP MIBs are installed.

Instead: read the switch's configuration over its CLI first, then **search the
walk for those exact values**. The syslog server `10.1.5.1`, the local port
`514`, the severity `info` and the username `admin` are all distinctive enough
to pin the column they live in. This is faster than the walk/change/walk diff
and just as grounded, because the CLI output and the OID value are the same
fact observed twice.

It also caught a mislabelling that a MIB-free guess would have shipped: the
subtree `4526.<family>.17` looks like logging until you notice it holds port
`123` and the string `"NTP Bits: 0x1c6900a8"`. **`4526.x.17` is SNTP, not
syslog.** The syslog host `10.1.5.1` appears in both subtrees because the same
box is this fleet's NTP server and its syslog server.

## Functional map of the surface (gsm7228ps, 87684 parsed varbinds)

| Varbinds | Area | Library covers it? |
|---|---|---|
| 42612 | NETGEAR vendor `4526.11` | a few OIDs only |
| 35777 | RMON-MIB `1.3.6.1.2.1.16` | no |
| 1502 | IF-MIB `ifTable` | yes (ports, admin/oper status) |
| 1501 | IF-MIB `ifXTable` | partly (HC counters, `ifHighSpeed`, `ifAlias`) |
| 1416 | **EtherLike-MIB `dot3` — duplex** | **no** |
| 1329 | P-BRIDGE-MIB | no |
| 880 | ENTITY-MIB | yes (fan/PSU inventory) |
| 780 | BRIDGE-MIB FDB | yes (`get_macs`) |
| 563 | Q-BRIDGE-MIB | yes (VLANs) |
| 537 | POWER-ETHERNET-MIB | yes (PoE) |
| 206 | SNMPv2-MIB system | partly — `sysName` **not** exposed |
| 194 | SNMP-USER-BASED-SM / VACM | no (SNMP users, distinct from local users) |

## Hostname

`sysName` — `1.3.6.1.2.1.1.5.0` — reads on **all five** switches. Standard MIB,
so it does not depend on a vendor subtree, and it is the one hostname source
that works on the `gs728tpp` (which has no vendor OIDs at all).

**`sysName` is not the same value as the configured `hostname`.** Measured on
`m4300-16x` (10.1.5.20):

| Source | Value |
|---|---|
| `sysName` (SNMP) | `sw-netgear-m4300-16x-poe-s2` |
| `show hosts` → "Host name" | `sw-netgear-m4300-16x-poe-s2` |
| `show running-config \| include hostname` | `manage-sw-netgear-m4300-16x-poe-s2` |

So `sysName` tracks `show hosts`, and the configured `hostname` is a *different*
string. On `gsm7252ps` the divergence is starker: `show running-config | include
hostname` returns **nothing at all** while `sysName` and `show hosts` both
report `sw-netgear-gsm7252ps-s1`.

A `get_hostname` that reads `sysName` on SNMP and `show running-config` on the
CLI would therefore return **different answers for the same switch** — which the
cross-backend equivalence tests would rightly fail. The CLI reader must parse
`show hosts`, not `show running-config`.

## Logging / syslog

`4526.<family>.14` on **both** vendor families, with the same column layout —
`4526.11.14` on the S3300 family and `4526.10.14` on FASTPATH.

| OID (family arc as `x`) | Meaning | Measured |
|---|---|---|
| `4526.x.14.1.1.1.0` | console logging admin mode | `1` |
| `4526.x.14.1.1.4.0` | console severity filter | `1` |
| `4526.x.14.1.2.1.0` | buffered logging admin mode | `2` |
| `4526.x.14.1.2.2.0` | buffered severity filter | `3` |
| `4526.x.14.1.4.1.0` | **syslog admin mode** | `1` (m4300), `2` (S3300) |
| `4526.x.14.1.4.3.0` | **syslog local port** | `514` |
| `4526.x.14.1.4.4.0` | syslog max hosts | `8` |
| `4526.x.14.1.6.2.0` | email-alert from-address | `switch@netgear.com` |
| `4526.x.14.2.1.0` | log messages received | `82948` |
| `4526.x.14.2.2.0` | log messages dropped | `0` |
| `4526.x.14.3.1.0` | buffered log entry count | `82081` |
| `4526.x.14.3.2.1.2.<n>` | buffered log message text | `<13> Aug 2 05:14:36 …` |

### Syslog host table — `4526.10.14.1.4.5.1.<col>.<index>`

Present on `m4300-24x`, absent on `gsm7228ps` (which has no syslog host
configured — consistent, not a MIB difference).

| Col | Meaning | Measured | CLI cross-check |
|---|---|---|---|
| 2 | address type | `1` | — |
| 3 | **host address** | `10.1.5.1` | `10.1.5.1` |
| 4 | **port** | `514` | `514` |
| 5 | **severity** | `6` | `info` |
| 7 | **row status / state** | `1` | `Active` |
| 9, 10 | counters | `1`, `0` | — |

Every field of `show logging hosts` is accounted for by a column, and the two
agree. That is a genuine SNMP↔CLI cross-verification of the same state.

### CLI equivalents (measured on 3 FASTPATH switches)

- `show logging` — globals. The m4300s additionally report a source interface.
- `show logging hosts` — the host table. **The column set differs by firmware**:
  the m4300s emit `Index/IP/Severity/Port/Status/Mode/Auth/Cert#`, the
  `gsm7252ps` emits only the first five. A parser fixed to one shape breaks on
  the other.
- `show syslog` does **not** exist — `% Invalid input detected` on all three.

## Local users

Found on the S3300 family at `4526.11.1.2.1.3.2.1.<col>.0`:

| Col | Measured |
|---|---|
| 2 | `"admin"` (username) |
| 4, 5, 6, 7, 9 | `2`, `1`, `2`, `1`, `0` |
| 11 | `15` (privilege level) |

**The FASTPATH family does not mirror this**: `4526.10.1.2.1.3` is empty on the
m4300-24x, and no varbind anywhere in its 156077 parsed values equals the string
`admin`. Local users therefore look absent from FASTPATH SNMP and will need the
CLI (`show users`) — but that is a statement about one firmware on one SKU and
must be confirmed on the other FASTPATH units before it is recorded as a limit.

Note `1.3.6.1.6.3.15.1.2.2.1.3…` also yields `admin` — that is an **SNMPv3 USM
user**, a different thing from a local login account. They must not be conflated.

## Not yet located

- Service protocols (HTTP/HTTPS/telnet/SSH enable state and ports). Searching
  the vendor subtree for the values 22/23/80/443 returns only false positives,
  where the number is a table *index* rather than a configured port.
- Port speed/duplex **configuration** (as opposed to `ifHighSpeed`, which is the
  negotiated rate). EtherLike-MIB `dot3` at `1.3.6.1.2.1.10.7` carries 1416
  varbinds on the S3300 and is the obvious candidate for duplex status.
