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


## Local users and service protocols — CLI, measured 2026-08-02

Captured from m4300-24x (10.1.5.13) and gsm7252ps (10.1.5.22). Three things
here would have been got wrong by assuming, which is why they are recorded
before any code is written against them.

### `show users` — two users, and the access-mode WORDS differ by firmware

Both switches carry `admin` and `guest`, and both print the same five columns
(User Name, User Access Mode, three SNMPv3 columns). The **values** are not the
same vocabulary:

| Switch | admin | guest |
|---|---|---|
| m4300-24x | `Privilege-15` | `Privilege-1` |
| gsm7252ps | `Read/Write` | `Read Only` |

A parser mapping the access-mode column to an enum must accept both spellings.
Matching on `Privilege-N` alone would silently fail on the gsm7252ps and vice
versa — the same shape of defect as the `show logging hosts` column count.

`show users long` prints just the names, on both.

### `show telnet` is OUTBOUND telnet, not the telnet server

    Outbound Telnet Login Timeout (minutes)........ 5
    Maximum Number of Outbound Telnet Sessions..... 5
    Allow New Outbound Telnet Sessions............. Yes

Every field is about the switch acting as a telnet **client**. None of it
reports whether the inbound telnet server — the thing this library's TELNET
backend connects to — is enabled. Reading "Allow New Outbound Telnet Sessions:
Yes" as "telnet is on" would be wrong in exactly the way that looks right.
The inbound server state has NOT been located yet.

### `show ip ssh` works, but its field set differs by firmware

    Administrative Mode: .......................... Enabled
    SSH Port: ..................................... 22          <- m4300 ONLY
    Protocol Levels: .............................. Version 2
    Max SSH Sessions Allowed: ..................... 5

The gsm7252ps prints **no `SSH Port` line at all**, and reports its protocol
levels as `Versions 1 and 2` against the m4300's `Version 2`. A reader must
treat the port as optional rather than assume every FASTPATH image reports it.

### HTTP has no `show ip http server`

Both switches answer `% Invalid input detected` to `show ip http server` and to
`show ip http secure-server`. The command that reports web-server state has not
been found yet; it is not either of those.

### What this means for implementation

`get_users` is implementable on the FASTPATH CLI today, across both firmwares,
provided the access-mode parser accepts both vocabularies. Note the SNMP side
disagrees about scope: the S3300's vendor user table (`4526.11.1.2.1.3`) held
only ONE user, while its CLI shows two — so the two backends are not reporting
the same set, and that must be resolved before `get_users` is registered as a
cross-backend operation.

Service protocols are NOT implementable yet: SSH state is readable, inbound
telnet state is unlocated, and HTTP state is unlocated. Recording that as three
separate unknowns rather than one blocked feature.


## Service-protocol WRITE commands — attempted, not established

Reading service state is done (`show ip http`, `show telnetcon`, `show ip ssh`;
see `get_services`). The commands that CHANGE it are not, and this section
records the attempt so the next person does not repeat it.

Toggling a management service on a production switch can lock out the very
session doing it — disabling SSH on 10.1.5.13 would end the connection issuing
the command — so no toggle was performed. The safe substitute this project uses
elsewhere is the device's own context-sensitive help (`<partial> ?`), which is
read-only and abandons the line.

That substitute did **not** work cleanly here. Asked in config mode on
m4300-24x:

| Query | Answer |
|---|---|
| `ip http ?` | lists only `accounting` and `authentication` |
| `ip ssh ?` | `% Unrecognized command` |
| `ip telnet ?` | `% Unrecognized command` |
| `telnet ?` | `% Unrecognized command` |

Two reasons to distrust the negative results rather than record them as limits:

1. **`ip http secure-server` is demonstrably valid on this switch** — it appears
   in its own `show running-config | include http` output. So the `ip http ?`
   listing above is incomplete, not authoritative, and the help query is being
   partly consumed by the shell driver rather than fully captured.
2. `show running-config | include telnet` returns `line telnet`, which suggests
   the inbound telnet server is configured inside a `line telnet` sub-mode
   rather than at global-config level. That would explain the `ip telnet`
   rejection without meaning the capability is absent.

**Conclusion: unresolved, and deliberately not implemented.** What is needed is
either a capture of the help output through a driver that does not swallow it,
or a toggle performed on a switch that is safe to lose contact with. Writing
`ip http server` / `no ip ssh server` on the strength of FASTPATH convention
would be precisely the inference this project forbids — and the cost of being
wrong is a switch that can no longer be reached.


## DEFECT: HTTP `create_vlan` cannot work on the FASTPATH models

Found 2026-08-02 by driving `create_vlan` over each backend of gsm7252ps
(10.1.5.22) against the live switch:

| Backend | Result |
|---|---|
| SNMP | created, deleted, VLAN set restored — PASS |
| SSH | created, deleted, VLAN set restored — PASS |
| **HTTP** | **`HttpUnexpectedPageError: no CSRF 'hash' token on page before write`** |

`HttpWriter.create_vlan` was written for the **Plus** dialect and only ever
worked there. Its own comment says so — *"web UI 8021qCf.cgi has no VLAN-name
field"* — that is the gs305ep/gs105pe `.cgi` page. It scrapes an
`<input name="hash">` CSRF token and posts `forms.vlan_add_form`.

On a FASTPATH model `vlan_config_path` is `/vlanStatus.html`, and a live
capture of that page (`tests/fixtures/http/gsm7252ps_vlan_status_live.html`)
shows it carries **no `hash` input at all** — only `applet_port`,
`applet_unit`, `dbgopt` and the XUI cell hiddens (`1.N.14.v_1_1_M`). It is an
XUI page and needs the two-`FORM` `submit_flag` shape, not the Plus form.

### Why nothing caught it

* **The capability oracle says HTTP=yes.** `_http_path_for` only asks whether
  `vlan_config_path` is set. It is — it just points at a page this writer
  cannot drive.
* **The mock passes.** `virtual/web.py` emits
  `<input type="hidden" name="hash" ...>` on *every* rendered page, including
  the FASTPATH ones. The real FASTPATH page has no such input, so the mock and
  the writer agree with each other while both disagree with the device — the
  exact failure principle 5 describes, and why a green suite proved nothing.

### Scope

Confirmed on gsm7252ps. The same code path and page type apply to `gsm7228ps`,
`m4300-24x` and `m4300-16x`, so they are expected to fail identically — an
inference, and each needs its own live check before it is recorded as fact.
`gs728tpp` is a different dialect (GoAhead XML) and untested here.

### What has to change

1. The mock must stop emitting a `hash` token on pages that do not have one.
   That alone will turn the existing suite red, which is the correct outcome.
2. `create_vlan` needs an XUI implementation for the FASTPATH dialects.
3. Until it exists, the oracle must report HTTP `create_vlan` unsupported on
   those models rather than claiming it works.


### Follow-up: no FASTPATH page carries the token, and the tests cannot see it

Probing every write page on the live gsm7252ps:

| Page | `hash` present |
|---|---|
| `/vlanStatus.html` | no |
| `/poeInterfaceConfiguration.html` | no |
| `/portPvidConfiguration.html` | no |
| `/switching/dot1q/vlan_port_cfg.html` | no |
| `/portsConfiguration.html` | no |

So the token is absent from the **whole XE FASTPATH dialect**, not just the VLAN
page, and every `_csrf`-scraping write is affected on those models — not only
`create_vlan`.

The mock is now faithful: `virtual/web.py` emits the token only for the Plus
dialects that really have it, and driving HTTP `create_vlan` against the fake
reproduces the live failure on gsm7252ps while still succeeding on gs305ep.

**`tests/test_capabilities.py` stayed green through that change, and it was
right to.** Its `_refused()` counts only `UnsupportedCapabilityError` and
`NotImplementedError` as a refusal; anything else "means the backend ACCEPTED
the operation and tried, which is exactly what Support.SUPPORTED claims". An
`HttpUnexpectedPageError` is therefore success by that definition. The test
verifies **dispatch**, not **outcome** — by design — so it can never catch a
write that reaches the right backend and then fails there.

That is a gap in the safety net, not a bug in the test. Catching this class
needs a different check: drive each write against the mock and assert the state
actually changed. Recorded here so the next person does not assume a green
capability suite means the writes work.
