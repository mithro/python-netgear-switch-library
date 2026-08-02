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


### CORRECTION: the dialect is drivable; `create_vlan` just lacks the branch

An earlier paragraph above implied the missing CSRF token makes the whole XE
FASTPATH dialect undrivable for writes. **That is wrong, and this corrects it.**

`HttpWriter.set_poe` branches on `_is_fastpath_dialect` into `_xui_poe_admin`,
which posts the two-`FORM` `submit_flag` shape and needs no `hash` at all. Its
docstring records it as LIVE-PROVEN on gsm7228ps (10.1.5.11, port `1/g12`),
m4300-16x (10.1.5.20:49152, port 1/0/15) and gsm7252ps (10.1.5.22). Driving
`set_poe` over HTTP against the now-faithful mock succeeds on all three
FASTPATH models.

So XUI writes work. `create_vlan`/`delete_vlan` simply have no XUI branch —
they go straight to the Plus form and its token. That makes HTTP VLAN creation
on FASTPATH a **missing implementation**, which principle 2 is explicit about:
*"A backend missing an operation is a missing implementation, to be built. It is
not a device limitation until proven otherwise."*

### Consequence: the capability marking committed above is itself wrong

`_CSRF_HTTP_WRITES` now makes the oracle report `Support.UNSUPPORTED` for HTTP
`create_vlan`/`delete_vlan` on those models. But `Support.UNSUPPORTED`'s own
docstring says it is *"Never a stand-in for 'not implemented yet'"* — and that
is exactly what it is being used for here.

The published support table therefore now tells a different lie from the one it
told before: it previously claimed a broken write worked; it now implies the
hardware cannot do something it can. The first lie was worse, so this is not a
regression — but it is not the end state.

**The correct fix is to implement `_xui_vlan_create`/`_xui_vlan_delete`**
alongside `_xui_poe_admin`, modelled on the same two-`FORM` `submit_flag` post,
then remove the `_CSRF_HTTP_WRITES` entry entirely so the table can say
"supported" truthfully. Until that lands, the xfail in
`tests/virtual/test_write_outcomes.py` and this note are the honest record.


### Root cause: `vlan_config_path` points at a STATUS page, not a config page

The reason HTTP `create_vlan` cannot work on FASTPATH is narrower and more
fixable than "no CSRF token".

`HTTP_SPECS['gsm7252ps'].vlan_config_path` is `/vlanStatus.html`. A live capture
(`tests/fixtures/http/gsm7252ps_vlan_status_live.html`) shows it *does* have the
XUI two-`FORM` shape — `ACTION="/vlanStatus.html/a0"` and `/a1`, plus
`submit_flag` — but it carries **no `v_2_*` action buttons at all**. It is a
read-only status page. `_xui_poe_admin` works because
`poeInterfaceConfiguration.html` is a *configuration* page and does have them.

The real page is **`/vlanConfiguration.html`** — 23104 bytes, titled "NetGear -
VLAN Configuration", carrying `v_2_1_1` through `v_2_1_4`. Captured as
`tests/fixtures/http/gsm7252ps_vlan_configuration_live.html`.

So the fix is two parts, and neither is a device limitation:

1. The spec needs a separate write path for VLAN creation — the read path
   (`vlanStatus.html`) is correct for `get_vlans` and simply cannot serve a
   write. This mirrors `vlan_membership_path` vs `vlan_membership_post_path`,
   which already makes exactly this distinction for membership.
2. `create_vlan`/`delete_vlan` then need an XUI branch posting to that page's
   action with the appropriate `v_2_1_*` button, modelled on
   `_xui_poe_admin`/`forms.xui_row_apply_form`.

Which of the four buttons is Add and which is Delete has NOT been established —
that needs the page's own markup read carefully, and the write driven against a
switch with a throwaway VLAN id before anything is claimed.


### `/vlanConfiguration.html` field semantics (read off the capture)

Correcting the previous note again: `v_2_1_1`..`v_2_1_4` are **row cell fields,
not action buttons**. From the capture:

| Field | Value in row 1 | Meaning |
|---|---|---|
| `1.0.14.v_2_1_1` | `1` | VLAN id |
| `1.0.14.v_2_1_2` | `default` | VLAN name |
| `1.0.14.v_2_1_3` | `Default` | VLAN type |
| `1.0.14.v_2_1_4` | `Add` | per-row action, in a `display:none` cell |

Two `FORM`s as expected: `/vlanConfiguration.html/a0` and `/a1`.

So this is the standard XUI editable-table shape the library already handles for
PoE (`parse_xui_list_page` + `forms.xui_row_apply_form`), with one difference
that matters: PoE **edits an existing row**, whereas creating a VLAN means
**submitting a NEW row** carrying the id, the name and the action cell.

`xui_row_apply_form` builds its body from a row the parser found on the page, so
it cannot express "a row that is not there yet". Creating a VLAN needs a sibling
builder — an add-row form — rather than a new argument to the existing one.

**Not yet established, and deliberately not guessed:** whether the action cell
takes the literal `Add` for a new row, what a delete row carries in that cell,
and whether the id/name cells for a new row are indexed `v_2_<n>_<col>` at the
next free row number or at a fixed "new row" index. Every one of those is
readable from the page's own JavaScript or from a browser-driven capture of a
real Add. Until then this stays unimplemented: posting a guessed action to a
switch's live VLAN table is the one write here that could disrupt production
VLANs, and the project's rule is that a wrong guess must never be shipped as a
capability.


### RESOLVED: the action cell is SNMP RowStatus, read from the page's own JS

`/scripts/_xe_vlanConfiguration.js` (captured as
`tests/fixtures/http/gsm7252ps_vlan_configuration.js`) defines the `2_1_4`
column's value list:

    [ "Invalid","Active","Not In Service","Not Ready","Add","Reserve","Delete","Modify" ]

Indexed from 0, that is **SNMP RowStatus**:

| Index | Label | RowStatus |
|---|---|---|
| 1 | Active | `active(1)` |
| 2 | Not In Service | `notInService(2)` |
| 3 | Not Ready | `notReady(3)` |
| **4** | **Add** | **`createAndGo(4)`** |
| 5 | Reserve | `createAndWait(5)` |
| **6** | **Delete** | **`destroy(6)`** |

The web UI is a thin skin over the same Q-BRIDGE row semantics the SNMP backend
already writes — and the library already names those constants:
`oids.ROW_STATUS_CREATE_AND_GO = 4` and `oids.ROW_STATUS_DESTROY = 6`.

The same file gives the two action buttons:

    xeData.xbImage_6_1_1 = "/base/images/Add_on.gif"     -> button 6_1_1 = Add
    xeData.xbImage_6_1_2 = "/base/images/Delete_on.gif"  -> button 6_1_2 = Delete

So all three unknowns from the previous note are now answered **from the
device's own code**, with no guessing and no write attempted:

* the action cell takes `4` to create and `6` to delete;
* a create submits a new row carrying id, name and action `4`;
* the submit buttons are `6_1_1` (Add) and `6_1_2` (Delete).

That is enough to implement `_xui_vlan_create`/`_xui_vlan_delete` against
`/vlanConfiguration.html`, posting to its `/a0` or `/a1` action alongside the
existing `submit_flag`. It still needs driving against a switch with a throwaway
VLAN id and reading back before `reads_verified`-style confidence is claimed —
but the mechanism is no longer inferred.


### The ADD button is client-side; APPLY carries the new row

Posting `v_6_1_1=ADD` to `/vlanConfiguration.html/a1` (with the page's tokens
and nav) returns **12 bytes** — not a form. So `ADD` is a JavaScript action that
reveals an input row in the table the browser already has; it is not a server
round trip and it creates nothing.

Section 6 is the page-button block (the page's own comment marks it
`page_buttons_end`):

| Field | Value |
|---|---|
| `v_6_1_1` | `ADD` |
| `v_6_1_2` | `DELETE` |
| `v_6_1_3` | `CANCEL` |
| `v_6_1_4`, `v_6_1_5` | `APPLY` |

The display table is 14 rows addressed `1.<row0>.14.v_2_1_<col>`, all hidden
inputs, with columns 1=id, 2=name, 3=type and 4=RowStatus.

So the create flow is a SINGLE post: the new row's cells plus an APPLY button,
with the action cell carrying `createAndGo(4)` — and delete is the same shape
with `destroy(6)`. It is NOT the two-step ADD-then-APPLY a browser appears to
perform.

Also captured: `page.action` is `/vlanConfiguration.html/a1`, `page.tokens` is
empty for this page, and `page.nav` is
`{v_1_1_1: Disable, v_4_1_1: 4093, v_4_2_1: Descending}` — the nav block that
`xui_row_apply_form` already knows to send.

**Still unresolved:** the row index a new row must use. Existing rows occupy
`1.0.14` .. `1.13.14`; whether a create uses `1.14.14` (next free), a fixed
sentinel, or re-uses index 0 has not been established, and getting it wrong
would edit an existing VLAN rather than add one. That is the single remaining
unknown, and it is readable from `xui_common.js`'s row-add handler.
