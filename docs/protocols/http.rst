HTTP web UI
===========

The switch's own web interface, driven the way a browser drives it: log in,
fetch a page, parse it, and post the form the page would have posted. Available
on every model in this fleet except the two unverified SNMP-only entries.

Sometimes it is the *only* reachable interface — through a firewall that permits
nothing else — and on Plus switches it is the only route to PoE control, which
NSDP has no tag for.

Switches that speak it
----------------------

.. ngsw-backend-models:: HTTP

What it can do, per switch
--------------------------

Web UIs vary enormously: a ``—`` below means that model's firmware ships no page
carrying the data, which is a real limit of the interface rather than a missing
implementation here.

.. ngsw-backend-operations:: HTTP

Five web-UI protocols, not one
------------------------------

Netgear has no single web UI. Five distinct login schemes run across this fleet,
each paired with its own HTML dialect, and they share a transport and almost
nothing else — different credential handling, different session mechanics,
different page sets. Each gets its own page:

.. ngsw-http-scheme-table::

.. toctree::
   :maxdepth: 1

   http/merge-hash-cgi
   http/gambit
   http/cheetah-form
   http/cheetah-v1
   http/xml-api

Everything below this point holds for all five.

Endpoint specs
--------------

Every model's page set is one ``HttpModelSpec`` record: the login path and field
names, and a path per operation — dashboard, statistics, PoE status and config,
VLAN config and membership, PVIDs, MAC table, LLDP, system info, management IP,
port config, certificate upload, reboot, logout.

A ``None`` path means *this firmware ships no such page*, and the reader raises
rather than inventing data. That is precisely what the
:doc:`../models/support` gaps table reports. A page that exists but has not been
found yet looks identical from here — which is why those entries are treated as
work rather than as facts about the hardware.

Non-standard transport details are in the spec too: the M4300-16X's web UI is on
**HTTPS port 49152**, and its spec carries both.

Reads are gated on verification
-------------------------------

``HttpModelSpec.reads_verified`` records whether a model's web reads have been
cross-verified against live hardware. While it is ``False`` the facade refuses
to dispatch HTTP for reads *and* writes: output nobody has checked is worse than
no output. Certificate upload is the one deliberate exception — a grounded write
flow that does not depend on read verification.

Gotchas
-------

**The switch answers with a login page instead of the page you asked for.**
:py:obj:`~netgear_switch.errors.HttpUnexpectedPageError` almost always means the session went away.

**Logins start failing under frequent polling.** Where a spec has no
``logout_path``, sessions are left to expire on their own, and a switch with a
small session table can refuse new logins until they do.

**Errors arrive with HTTP 200.** On the FASTPATH XUI dialects a failed write
reports itself in hidden ``err_flag`` / ``err_msg`` fields while the response
code stays 200, so a write that "succeeded" by status code may not have — see
:doc:`http/cheetah-form`.

**A write is refused in a way that looks like a device limitation.** Web-UI
writes replay the whole form, including hidden and list-navigation fields, and
the firmware rejects an incomplete one — which is all "the GSM7252PS refuses PoE
writes" ever was: one absent list-unit field.

API
---

* `netgear_switch.http_read` — :py:obj:`~netgear_switch.http_read.HttpReader`, :py:obj:`~netgear_switch.http_read.AsyncHttpReader`.
* `netgear_switch.http_write` — :py:obj:`~netgear_switch.http_write.HttpWriter`, :py:obj:`~netgear_switch.http_write.AsyncHttpWriter`, and the
  certificate-upload flows.
* `netgear_switch.protocols.http.endpoints` — every model's spec, with the
  capture that grounds it named in comments.
* `netgear_switch.protocols.http.parse` — the per-dialect parsers.
* `netgear_switch.protocols.http.forms` — form scraping and replay.
* `netgear_switch.protocols.http.crypt` — the login hash transforms.
