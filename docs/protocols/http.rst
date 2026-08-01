HTTP web UI
===========

The switch's own web interface, driven the way a browser drives it: log in,
fetch a page, parse it, and post the form the page would have posted. Available
on every model in this fleet except the two unverified SNMP-only entries.

It matters because it is sometimes the *only* reachable interface — through a
firewall that permits nothing else — and because on Plus switches it is the only
route to PoE control, which NSDP has no tag for.

Switches that speak it
----------------------

.. ngsw-backend-models:: HTTP

What it can do, per switch
--------------------------

Web UIs vary enormously: a ``—`` below means that model's firmware ships no page
carrying the data, which is a real limit of the interface rather than a missing
implementation here.

.. ngsw-backend-operations:: HTTP

Five login schemes
------------------

There is no single Netgear web UI. Each scheme in
``src/netgear_switch/protocols/http/endpoints.py`` is a distinct firmware
lineage:

.. list-table::
   :header-rows: 1
   :widths: 22 78

   * - Scheme
     - How login works
   * - ``MERGE_HASH_CGI``
     - Plus switches (GS305EP, GS105PE). The password is hashed by merging it
       with a nonce the login page carries, then posted to a ``.cgi`` endpoint.
   * - ``GAMBIT``
     - GS110EMX. A ``Gambit`` session token is issued at login and carried
       thereafter.
   * - ``CHEETAH_FORM``
     - GSM7252PS and the S3300. A conventional form POST setting a session
       cookie.
   * - ``CHEETAH_V1``
     - M4300. Same lineage, but every page lives under ``/v1/``, a ``Referer``
       header is required as CSRF protection, and the session identifier expires
       on a 60-second window.
   * - ``XML_API``
     - GS728TPP. A GoAhead ``wcd`` XML API: a ``GET /`` redirect to a
       per-session path, then a **GET** — not a POST — carrying the credentials
       in the query string, answering ``<statusCode>0</statusCode>`` with a
       session id in a response header.

Seven HTML dialects
-------------------

Login is only half of it: the pages themselves differ enough that parsing is
per-dialect — ``STANDARD``, ``GS110EMX``, ``GS105PE``, ``M4300``,
``XE_FASTPATH``, ``S3300`` and ``GOAHEAD_XML``.

The FASTPATH XUI dialects share a distinctive shape worth knowing if you ever
read the write code: each page carries two ``<FORM>`` elements, posts to
``<page>.html/a1`` with a ``submit_flag``, addresses table rows as
``<unit>.<row>.<count>.v_1_2_<column>``, and returns errors as hidden
``err_flag`` / ``err_msg`` fields **with HTTP 200**. A write that "succeeded"
by status code may have failed in the body, so the library reads those fields.

Endpoint specs
--------------

Every model's page set is one ``HttpModelSpec`` record: the login path and field
names, and a path per operation — dashboard, statistics, PoE status and config,
VLAN config and membership, PVIDs, MAC table, LLDP, system info, management IP,
port config, certificate upload, reboot, logout.

A ``None`` path means *this firmware ships no such page*, and the reader raises
rather than inventing data. That is precisely what the
:doc:`../models/support` gaps table reports, and where a page exists but has not
been found yet, it looks identical from here — which is why those entries are
treated as work rather than as facts about the hardware.

Non-standard transport details are in the spec too: the M4300-16X's web UI is on
**HTTPS port 49152**, and its spec carries both.

Reads are gated on verification
-------------------------------

``HttpModelSpec.reads_verified`` records whether a model's web reads have been
cross-verified against live hardware. While it is ``False`` the facade refuses
to dispatch HTTP for reads *and* writes: output nobody has checked is worse than
no output. Certificate upload is the one deliberate exception — it is a grounded
write flow that does not depend on read verification.

Gotchas
-------

**Sessions expire, and a page you did not expect is the symptom.**
`HttpUnexpectedPageError` almost always means the session went away and the
switch served a login page instead of the page requested.

**Some models never log out.** Where a spec has no ``logout_path``, sessions are
left to expire on their own, and a switch with a small session table can refuse
new logins until they do. Worth knowing if you poll frequently.

**Errors arrive with HTTP 200.** See the XUI note above.

**A write needs the fields the page would have sent.** Web-UI writes replay the
whole form, including hidden and list-navigation fields. A missing one is
rejected by the firmware in ways that look like a device limitation but are not:
"the GSM7252PS refuses PoE writes" turned out to be one absent list-unit field.

API
---

* `netgear_switch.http_read` — `HttpReader`, `AsyncHttpReader`.
* `netgear_switch.http_write` — `HttpWriter`, `AsyncHttpWriter`, and the
  certificate-upload flows.
* `netgear_switch.protocols.http.endpoints` — every model's spec, with the
  capture that grounds it named in comments.
* `netgear_switch.protocols.http.parse` — the per-dialect parsers.
* `netgear_switch.protocols.http.forms` — form scraping and replay.
* `netgear_switch.protocols.http.crypt` — the login hash transforms.
