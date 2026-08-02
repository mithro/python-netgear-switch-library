XML_API — the GoAhead ``wcd`` interface
=======================================

Not a web UI that happens to be scraped, but an actual XML API. The only entry
in the registry that is not HTML at all.

Switches
--------

.. ngsw-http-scheme:: XML_API

How the login works
-------------------

**Credentials go in the query string of a GET**, not in a form POST. Success is
signalled in the body — ``<statusCode>0</statusCode>`` — and the session id
arrives in a response header.

Because the responses are XML, this dialect needs none of the HTML parsing the
other four rely on: no form scraping, no hidden-field replay, no reading a
status out of a page that returned 200 regardless.

Why this switch needs its web UI
--------------------------------

The GS728TPP is the strongest argument in the fleet for having more than one
backend, because its SNMP agent is unusually poor: it implements **no Netgear
vendor OIDs at all**. A walk of ``1.3.6.1.4.1.4526`` answers ``noSuchObject``,
and its ``sysObjectID`` of ``4526.100.4.27`` is an identifier value rather than
the root of a data subtree.

Everything SNMP can answer therefore comes from standard MIBs — per-port PoE
from RFC 3621 ``pethPsePortTable``, the management IP from ``ipAddrTable``, and
fan and PSU *inventory* from ENTITY-MIB ``entPhysical``.

Crucially there is **no live sensor reading anywhere in its SNMP** — only the
inventory. The web UI's diagnostics page does report health. So the two backends
legitimately differ on this model, and the
:doc:`support tables </models/support>` say so rather than papering over it.

Pages
-----

.. ngsw-http-scheme-pages:: XML_API

Per-port statistics are the one read this API cannot serve; that data is only
available over SNMP on this model.

API
---

* ``netgear_switch.virtual.web_gs728tpp`` — the mock's XML responder.
* ``netgear_switch.protocols.http.endpoints`` — the spec, with the live captures
  that ground it.
