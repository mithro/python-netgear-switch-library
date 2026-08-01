GS728TPP
========

.. ngsw-model-photo:: gs728tpp

.. ngsw-model-diagram:: gs728tpp

A 28-port Smart Managed Pro switch with 24 PoE+ ports. The most unusual entry in
the registry: its SNMP agent implements **no Netgear vendor OIDs at all**, and
its web UI is an XML API rather than scraped HTML.

At a glance
-----------

.. ngsw-model-facts:: gs728tpp

Live-verified at 10.2.5.10 via a jump host. Seed:
:py:func:`~netgear_switch.virtual.seed.seed_gs728tpp`.

What works, over which protocol
-------------------------------

.. ngsw-model-support:: gs728tpp

Measured behaviour
------------------

**Zero vendor OIDs.** A walk of ``1.3.6.1.4.1.4526`` answers ``noSuchObject``;
the ``sysObjectID`` of ``4526.100.4.27`` is only an identifier value, not a data
subtree. Everything comes from standard MIBs instead — per-port PoE from RFC
3621 ``pethPsePortTable``, the management IP from ``ipAddrTable``, and the fan
and PSU **inventory** from ENTITY-MIB ``entPhysical``. This is why the readers
guard on ``oids.has_vendor_oids`` rather than assuming a vendor subtree exists.

**There is no live sensor value anywhere in its SNMP** — only the inventory. The
web UI's diagnostics list does report health, so the two backends legitimately
differ here. That is a difference, not a bug, and the support table above states
it rather than hiding it.

**Its web UI is the GoAhead ``wcd`` XML API.** Login is a ``GET`` carrying the
credentials in the query string — not a form POST — answering
``<statusCode>0</statusCode>`` with a session id in a response header. It is the
only ``XML_API`` model in the registry.

**Management-IP writes are unavailable on both backends.** SNMP cannot serve
them because the mgmt-IP write columns are vendor-only and this agent has no
vendor subtree; the web UI ships no page for it. The support table reports both
refusals with their reasons.

Protocols
---------

* :doc:`../protocols/snmp` — standard MIBs only, no vendor subtree.
* :doc:`../protocols/http` — the ``XML_API`` scheme, ``GOAHEAD_XML`` dialect.
