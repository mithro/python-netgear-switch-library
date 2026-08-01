GS105PE
=======

.. ngsw-model-photo:: gs105pe

A 5-port "Smart Plus" switch (Gen-2 Broadcom BCM53125) — a genuinely distinct
SKU from the GS305EP, not a rebadge. No SNMP; NSDP and the web UI.

At a glance
-----------

.. ngsw-model-facts:: gs105pe

Live-verified 2026-07-21 against real units at 10.1.5.29 and .30, firmware
V1.6.0.x. Seed: :py:func:`~netgear_switch.virtual.seed.seed_gs105pe`.

What works, over which protocol
-------------------------------

.. ngsw-model-support:: gs105pe

Measured behaviour
------------------

**Zero PoE ports — confirmed, not assumed.** The product is marketed with "PoE
pass-through", which means it can *be powered* over PoE; that is not a claim to
*source* power. The web UI's ``getPoePortStatus.cgi`` returns HTTP 404 on a real
unit, so it exposes no PSE status page at all, and ``poe_port_count`` is 0.

**No MAC/FDB table over any interface.** Not NSDP, not the web UI — a confirmed
firmware limitation rather than something merely unread.

**It exposed two real NSDP bugs**, both fixed: ``parse_device`` wrongly treated
the ``MODEL`` TLV as optional, and ``PORT_MIRRORING`` is variable-width across
firmware versions rather than the fixed size the parser assumed.

Protocols
---------

* :doc:`../protocols/nsdp` — the default backend; reports MODEL ``GS105PE`` and
  5 ports.
* :doc:`../protocols/http` — the ``MERGE_HASH_CGI`` scheme with the ``GS105PE``
  page dialect.
