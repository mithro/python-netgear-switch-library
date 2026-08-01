GS110EMX
========

.. ngsw-model-photo:: gs110emx

A 10-port Plus switch with multi-gigabit uplinks and no PoE. Like every Plus
model it has **no SNMP agent**: it is managed over NSDP and its web UI.

At a glance
-----------

.. ngsw-model-facts:: gs110emx

Live-verified on units at 10.1.5.25–.27, firmware 1.0.2.8. Seed:
:py:func:`~netgear_switch.virtual.seed.seed_gs110emx`.

What works, over which protocol
-------------------------------

.. ngsw-model-support:: gs110emx

Measured behaviour
------------------

**No MAC table, LLDP or sensors — on either interface.** That was established
independently on both, by an exhaustive sweep of the NSDP tag space against a
live unit *and* by the web UI's page set, rather than measured on one and
extrapolated to the other. The refusal messages name the sweep as their
evidence.

**This is the switch whose NSDP v2 write authentication was cracked.** It
advertises ``0x10`` for tag ``0x0014``, meaning the salted challenge-response:
read a rotating 4-byte salt from ``0x0017``, then write an 8-byte XOR fold of
the password, the salt and the switch's own MAC in tag ``0x001A`` — **first** in
the packet, before the configuration TLVs, or it is rejected.
:doc:`../protocols/nsdp` records the full investigation, including the
transforms that were tried and refused.

**Every 10G link used to report as down.** The ``PORT_STATUS`` speed byte value
``0x06`` means 10 Gbit/s; treating unknown values as "down" was a real defect the
tag sweep found and fixed.

**Its web UI uses the Gambit session scheme**, and — unlike NSDP — it *does*
expose port administrative enable, which is why
:py:meth:`~netgear_switch.sync_api.SyncSwitch.set_port_enabled` works over HTTP but not
NSDP on this model.

Protocols
---------

* :doc:`../protocols/nsdp` — the default backend.
* :doc:`../protocols/http` — the ``GAMBIT`` scheme, ``GS110EMX`` page dialect.
