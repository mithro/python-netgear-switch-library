GSM7252PS
=========

.. ngsw-model-photo:: gsm7252ps

.. ngsw-model-diagram:: gsm7252ps

A 52-port Fully Managed stackable switch, 48 of them PoE. The model with the
widest verified backend coverage in this fleet — SNMP, the XE FASTPATH web UI
and the CLI are all cross-verified against each other — and the one the
equivalence tests lean on hardest.

At a glance
-----------

.. ngsw-model-facts:: gsm7252ps

Live-verified at 10.1.5.22. Its seed,
:py:func:`~netgear_switch.virtual.seed.seed_gsm7252ps`, is the most exhaustively
documented in the project: every read operation has at least one non-empty,
non-vacuous example, so the parsers are exercised against real data rather than
empty tables.

What works, over which protocol
-------------------------------

.. ngsw-model-support:: gsm7252ps

Measured behaviour
------------------

**Q-BRIDGE really is writable here** — and that is verified, not assumed. A walk
of the vendor switchport table ``1.3.6.1.4.1.4526.10.1.2.8.37`` returns **zero
rows** on this switch, versus 1520 on the M4300-24X, so the standard
read-modify-write dialect is not merely the one that happened to work first: it
is the only membership mechanism this agent publishes.

**A single combined PDU applies correctly.** Unlike the S3300, this firmware
honours egress and untagged varbinds travelling together, so it keeps the atomic
write rather than the split-PDU workaround.

**Its VLAN PortList is 79 bytes wide** — a property of the device, not derivable
from its 52 ports. The mock seeds that measured width instead of computing it,
which is what makes the wire-conformance test meaningful.

**"It refuses PoE writes over HTTP" was our bug, not the firmware's.** The web
form needs a list-navigation field (``v_1_1_1``) that the writer was not
sending; with it, PoE writes apply cleanly. See :doc:`../protocols/http`.

Protocols
---------

* :doc:`../protocols/snmp` — vendor subtree ``4526.10``, the default backend.
* :doc:`../protocols/http` — the ``XE_FASTPATH`` dialect, ``CHEETAH_FORM``
  login.
* :doc:`../protocols/cli` — SSH or telnet, and SCP certificate deployment.
