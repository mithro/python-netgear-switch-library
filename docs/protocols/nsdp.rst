NSDP
====

The **Netgear Switch Discovery Protocol**: a UDP, TLV-based management protocol,
and one of only two ways to manage a Plus switch. It is undocumented by the
vendor; everything here was established by capture and by measurement against
live hardware.

Switches that speak it
----------------------

.. ngsw-backend-models:: NSDP

What it can do, per switch
--------------------------

.. ngsw-backend-operations:: NSDP

The wire format
---------------

A 32-byte header — signature ``NSDP``, version, operation, error status, the
blamed TLV tag, the client and device MACs, a sequence number — followed by
type-length-value entries and the end marker ``ff ff 00 00``. The library sends
from UDP port **63321** to port **63322**.

.. code-block:: text

   +--------------------------------+
   | "NSDP" header (32 bytes)       |
   |   version / operation / error  |
   |   blamed tag / client MAC      |
   |   device MAC / sequence number |
   +--------------------------------+
   | TLV: tag(2) len(2) value(len)  |
   | TLV: ...                       |
   | ff ff 00 00                    |
   +--------------------------------+

Because it is broadcast-based, **the sending interface matters** on a
multi-homed host. Pass ``nsdp_interface=`` to the facade, ``nsdp.interface`` in
the inventory, or ``--nsdp-interface`` on the command line.

.. note::

   The error status names the TLV that caused it: header bytes 4–5 carry the
   *blamed tag*. That is the single most useful field when a write is rejected,
   and the library surfaces it.

What NSDP can and cannot do
---------------------------

Reads: port status, per-port statistics, VLANs, PVIDs, and the management IP.
Writes: PVID, VLAN membership, VLAN create and delete, and the management IP.

It has **no** MAC/FDB table, LLDP, sensor or PoE capability, and this is not an
assumption — it was established by an exhaustive sweep of the tag space against
a live GS110EMX. The refusal messages the library raises say so, and they name
the sweep as their evidence.

Port administrative enable is also refused, as unproven rather than absent: no
tag has been shown to do it.

`SyncSwitch.nsdp_device` returns the complete raw device record — firmware,
serial number, DHCP mode, VLAN engine, QoS engine, port mirroring, IGMP
snooping, broadcast filtering, loop detection — including fields no other
backend exposes, and with per-port values left unconverted.

Write authentication
--------------------

Two schemes exist. A switch advertises which by the value of tag ``0x0014``
(``AUTH_V2_ENCPASS``): ``1`` means v1, ``0x10`` means v2.

**v1** (older firmware)
    The admin password travels in a ``PASSWORD`` TLV (``0x000A``) "encrypted" by
    a repeating XOR against the 19-byte key ``NtgrSmartSwitchRock``. XOR is its
    own inverse, so one function both encodes and decodes.

**v2** (newer firmware, including GS110EMX 1.0.2.8)
    A challenge-response. The client reads a fresh 4-byte salt from tag
    ``0x0017`` — which rotates on *every* read — then writes an 8-byte token in
    tag ``0x001A`` alongside the configuration change. The token is not a hash:
    it is an 8-byte XOR fold of the 20-byte password, the 4-byte salt and the
    switch's own 6-byte MAC, taken from the salt read's response header. Each
    output byte XORs three password bytes, which is precisely the weakness
    documented as CVE-2020-35221.

.. warning::

   **The token TLV must come first**, before the configuration TLVs. Sending it
   last is rejected. This cost real debugging time and is pinned by a test.

Two facts worth recording about v2, because both are easy to assume wrongly:

* The token is **not** ``md5(merge(password, salt))``. That transform *is* what
  the switch's web UI uses — confirmed by a successful HTTP login — but the two
  authentication paths do not share it. Every md5 variant was tried live against
  a real unit and rejected with error 13.
* Tag ``0x001A`` is write-only: reading it returns error 3.

Cross-checked against other implementations
-------------------------------------------

The v2 fold reproduces ``go-nsdp``'s own test vector byte for byte, and the
mock's packets were decoded by two independent third-party tools — ProSafeLinux
decodes both mock switches completely with every value matching the seed, and
the C implementation ``ngadmin`` validated the header and surfaced a real
four-byte sequence-number bug, which was fixed.

That is the point of an independent cross-check: a mock validated only by the
client that talks to it proves nothing.

Gotchas
-------

**Speed encoding.** In ``PORT_STATUS``, the speed byte value ``0x06`` means
10 Gbit/s. Treating unknown values as "down" made every 10G link on the GS110EMX
report as down — a real defect the tag sweep found.

**Variable-width TLVs.** ``PORT_MIRRORING`` is not a fixed size across firmware
versions; parsers must not assume one.

**Model is mandatory in a device reply.** A ``get_device`` response without a
``MODEL`` TLV is not a valid identification, and the parser says so rather than
inventing one.

API
---

* `netgear_switch.nsdp_read` — `NsdpReader`, `AsyncNsdpReader`.
* `netgear_switch.nsdp_write` — `NsdpWriter`, `AsyncNsdpWriter`.
* `netgear_switch.protocols.nsdp.protocol` — header, tags and error codes.
* `netgear_switch.protocols.nsdp.auth` — v1 XOR and the v2 fold, with the full
  investigation record in the module docstring.
* `netgear_switch.protocols.nsdp.types` — `NsdpDevice` and its components.
