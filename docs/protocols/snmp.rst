SNMP
====

The richest backend, available on every Fully Managed and Smart Managed Pro
model. Plus switches have no SNMP agent at all.

Switches that speak it
----------------------

.. ngsw-backend-models:: SNMP

What it can do, per switch
--------------------------

.. ngsw-backend-operations:: SNMP

Transports
----------

.. list-table::
   :header-rows: 1
   :widths: 18 26 56

   * - Mode
     - Implementation
     - Notes
   * - Synchronous
     - ``NetsnmpCliClient`` in ``src/netgear_switch/transport/sync/snmp_netsnmp_cli.py``
     - Shells out to ``snmpget``, ``snmpbulkwalk`` and ``snmpset`` from the
       net-snmp system package. No Python SNMP library is needed. A non-default
       port is given as ``host:port``.
   * - Asynchronous
     - ``PysnmpClient`` in ``src/netgear_switch/transport/aio/snmp_pysnmp.py``
     - Uses :pypi:`pysnmp` from the ``[async]`` extra, and takes ``port=`` as a
       keyword.

Both satisfy the same ``SnmpClient`` protocol, so a reader neither knows nor
cares which is underneath — and either can be pointed at a mock.

.. note::

   The net-snmp CLI route was chosen deliberately: ``ezsnmp`` fails to build on
   arm64, and shelling out to the reference implementation removes a whole class
   of encoding disagreements. The cost is a system dependency —
   ``apt install snmp``.

What is read from where
-----------------------

Almost everything comes from standard MIBs, which is why it works across models
that share no vendor OIDs at all:

.. list-table::
   :header-rows: 1
   :widths: 26 74

   * - Data
     - Source
   * - Port status
     - ``IF-MIB`` — ``ifType`` (to find the physical ports), ``ifAdminStatus``,
       ``ifOperStatus``, ``ifName``, ``ifAlias``, ``ifHighSpeed``.
   * - Counters
     - ``IF-MIB`` 64-bit ``ifHC*`` octet and unicast counters, plus
       ``ifInErrors`` / ``ifOutErrors``.
   * - VLANs and PVIDs
     - ``Q-BRIDGE-MIB`` — ``dot1qVlanStaticName``, ``dot1qVlanStaticEgressPorts``,
       ``dot1qVlanStaticUntaggedPorts``, ``dot1qPvid``.
   * - MAC table
     - ``Q-BRIDGE-MIB`` ``dot1qTpFdbPort``, mapped through
       ``dot1dBasePortIfIndex``.
   * - LLDP
     - ``LLDP-MIB`` ``lldpRemTable``.
   * - PoE
     - ``POWER-ETHERNET-MIB`` (RFC 3621) ``pethPsePortTable``. Delivered power in
       milliwatts is a *vendor* column where one exists.
   * - Management IP
     - ``ipAddrTable`` / ``ipRouteTable``, the base MAC from
       ``dot1dBaseBridgeAddress``, with an RFC 4293 fallback for the M4300.
   * - Sensors
     - Vendor fan/PSU/temperature columns where present; otherwise the
       ``ENTITY-MIB`` physical inventory, which has no live values.

Vendor subtrees
---------------

Two Netgear enterprise subtrees appear in this fleet, and which one a model uses
is recorded in its registry entry:

* ``1.3.6.1.4.1.4526.10`` — Fully Managed (M4300, GSM7252PS).
* ``1.3.6.1.4.1.4526.11`` — Smart Managed Pro (S3300 / GSM7228PS).
* **Neither** — the GS728TPP implements no vendor OIDs whatsoever. A walk of
  ``1.3.6.1.4.1.4526`` answers ``noSuchObject``; its ``sysObjectID`` of
  ``4526.100.4.27`` is only an identifier value, not a data subtree.

Code guards on ``oids.has_vendor_oids(model)`` instead of assuming a subtree is
there, which is what makes the vendor-free model work at all.

.. warning::

   A model's ``sysObjectID`` product identifier and its vendor *data* subtree
   are different things. The S3300's product OID is ``4526.100.10.19`` while its
   data lives under ``4526.11``. Confusing the two is what made model
   auto-detection fail on that switch.

Model identification
--------------------

:py:obj:`~netgear_switch.sync_api.detect_model` reads ``sysObjectID`` and ``sysDescr``. ``sysObjectID`` is
preferred: it is an unambiguous product identifier, so it can separate SKUs
whose ``sysDescr`` text is indistinguishable — the S3300-52X from the
unregistered S3300-28X, for instance. The OID map holds only values proven by a
live capture, never one read off a specification sheet, and an unmatched switch
yields ``key=None`` rather than a guess.

VLAN writes
-----------

Two dialects, selected by ``SwitchModel.snmp_vlan_write``:

``"qbridge"``
    Read-modify-write of ``dot1qVlanStaticEgressPorts`` and
    ``dot1qVlanStaticUntaggedPorts``. Verified on the GSM7252PS and the S3300 —
    and it is the only mechanism *either* publishes: a walk of the vendor
    switchport table returns zero rows on both, versus 1520 and 1440 rows on the
    two M4300s.

``"fastpath_switchport"``
    Writes go to the vendor switchport table
    ``1.3.6.1.4.1.4526.10.1.2.8.37.1``: column 2 is the port mode
    (access/trunk/general), column 3 the access VLAN, column 6 the allowed-VLAN
    bitmap. Columns 7 and 8 (untagged and tagged bitmaps) are ``notWritable``.

On FASTPATH 12.x the standard columns are effectively unusable:
``dot1qVlanStaticEgressPorts`` is writable only while **no interface on the
switch** is in access mode, and an untagged membership write is expressed *as*
access mode — so the standard dialect would disable itself on first use.
``dot1qVlanStaticUntaggedPorts`` is worse than read-only: a SET returns
``noError`` and is then silently discarded. ``dot1qVlanStaticRowStatus :=
notInService`` also ``commitFail``\ s, so there is no RFC 2674
suspend-modify-activate route either.

PortList widths
---------------

A ``PortList`` bitmap's width is a property of the *device*, not of its port
count. The three measured here are 79, 131 and 45 bytes on switches with 52, 28
and 52 ports. None is derivable from the port count, and writing a bitmap of the
wrong width is a wire-conformance defect.

The writer preserves the width the device itself reported. The mock seeds the
measured widths per model rather than computing them — because a mock that
derives a value with the same formula as the code under test can only ever agree
with that code. That is exactly how this defect went unnoticed.

Gotchas
-------

**An unauthorised request is silently dropped.** No error, no refusal — the
agent does not answer at all, which is indistinguishable from an unreachable
host. If writes "time out", check the write community before anything else. One
switch here has no ``private`` community at all; it publishes ``pib`` and
``public``, both read-write.

**The untagged varbind in a combined write is ignored.** On Smart firmware,
setting a port's egress bit auto-untags it, and that side effect beats an
untagged varbind in the same PDU. Two PDUs, egress first, work — see
``snmp_vlan_split_membership_writes``.

**An absent optional OID is not an error.** Readers treat a missing optional
subtree honestly: ``power_mw`` is ``None`` where there is no vendor power column,
rather than ``0``. But a model that *claims* a vendor sensor subtree and walks
empty raises, rather than returning ``[]`` — that silent-empty is what hid the
GS728TPP's vendor-OID mismatch.

API
---

* `netgear_switch.snmp_read` — :py:obj:`~netgear_switch.snmp_read.SnmpReader`, :py:obj:`~netgear_switch.snmp_read.AsyncSnmpReader`, :py:obj:`~netgear_switch.snmp_read.read_system_info`.
* `netgear_switch.snmp_write` — :py:obj:`~netgear_switch.snmp_write.SnmpWriter`, :py:obj:`~netgear_switch.snmp_write.AsyncSnmpWriter`.
* `netgear_switch.protocols.snmp.oids` — every OID this library uses, with the
  measurement notes attached.
* `netgear_switch.protocols.snmp.parse` — pure parsers over walk output.
