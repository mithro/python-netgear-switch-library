Reading a switch
================

Nine read operations, available on `SyncSwitch` and `AsyncSwitch` alike, each
taking an optional ``backend=``. All return frozen dataclasses from
`netgear_switch.models`, identical whichever protocol produced them.

The operations
--------------

.. list-table::
   :header-rows: 1
   :widths: 22 26 52

   * - Method
     - Returns
     - Notes
   * - `SyncSwitch.get_ports`
     - ``list[PortStatus]``
     - Port number, ``ifName``, admin state, link state, speed in Mbit/s, and
       the operator-set description (``ifAlias``) where the backend can read
       one.
   * - `SyncSwitch.get_stats`
     - ``list[PortStats]``
     - RX/TX bytes, packets and errors. Any counter a backend cannot read is
       ``None``, never zero.
   * - `SyncSwitch.get_vlans`
     - ``list[VLANInfo]``
     - VLAN id, name, and three port sets: ``member_ports``, ``tagged_ports``,
       ``untagged_ports``.
   * - `SyncSwitch.get_pvids`
     - ``list[tuple[int, int]]``
     - ``(port, vlan)`` pairs.
   * - `SyncSwitch.get_lldp`
     - ``list[LLDPNeighbor]``
     - Local port plus the neighbour's system name, chassis id, port id and
       port description.
   * - `SyncSwitch.get_macs`
     - ``list[MacEntry]``
     - The forwarding table: MAC, port, VLAN.
   * - `SyncSwitch.get_poe`
     - ``list[PoEStatus]``
     - Admin state, detection state (`PoEDetect`) and delivered milliwatts.
   * - `SyncSwitch.get_sensors`
     - ``list[Sensor]``
     - Fan, PSU and temperature readings with their units.
   * - `SyncSwitch.get_mgmt_ip`
     - `MgmtIpConfig`
     - Address, netmask, gateway, DHCP-or-static mode, and the switch's base
       MAC.

Not every model serves every one of these on every backend.
:doc:`../models/support` has the complete grid, and
`netgear_switch.capabilities.support` answers the question in code.

Absent data is ``None``, never a substitute
-------------------------------------------

A field a backend genuinely cannot read stays ``None``:

* ``PortStatus.description`` is ``None`` on NSDP and HTTP backends, which have
  no ``ifAlias`` equivalent — not ``""``.
* ``PoEStatus.power_mw`` is ``None`` on a switch with no vendor power column
  (the GS728TPP serves everything from standard MIBs and has no such column) —
  not ``0``.
* ``MgmtIpConfig.base_mac`` is ``None`` where the model's web UI has no page
  carrying it.

An operation that cannot be answered at all *raises*; it does not return an
empty list. An empty list means the switch really reported nothing.

Two special reads
-----------------

`SyncSwitch.identify` asks the switch what it actually is, over SNMP, ignoring
the model the facade was constructed with. That is the point: use it to confirm
or discover a model when you only have a host and a community.

.. code-block:: python

   detected = switch.identify()
   if detected.matched and detected.key != switch.model.key:
       raise SystemExit(f"{switch.host} is really a {detected.key}")

Matching prefers ``sysObjectID`` — an unambiguous product identifier that can
distinguish SKUs whose ``sysDescr`` text is identical — and falls back to
``sysDescr``. ``key`` is ``None`` when neither matched; it is never a guess.

`SyncSwitch.nsdp_device` returns the complete raw NSDP device record for a Plus
switch: firmware, serial, DHCP mode, VLAN engine, port mirroring, IGMP snooping
and the unconverted per-port fields. It is NSDP-only by nature and bypasses
backend dispatch.

Snapshots
---------

`SyncSwitch.snapshot` runs every read over **one** backend and returns a
`SwitchData`:

.. code-block:: python

   snap = switch.snapshot()
   print(snap.model, snap.host, len(snap.ports), len(snap.vlans))

Fields that backend cannot serve degrade to ``()`` or ``None``. They are *not*
re-read over another protocol — so a snapshot describes what one protocol
really reports, rather than a blend of several. To compare protocols, take two
snapshots:

.. code-block:: python

   from netgear_switch import Backend

   over_snmp = switch.snapshot(backend=Backend.SNMP)
   over_web = switch.snapshot(backend=Backend.HTTP)
   assert over_snmp.vlans == over_web.vlans

This is exactly what the cross-backend equivalence tests do; see
``tests/test_cross_backend_equivalence.py``.

.. note::

   ``snapshot`` is the one place where an unsupported operation is swallowed
   rather than raised, because its job is "collect what this protocol can tell
   me". Every individual ``get_*`` call still raises. If you need to know
   *why* a field is empty, call the operation directly, or ask
   `netgear_switch.capabilities.support`.

Reading asynchronously
----------------------

.. code-block:: python

   import asyncio
   from netgear_switch import AsyncSwitch, get_model

   async def sweep(hosts: list[str]) -> None:
       switches = [
           AsyncSwitch(get_model("gsm7252ps"), host=h, snmp_community="public")
           for h in hosts
       ]
       try:
           for snap in await asyncio.gather(*(s.snapshot() for s in switches)):
               print(snap.host, len(snap.ports))
       finally:
           await asyncio.gather(*(s.aclose() for s in switches))

`AsyncSwitch` requires the ``[async]`` extra for SNMP (:pypi:`pysnmp`) and
``[http]`` for web-UI backends.

Handling refusals
-----------------

.. code-block:: python

   from netgear_switch import Backend, UnsupportedCapabilityError, support

   # Ask first — no network traffic:
   if support(switch.model, Backend.SNMP, "get_sensors").supported:
       print(switch.get_sensors(backend=Backend.SNMP))

   # Or act and handle the refusal, which names the backend that refused:
   try:
       switch.get_poe()
   except UnsupportedCapabilityError as exc:
       print(exc)

Capturing what a switch says
----------------------------

``ngsw capture`` writes a complete JSON record of a switch's readable state,
which is how this project's fixtures and mock seeds are produced:

.. code-block:: sh

   ngsw --switch core capture core-2026-07-31.json

See :doc:`../fake/internals` for how a capture becomes a mock.
