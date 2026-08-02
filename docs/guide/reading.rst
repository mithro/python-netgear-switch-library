Reading a switch
================

Every read below is available on :py:obj:`~netgear_switch.sync_api.SyncSwitch` and :py:obj:`~netgear_switch.aio_api.AsyncSwitch` alike, and each
takes an optional ``backend=``. They return frozen dataclasses from
`netgear_switch.models`, identical whichever protocol produced them.

The operations
--------------

.. list-table::
   :header-rows: 1
   :widths: 22 26 52

   * - Method
     - Returns
     - Notes
   * - :py:obj:`~netgear_switch.sync_api.SyncSwitch.get_ports`
     - ``list[PortStatus]``
     - Port number, ``ifName``, admin state, link state, speed in Mbit/s, and
       the operator-set description (``ifAlias``) where the backend can read
       one.
   * - :py:obj:`~netgear_switch.sync_api.SyncSwitch.get_stats`
     - ``list[PortStats]``
     - RX/TX bytes, packets and errors. Any counter a backend cannot read is
       ``None``, never zero.
   * - :py:obj:`~netgear_switch.sync_api.SyncSwitch.get_vlans`
     - ``list[VLANInfo]``
     - VLAN id, name, and three port sets: ``member_ports``, ``tagged_ports``,
       ``untagged_ports``.
   * - :py:obj:`~netgear_switch.sync_api.SyncSwitch.get_pvids`
     - ``list[tuple[int, int]]``
     - ``(port, vlan)`` pairs.
   * - :py:obj:`~netgear_switch.sync_api.SyncSwitch.get_lldp`
     - ``list[LLDPNeighbor]``
     - Local port plus the neighbour's system name, chassis id, port id and
       port description.
   * - :py:obj:`~netgear_switch.sync_api.SyncSwitch.get_macs`
     - ``list[MacEntry]``
     - The forwarding table: MAC, port, VLAN.
   * - :py:obj:`~netgear_switch.sync_api.SyncSwitch.get_poe`
     - ``list[PoEStatus]``
     - Admin state, detection state (:py:obj:`~netgear_switch.models.PoEDetect`) and delivered milliwatts.
   * - :py:obj:`~netgear_switch.sync_api.SyncSwitch.get_sensors`
     - ``list[Sensor]``
     - Fan, PSU and temperature readings with their units.
   * - :py:obj:`~netgear_switch.sync_api.SyncSwitch.get_mgmt_ip`
     - :py:obj:`~netgear_switch.models.MgmtIpConfig`
     - Address, netmask, gateway, DHCP-or-static mode, and the switch's base
       MAC.
   * - :py:obj:`~netgear_switch.sync_api.SyncSwitch.get_hostname`
     - ``str``
     - The switch's configured host name.
   * - :py:obj:`~netgear_switch.sync_api.SyncSwitch.get_users`
     - ``list[SwitchUser]``
     - Local login accounts. ``access_mode`` is the firmware's own wording —
       the images disagree (``Privilege-15`` vs ``Read/Write``) — with a
       normalised ``privileged`` flag beside it.
   * - :py:obj:`~netgear_switch.sync_api.SyncSwitch.get_services`
     - ``list[ServiceStatus]``
     - Whether http, https, telnet and ssh are enabled, and on which port
       where the firmware reports one.
   * - :py:obj:`~netgear_switch.sync_api.SyncSwitch.get_syslog`
     - :py:obj:`~netgear_switch.models.SyslogConfig`
     - Whether remote logging is on, the local source port, and the configured
       collectors.

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

:py:obj:`~netgear_switch.sync_api.SyncSwitch.identify` asks the switch what it actually is, over SNMP, ignoring
the model the facade was constructed with. That is the point: use it to confirm
or discover a model when you only have a host and a community.

.. tab-set::

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

         detected = switch.identify()
         if detected.matched and detected.key != switch.model.key:
             raise SystemExit(f"{switch.host} is really a {detected.key}")

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

         detected = await switch.identify()
         if detected.matched and detected.key != switch.model.key:
             raise SystemExit(f"{switch.host} is really a {detected.key}")

Matching prefers ``sysObjectID`` — an unambiguous product identifier that can
distinguish SKUs whose ``sysDescr`` text is identical — and falls back to
``sysDescr``. ``key`` is ``None`` when neither matched; it is never a guess.

:py:obj:`~netgear_switch.sync_api.SyncSwitch.nsdp_device` returns the complete raw NSDP device record for a Plus
switch: firmware, serial, DHCP mode, VLAN engine, port mirroring, IGMP snooping
and the unconverted per-port fields. It is NSDP-only by nature and bypasses
backend dispatch.

Snapshots
---------

:py:obj:`~netgear_switch.sync_api.SyncSwitch.snapshot` runs every read over **one** backend and returns a
:py:obj:`~netgear_switch.models.SwitchData`:

.. tab-set::

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

         snap = switch.snapshot()
         print(snap.model, snap.host, len(snap.ports), len(snap.vlans))

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

         snap = await switch.snapshot()
         print(snap.model, snap.host, len(snap.ports), len(snap.vlans))

Fields the backend cannot serve degrade to ``()`` or ``None``. They are *not*
re-read over another protocol — so a snapshot describes what one protocol
really reports, rather than a blend of several. To compare protocols, take two
snapshots:

.. tab-set::

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

         from netgear_switch import Backend

         over_snmp = switch.snapshot(backend=Backend.SNMP)
         over_web = switch.snapshot(backend=Backend.HTTP)
         assert over_snmp.vlans == over_web.vlans

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

         from netgear_switch import Backend

         over_snmp = await switch.snapshot(backend=Backend.SNMP)
         over_web = await switch.snapshot(backend=Backend.HTTP)
         assert over_snmp.vlans == over_web.vlans

The cross-backend equivalence tests do exactly this; see
``tests/test_cross_backend_equivalence.py``.

.. note::

   ``snapshot`` is the one place where an unsupported operation is swallowed
   rather than raised, because its job is "collect what this protocol can tell
   me". Every individual ``get_*`` call still raises. If you need to know
   *why* a field is empty, call the operation directly, or ask
   `netgear_switch.capabilities.support`.

Reading a fleet
---------------

Here the two APIs stop being interchangeable: the asynchronous facade reads
every switch at once, the synchronous one reads them in turn.

.. tab-set::

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

         from netgear_switch import SyncSwitch, get_model

         def sweep(hosts: list[str]) -> None:
             for host in hosts:
                 switch = SyncSwitch(
                     get_model("gsm7252ps"), host=host, snmp_community="public"
                 )
                 snap = switch.snapshot()
                 print(snap.host, len(snap.ports))

   .. tab-item:: Async
      :sync: async

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

:py:class:`~netgear_switch.aio_api.AsyncSwitch` requires the ``[async]`` extra for SNMP
(:pypi:`pysnmp`) and ``[http]`` for web-UI backends.

Handling refusals
-----------------

.. tab-set::

   .. tab-item:: Sync
      :sync: sync

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

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

         from netgear_switch import Backend, UnsupportedCapabilityError, support

         # support() is a plain function — the question needs no switch and no await.
         if support(switch.model, Backend.SNMP, "get_sensors").supported:
             print(await switch.get_sensors(backend=Backend.SNMP))

         # Or act and handle the refusal, which names the backend that refused:
         try:
             await switch.get_poe()
         except UnsupportedCapabilityError as exc:
             print(exc)

Capturing what a switch says
----------------------------

``ngsw capture`` writes a complete JSON record of a switch's readable state.
This project's fixtures and mock seeds are produced with it:

.. code-block:: sh

   ngsw --switch core capture core-2026-07-31.json

See :doc:`../fake/internals` for how a capture becomes a mock.
