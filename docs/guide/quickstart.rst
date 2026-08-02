Quickstart
==========

Everything in the first section runs without a switch: the library ships
faithful mock switches, and the example points at one.

.. tip::

   Every example below appears in **synchronous** and **asynchronous** form.
   Choosing one switches every example on the page, and the choice is
   remembered as you move around the site.
   :py:class:`~netgear_switch.sync_api.SyncSwitch` and
   :py:class:`~netgear_switch.aio_api.AsyncSwitch` expose the same operations with the
   same arguments; only the transports differ.

Talk to a mock in-process
-------------------------

:py:class:`~netgear_switch.virtual.server.VirtualSwitch` binds real sockets, so
the facade reaches it exactly the way it reaches hardware — same transport, same
parsers, same code path. Only the address differs.

.. tab-set::

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

         from netgear_switch import SyncSwitch, get_model
         from netgear_switch.transport.sync.snmp_netsnmp_cli import NetsnmpCliClient
         from netgear_switch.virtual.server import VirtualSwitch

         with VirtualSwitch(model="gsm7252ps") as mock:
             switch = SyncSwitch(
                 get_model("gsm7252ps"),
                 host=mock.host,
                 # The mock binds an ephemeral port; net-snmp takes it as host:port.
                 snmp_client=NetsnmpCliClient(f"{mock.host}:{mock.port}", "public"),
             )
             for port in switch.get_ports()[:4]:
                 print(port.port, port.link_up, port.speed_mbps)
             print(switch.get_mgmt_ip())

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

         import asyncio

         from netgear_switch import AsyncSwitch, get_model
         from netgear_switch.transport.aio.snmp_pysnmp import PysnmpClient
         from netgear_switch.virtual.server import VirtualSwitch

         async def main() -> None:
             with VirtualSwitch(model="gsm7252ps") as mock:
                 switch = AsyncSwitch(
                     get_model("gsm7252ps"),
                     host=mock.host,
                     # pysnmp takes the mock's ephemeral port as a keyword.
                     snmp_client=PysnmpClient(mock.host, "public", port=mock.port),
                 )
                 try:
                     for port in (await switch.get_ports())[:4]:
                         print(port.port, port.link_up, port.speed_mbps)
                     print(await switch.get_mgmt_ip())
                 finally:
                     await switch.aclose()

         asyncio.run(main())

Either way:

.. code-block:: text

   1 True 1000
   2 True 1000
   3 True 1000
   4 True 1000
   MgmtIpConfig(mode=<IpMode.STATIC: 'static'>, address='10.1.5.22',
                netmask='255.255.255.0', gateway='10.1.5.1',
                base_mac='E0:91:F5:0C:D6:DB')

That output is real GSM7252PS data: the mock is seeded from a capture of the
switch at 10.1.5.22, not from invented values. See :doc:`../fake/index`.

Talk to a real switch
---------------------

The first argument is a :py:class:`~netgear_switch.registry.SwitchModel`, which
:py:func:`~netgear_switch.registry.get_model` resolves from a registry key (``ngsw
models`` lists them all).

.. tab-set::

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

         from netgear_switch import SyncSwitch, get_model

         switch = SyncSwitch(
             get_model("gsm7252ps"), host="10.1.5.22", snmp_community="public"
         )

         for vlan in switch.get_vlans():
             print(vlan.vlan_id, vlan.name, sorted(vlan.untagged_ports))

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

         from netgear_switch import AsyncSwitch, get_model

         switch = AsyncSwitch(
             get_model("gsm7252ps"), host="10.1.5.22", snmp_community="public"
         )
         try:
             for vlan in await switch.get_vlans():
                 print(vlan.vlan_id, vlan.name, sorted(vlan.untagged_ports))
         finally:
             await switch.aclose()

If you do not know the model, ask the switch:

.. tab-set::

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

         from netgear_switch import detect_model

         detected = detect_model("10.1.5.22", community="public")
         print(detected.key, detected.sys_descr)

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

         from netgear_switch import async_detect_model

         detected = await async_detect_model("10.1.5.22", community="public")
         print(detected.key, detected.sys_descr)

For anything beyond a one-off, put the host and its credentials in an
inventory file instead of in code — see :doc:`configuration`.

Choose the protocol
-------------------

Every read and write takes an optional ``backend=``. Name one and that protocol
runs; leave it out and the model's default is used. Neither case ever falls
back to another protocol — see :doc:`concepts`.

.. tab-set::

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

         from netgear_switch import Backend

         over_snmp = switch.get_vlans(backend=Backend.SNMP)
         over_web = switch.get_vlans(backend=Backend.HTTP)
         over_cli = switch.get_vlans(backend=Backend.SSH)

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

         from netgear_switch import Backend

         over_snmp = await switch.get_vlans(backend=Backend.SNMP)
         over_web = await switch.get_vlans(backend=Backend.HTTP)

         # No CLI here: the CLI transports are blocking, so the async facade
         # has no SSH/telnet/console backend. Use SyncSwitch, or:
         #   await asyncio.to_thread(sync_switch.get_vlans, backend=Backend.SSH)

That the three agree is asserted, not assumed —
``tests/test_cross_backend_equivalence.py`` compares them for every model with
more than one backend. They agree on the *physical* ports; SNMP also reports
internal and link-aggregation interfaces that a web UI's port table does not
list, and one model has a VLAN where SNMP shows configured members and the
web UI shows current ones. Both are real properties of the interfaces, and the
tests pin them explicitly rather than papering over them.

Ask before you act
------------------

:py:mod:`netgear_switch.capabilities` answers "can this model do this, over
that?" without touching the switch. It is the same data that generates
:doc:`../models/support`, exposed as a plain function — nothing to await.

.. code-block:: python

   from netgear_switch import Backend, support

   print(support("m4300-24x", Backend.SNMP, "get_poe"))

.. code-block:: text

   Capability(model_key='m4300-24x', backend=<Backend.SNMP: 'snmp'>,
              operation=Operation(name='get_poe', kind=<OperationKind.READ: 'read'>,
                                  summary='Per-port PoE status and power draw',
                                  backends=None),
              support=<Support.UNSUPPORTED: 'unsupported'>,
              reason='M4300-24X (XSM4324CS) has no PSE ports, so it has no PoE '
                     'to report or set')

Write something
---------------

Disruptive operations require ``force=True``, and every write reads back to
confirm it landed:

.. tab-set::

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

         from netgear_switch import VlanMode

         switch.create_vlan(4001, "throwaway", force=True)
         switch.set_vlan_membership(4001, port=7, mode=VlanMode.UNTAGGED, force=True)
         switch.set_pvid(7, 4001, force=True)

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

         from netgear_switch import VlanMode

         await switch.create_vlan(4001, "throwaway", force=True)
         await switch.set_vlan_membership(
             4001, port=7, mode=VlanMode.UNTAGGED, force=True
         )
         await switch.set_pvid(7, 4001, force=True)

See :doc:`writing` for the safety rails, for what a refusal means, and for the
rules this project follows when testing writes against live hardware.

Sweep a fleet
-------------

Concurrency is where the two APIs genuinely differ: the async facade talks to a
whole inventory at once.

.. tab-set::

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

         from netgear_switch import SyncSwitch, get_model

         for host in ("10.1.5.22", "10.1.5.13", "10.1.5.11"):
             switch = SyncSwitch(
                 get_model("gsm7252ps"), host=host, snmp_community="public"
             )
             snap = switch.snapshot()
             print(snap.host, len(snap.ports), len(snap.vlans))

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

         import asyncio

         from netgear_switch import AsyncSwitch, get_model

         switches = [
             AsyncSwitch(get_model("gsm7252ps"), host=h, snmp_community="public")
             for h in ("10.1.5.22", "10.1.5.13", "10.1.5.11")
         ]
         try:
             for snap in await asyncio.gather(*(s.snapshot() for s in switches)):
                 print(snap.host, len(snap.ports), len(snap.vlans))
         finally:
             await asyncio.gather(*(s.aclose() for s in switches))

From the command line
---------------------

.. code-block:: sh

   ngsw --host 10.1.5.22 --model gsm7252ps --community public ports
   ngsw --host 10.1.5.22 --model gsm7252ps --community public vlans --json
   ngsw --host 10.1.5.22 --model gsm7252ps --backend http vlans

The complete reference is :doc:`../cli`.

Where to go next
----------------

* :doc:`concepts` — models, backends, and why nothing falls back.
* :doc:`configuration` — inventories and credentials kept out of your code.
* :doc:`../fake/testing` — test *your* tool against a switch you cannot break.
