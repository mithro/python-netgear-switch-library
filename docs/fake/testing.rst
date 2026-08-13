Testing against the fake
========================

Worked examples of pointing your own code — or somebody else's tool — at a mock
switch. Every snippet on this page was executed against the mocks; the output
shown is what they actually printed.

Two ways in:

**In-process** (this page, mostly). Construct a
`netgear_switch.virtual.server.VirtualSwitch`, read the port it bound, and
connect. Fast, no subprocess, no port collisions — the mocks bind ephemeral
ports by default.

**As a daemon.** ``ngsw serve`` for tools that are not Python. See
:doc:`serving`.

A pytest fixture
----------------

.. code-block:: python

   # conftest.py
   from collections.abc import Iterator

   import pytest
   from netgear_switch.virtual.server import VirtualSwitch


   @pytest.fixture
   def switch_mock() -> Iterator[VirtualSwitch]:
       """A seeded GSM7252PS on ephemeral ports, stopped even if the test fails."""
       mock = VirtualSwitch(model="gsm7252ps")
       mock.start()
       try:
           yield mock
       finally:
           mock.stop()

:py:obj:`~netgear_switch.virtual.server.VirtualSwitch` is also a context manager, which is usually enough:

.. code-block:: python

   with VirtualSwitch(model="gsm7252ps") as mock:
       ...

After ``start()``, ``mock.port`` is the bound UDP port (SNMP *or* NSDP,
whichever the model has) and ``mock.http_port`` the bound TCP port.
``mock.bound_endpoints`` lists what actually came up.

Testing code that uses this library
-----------------------------------

Inject a client pointed at the mock. Everything above the transport — dispatch,
parsing, model rules — is the same code that runs against hardware.

.. tab-set::

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

         from netgear_switch import SyncSwitch, get_model
         from netgear_switch.transport.sync.snmp_netsnmp_cli import NetsnmpCliClient
         from netgear_switch.virtual.server import VirtualSwitch


         def test_reports_link_state() -> None:
             with VirtualSwitch(model="gsm7252ps") as mock:
                 switch = SyncSwitch(
                     get_model("gsm7252ps"),
                     host=mock.host,
                     snmp_client=NetsnmpCliClient(
                         f"{mock.host}:{mock.port}", "public"
                     ),
                 )
                 assert switch.get_ports()[0].link_up

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

         import pytest

         from netgear_switch import AsyncSwitch, get_model
         from netgear_switch.transport.aio.snmp_pysnmp import PysnmpClient
         from netgear_switch.virtual.server import VirtualSwitch


         @pytest.mark.asyncio
         async def test_reports_link_state() -> None:
             with VirtualSwitch(model="gsm7252ps") as mock:
                 switch = AsyncSwitch(
                     get_model("gsm7252ps"),
                     host=mock.host,
                     snmp_client=PysnmpClient(mock.host, "public", port=mock.port),
                 )
                 try:
                     assert (await switch.get_ports())[0].link_up
                 finally:
                     await switch.aclose()

.. code-block:: text

   PortStatus(port=1, name='1/0/1', admin_enabled=True, link_up=True,
              speed_mbps=1000, description='eth0.rpi5-pmod')

Every backend takes an injected client:

.. list-table::
   :header-rows: 1
   :widths: 22 78

   * - Backend
     - Constructor argument
   * - SNMP
     - sync: ``snmp_client=NetsnmpCliClient(f"{host}:{port}", community)``;
       async: ``snmp_client=PysnmpClient(host, community, port=mock.port)``.
       Add ``snmp_write_client=`` for writes.
   * - NSDP
     - sync: ``nsdp_client=UdpNsdpClient(host, client_port=0, server_port=mock.port)``;
       async: the same arguments to ``AsyncUdpNsdpClient``.
   * - HTTP
     - sync: ``http_client=HttpClient(f"{host}:{http_port}", password, http_spec(model))``;
       async: the same arguments to ``AsyncHttpClient``.
   * - CLI
     - ``cli_client=mock.cli_session()`` — **synchronous only**. The CLI
       transports block, so :py:class:`~netgear_switch.aio_api.AsyncSwitch` has no CLI
       backend and takes no ``cli_client``.

All three at once
-----------------

One mock, one facade, three protocols — SNMP, the web UI and the FASTPATH CLI
answering the same question. This is what makes cross-backend behaviour
testable without hardware:

.. tab-set::

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

         from netgear_switch import Backend, SyncSwitch, get_model
         from netgear_switch.protocols.http.endpoints import http_spec
         from netgear_switch.transport.http.client import HttpClient
         from netgear_switch.transport.sync.snmp_netsnmp_cli import NetsnmpCliClient
         from netgear_switch.virtual.server import VirtualSwitch

         model = get_model("gsm7252ps")
         with VirtualSwitch(model="gsm7252ps") as mock:
             switch = SyncSwitch(
                 model,
                 host=mock.host,
                 snmp_client=NetsnmpCliClient(f"{mock.host}:{mock.port}", "public"),
                 http_client=HttpClient(
                     f"{mock.host}:{mock.http_port}", "password", http_spec(model)
                 ),
                 cli_client=mock.cli_session(),
             )
             snmp = switch.get_vlans(backend=Backend.SNMP)
             http = switch.get_vlans(backend=Backend.HTTP)
             cli = switch.get_vlans(backend=Backend.SSH)

             assert {v.vlan_id for v in snmp} == {v.vlan_id for v in http} \
                 == {v.vlan_id for v in cli}

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

         from netgear_switch import AsyncSwitch, Backend, get_model
         from netgear_switch.protocols.http.endpoints import http_spec
         from netgear_switch.transport.aio.snmp_pysnmp import PysnmpClient
         from netgear_switch.transport.http.client import AsyncHttpClient
         from netgear_switch.virtual.server import VirtualSwitch

         model = get_model("gsm7252ps")
         with VirtualSwitch(model="gsm7252ps") as mock:
             switch = AsyncSwitch(
                 model,
                 host=mock.host,
                 snmp_client=PysnmpClient(mock.host, "public", port=mock.port),
                 http_client=AsyncHttpClient(
                     f"{mock.host}:{mock.http_port}", "password", http_spec(model)
                 ),
                 # No cli_client: the async facade has no CLI backend.
             )
             try:
                 snmp = await switch.get_vlans(backend=Backend.SNMP)
                 http = await switch.get_vlans(backend=Backend.HTTP)

                 assert {v.vlan_id for v in snmp} == {v.vlan_id for v in http}
             finally:
                 await switch.aclose()

.. code-block:: text

   [1, 4, 5, 6, 7, 10, 20, 21, 41, 89, 90, 99, 121, 141]   # identical on all three

.. note::

   Compare VLAN *ids* freely; compare membership with care. SNMP reports
   internal and link-aggregation interfaces (here, ifIndexes 418 and above)
   that the web UI's port table does not list, and this model's VLAN 1 has two
   ports SNMP shows as *configured* members while the web UI shows *current*
   ones. Both are genuine properties of the two management interfaces, not mock
   artefacts — ``tests/test_cross_backend_equivalence.py`` restricts to physical
   ports and pins the known difference explicitly rather than hiding it.

The CLI, with no SSH server
---------------------------

The CLI face is in-process and implements the ``CliSession`` protocol directly,
so there is no key exchange, no terminal emulation, and nothing to time out:

.. code-block:: python

   with VirtualSwitch(model="gsm7252ps") as mock:
       session = mock.cli_session()
       print(session.run("show vlan brief"))

Pass the same object as ``cli_client=`` to exercise the whole facade over the
CLI backend.

Testing that your code handles refusals
---------------------------------------

The *failure* paths are the most valuable thing a faithful mock gives you. The
mock refuses exactly what the hardware refuses, with the same message:

.. tab-set::

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

         from netgear_switch import SyncSwitch, UnsupportedCapabilityError, get_model
         from netgear_switch.transport.sync.nsdp_udp import UdpNsdpClient
         from netgear_switch.virtual.server import VirtualSwitch

         with VirtualSwitch(model="gs110emx") as mock:
             switch = SyncSwitch(
                 get_model("gs110emx"),
                 host=mock.host,
                 nsdp_client=UdpNsdpClient(
                     mock.host, client_port=0, server_port=mock.port, timeout=2.0
                 ),
             )
             try:
                 switch.get_poe()
             except UnsupportedCapabilityError as exc:
                 print(exc)

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

         from netgear_switch import AsyncSwitch, UnsupportedCapabilityError, get_model
         from netgear_switch.transport.aio.nsdp_udp import AsyncUdpNsdpClient
         from netgear_switch.virtual.server import VirtualSwitch

         with VirtualSwitch(model="gs110emx") as mock:
             switch = AsyncSwitch(
                 get_model("gs110emx"),
                 host=mock.host,
                 nsdp_client=AsyncUdpNsdpClient(
                     mock.host, client_port=0, server_port=mock.port, timeout=2.0
                 ),
             )
             try:
                 await switch.get_poe()
             except UnsupportedCapabilityError as exc:
                 print(exc)
             finally:
                 await switch.aclose()

.. code-block:: text

   model 'gs110emx': the default backend NSDP cannot serve this operation:
   NSDP has no PoE status tag (measured by an exhaustive NSDP tag sweep of a
   real GS110EMX ...)

Use `netgear_switch.capabilities` to enumerate what to test, instead of
hard-coding a list that will drift:

.. code-block:: python

   from netgear_switch.capabilities import READ_OPERATIONS, backends_for, support

   for backend in backends_for("gs110emx"):
       print(backend.name, [
           op.name for op in READ_OPERATIONS if support("gs110emx", backend, op).supported
       ])

.. code-block:: text

   NSDP ['get_ports', 'get_stats', 'get_vlans', 'get_pvids', 'get_mgmt_ip', 'nsdp_device']
   HTTP ['get_ports', 'get_stats', 'get_vlans', 'get_pvids', 'get_mgmt_ip']

Testing writes
--------------

Writes mutate the mock's state, and the change is visible over every protocol —
because all the faces serve one state, exactly as one switch has one
configuration:

.. code-block:: python

   client = NetsnmpCliClient(f"{mock.host}:{mock.port}", "public")
   switch = SyncSwitch(
       model, host=mock.host,
       snmp_client=client, snmp_write_client=client,
       http_client=HttpClient(
           f"{mock.host}:{mock.http_port}", "password", http_spec(model)
       ),
   )

   before = next(p for p in switch.get_ports() if p.port == 5)
   switch.set_port_enabled(5, not before.admin_enabled, force=True)

   assert not next(p for p in switch.get_ports() if p.port == 5).admin_enabled
   assert not next(
       p for p in switch.get_ports(backend=Backend.HTTP) if p.port == 5
   ).admin_enabled          # the web UI sees the SNMP write

.. code-block:: text

   admin before / after over SNMP / after over HTTP:  True False False

Crafting a scenario
-------------------

``VirtualSwitch.state`` is an ordinary mutable dataclass. Edit it to produce the
condition you want to test — a dead link, a PoE fault, a full MAC table:

.. code-block:: python

   import dataclasses
   from netgear_switch.virtual.server import VirtualSwitch

   mock = VirtualSwitch(model="gsm7252ps")
   mock.state.ports[1] = dataclasses.replace(mock.state.ports[1], link=False, speed=0)
   mock.start()
   try:
       ...   # port 1 now reports link down on every backend
   finally:
       mock.stop()

.. important::

   **Mutate before** ``start()``. The SNMP face builds a sorted OID view when it
   binds, so a direct edit to ``state`` after ``start()`` is picked up by the
   HTTP, NSDP and CLI faces — which read the state live — but **not** by SNMP.
   Writes performed *through* a protocol rebuild the view and are consistent
   everywhere; only out-of-band edits need to happen first.

Testing model detection
-----------------------

The mocks carry the real ``sysDescr`` and ``sysObjectID`` from captures, so
identification is testable end to end — including the case where you connect
with the wrong model:

.. code-block:: python

   with VirtualSwitch(model="gsm7228ps") as mock:
       switch = SyncSwitch(
           get_model("gsm7252ps"),          # deliberately wrong
           host=mock.host,
           snmp_client=NetsnmpCliClient(f"{mock.host}:{mock.port}", "public"),
       )
       print(switch.identify())          # await switch.identify() on AsyncSwitch

.. code-block:: text

   DetectedModel(key='gsm7228ps',
                 sys_descr='S3300-52X-PoE+ ProSAFE 48-Port Gigabit Stackable
                            Smart Switch with PoE+ and 4 10G uplinks',
                 sys_object_id='1.3.6.1.4.1.4526.100.10.19')

Identification came from ``sysObjectID`` — the only way to tell this SKU apart
from the S3300-28X, whose ``sysDescr`` text is indistinguishable.

Testing tools that are not this library
---------------------------------------

The faces are real servers, so anything that speaks the protocol works. Start
the mock in-process and drive your tool as a subprocess:

.. code-block:: python

   import subprocess
   from netgear_switch.virtual.server import VirtualSwitch

   with VirtualSwitch(model="gsm7228ps") as mock:
       out = subprocess.run(
           ["snmpget", "-v2c", "-c", "public",
            f"{mock.host}:{mock.port}", "1.3.6.1.2.1.1.1.0"],
           capture_output=True, text=True, check=True,
       )
       print(out.stdout.strip())

.. code-block:: text

   iso.3.6.1.2.1.1.1.0 = STRING: "S3300-52X-PoE+ ProSAFE 48-Port Gigabit
   Stackable Smart Switch with PoE+ and 4 10G uplinks"

For a tool you cannot start from Python, run ``ngsw serve --port N`` with a
pinned port and point the tool's configuration at it — see :doc:`serving`.

Testing a monitoring integration
--------------------------------

A common case: your exporter or check script takes a host and a community.

.. code-block:: python

   import pytest
   from netgear_switch.virtual.server import VirtualSwitch

   from my_exporter import collect          # your code


   @pytest.mark.parametrize("model", ["gsm7252ps", "gsm7228ps", "m4300-24x"])
   def test_exporter_handles_every_model(model: str) -> None:
       with VirtualSwitch(model=model) as mock:
           metrics = collect(host=f"{mock.host}:{mock.port}", community="public")
           assert metrics["ports_up"] >= 0

Parametrising over models is where the fake earns its keep: the M4300-24X has no
PoE at all, the GS728TPP has no vendor OIDs, and the S3300 answers to a different
vendor subtree. Code written against a single switch tends to assume all three
away.

Choosing a model to test against
--------------------------------

.. list-table::
   :header-rows: 1
   :widths: 20 80

   * - Model
     - Good for exercising
   * - ``gsm7252ps``
     - The widest backend coverage: SNMP, HTTP and CLI all verified. Start here.
   * - ``gsm7228ps``
     - A different SNMP vendor subtree, ``sysObjectID`` identification, telnet
       on a non-standard port, and split-PDU VLAN writes.
   * - ``m4300-24x``
     - A switch with **no PoE at all** — the refusal path on every backend — and
       the vendor-switchport VLAN-write dialect.
   * - ``gs110emx``
     - A Plus switch: NSDP plus a web UI, no SNMP, no MAC table, no LLDP, no
       sensors.
   * - ``gs305ep``
     - PoE that is available over HTTP but not over NSDP — the clearest case for
       naming a backend.
   * - ``gs728tpp``
     - An SNMP agent with **no vendor OIDs**, standard MIBs only, and the GoAhead
       XML web API.

Known deviations
----------------

Documented rather than hidden, because knowing them is what makes the rest
trustworthy:

* **Session handling is permissive over HTTP.** The face validates the login
  POST and reproduces the M4300's ``Referer`` CSRF check, but does not require a
  session for ordinary page ``GET``\ s. Real firmware does.
* **Out-of-band state edits after** ``start()`` **are invisible to SNMP.** See
  the note above.
* **The CLI face is in-process.** No SSH or telnet listener exists to test a
  transport against; it exercises the command surface, not the connection.
* **Not every page of a real web UI exists** — only the pages the library uses.

If you find a divergence beyond these, it is a bug in the mock, and the project
treats it that way: the mock gets fixed, never the expectation.
