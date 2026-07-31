python-netgear-switch-library
=============================

Query and control Netgear switches — Fully Managed, Smart Managed Pro and Plus —
over **SNMP**, **NSDP**, the **HTTP web UI** and the **FASTPATH CLI**, behind one
model-driven Python API, the ``ngsw`` command-line tool, and an MCP server.

.. code-block:: python

   from netgear_switch import SyncSwitch, Backend

   switch = SyncSwitch(host="10.1.5.22", model="gsm7252ps", community="public")

   for port in switch.get_ports():
       print(port.port, port.link_up, port.speed_mbps)

   # Name a backend and that is the protocol that runs. Nothing else.
   vlans = switch.get_vlans(backend=Backend.HTTP)

What makes this library different
---------------------------------

**One request, one protocol.** Ask for SNMP and you get SNMP, or an error
naming what failed. The facade never retries an operation over a different
backend, because a result that silently arrived over HTTP makes every claim
about SNMP worthless. See :doc:`guide/concepts`.

**Backends are interchangeable by design.** Where a switch offers SNMP, a web
UI and a CLI, all three implement the same operations, so the *caller* chooses —
useful when SNMP writes are locked down, or when only the web UI is reachable
through a firewall. Where a gap remains, it is listed in
:doc:`models/support`, not hidden.

**Every claim is measured.** Model behaviour in this library comes from
captured traffic and live runs against real hardware, recorded with the host and
firmware version it was observed on. Where a device refuses something, the
refusal is reproduced — including its error code and its ordering requirements —
by the :doc:`virtual switch <fake/index>`, so the behaviour can be tested
without hardware and cannot regress unnoticed.

**A faithful fake ships with the library.** ``ngsw serve`` runs mock switches on
real sockets: point ``snmpwalk``, a monitoring agent, or your own code at one.
See :doc:`fake/testing` for worked examples.

Start here
----------

* :doc:`guide/installation` — pip, apt, and the net-snmp system dependency.
* :doc:`guide/quickstart` — a first read, against a mock, in under a minute.
* :doc:`models/support` — which model can do what, over which protocol.
* :doc:`cli` — the complete ``ngsw`` reference.

.. toctree::
   :maxdepth: 2
   :caption: Guide
   :hidden:

   guide/installation
   guide/quickstart
   guide/concepts
   guide/configuration
   guide/reading
   guide/writing
   guide/principles

.. toctree::
   :maxdepth: 2
   :caption: Switches
   :hidden:

   models/index
   models/support
   protocols/index

.. toctree::
   :maxdepth: 2
   :caption: Tools
   :hidden:

   cli
   mcp

.. toctree::
   :maxdepth: 2
   :caption: The virtual switch
   :hidden:

   fake/index
   fake/serving
   fake/testing
   fake/internals

.. toctree::
   :maxdepth: 2
   :caption: API reference
   :hidden:

   api/index

.. toctree::
   :maxdepth: 1
   :caption: Project
   :hidden:

   development

Indices
-------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
