MCP server
==========

``ngsw-mcp`` exposes the library as `Model Context Protocol
<https://modelcontextprotocol.io>`_ tools over stdio, so an LLM-driven client
can inspect — and, if you let it, reconfigure — your switches.

.. code-block:: sh

   pip install 'python-netgear-switch-library[mcp]'
   ngsw-mcp

Configuring a client
--------------------

.. code-block:: json

   {
     "mcpServers": {
       "netgear": {
         "command": "ngsw-mcp",
         "env": {
           "NGSW_INVENTORY": "/etc/ngsw/inventory.toml"
         }
       }
     }
   }

Every tool resolves its target switch through the **same resolver the CLI uses**
— either a named switch from a TOML inventory (``switch=`` plus ``config=``, or
``$NGSW_INVENTORY`` for the path), or an ad-hoc ``host=`` and ``model=`` pair,
with credentials layered from arguments, environment and inventory. See
:doc:`guide/configuration`.

.. note::

   ``$NGSW_INVENTORY`` is an MCP-server convenience — an MCP client has no
   command line to pass ``--config`` on. The ``ngsw`` CLI requires ``--config``
   explicitly.

Read tools
----------

Registered unconditionally.

.. list-table::
   :header-rows: 1
   :widths: 26 74

   * - Tool
     - Returns
   * - ``list_switches``
     - The switches in the configured inventory.
   * - ``identify``
     - The switch's real model, from ``sysObjectID`` and ``sysDescr``.
   * - ``get_ports``
     - Per-port link status and speed.
   * - ``get_stats``
     - Per-port byte and packet counters.
   * - ``get_vlans``
     - VLANs with member, tagged and untagged ports.
   * - ``get_pvids``
     - Per-port PVID.
   * - ``get_macs``
     - The MAC/FDB table.
   * - ``get_lldp``
     - LLDP neighbours.
   * - ``get_sensors``
     - Fan, temperature and PSU sensors.
   * - ``get_poe``
     - Per-port PoE status and delivered power.
   * - ``get_mgmt_ip``
     - Management IP configuration and base MAC.
   * - ``snapshot``
     - Every read at once, over one backend.
   * - ``get_device``
     - The complete raw NSDP device record (Plus switches).

Results are the library's own dataclasses serialised to plain JSON.

Write tools
-----------

**Only registered when** ``NGSW_MCP_ALLOW_WRITES`` **is truthy.** They do not
exist otherwise — a model cannot call a tool that was never advertised.

.. code-block:: sh

   NGSW_MCP_ALLOW_WRITES=1 ngsw-mcp

``set_port_enabled``, ``set_poe``, ``cycle_poe``, ``clear_poe_fault``,
``set_pvid``, ``set_vlan_membership``, ``create_vlan``, ``delete_vlan``,
``set_mgmt_ip``, ``upload_certificate``, ``upload_certificate_scp``.

Even with writes enabled, each disruptive operation requires the caller to pass
``force=true`` — the same rail the library and the CLI enforce — and
``protected_ports`` from the inventory still applies.

.. warning::

   An MCP tool call is model-initiated. Reconfiguring a live switch is
   destructive and can cut you off from the device that carries your management
   traffic. Enable writes deliberately, and put your uplinks in
   ``protected_ports`` first.

Choosing a backend
------------------

Every read and write tool takes an optional ``backend`` argument
(``snmp``/``nsdp``/``http``/``ssh``/``telnet``/``console``), with the same
meaning as everywhere else: that protocol runs, or the call fails. An unknown
name is a :py:obj:`~netgear_switch.errors.ConfigError` rather than a silent default.

The two certificate-upload tools deliberately do **not** take one — their
transport is intrinsic to the operation.

Honest refusals
---------------

An operation a model's backend genuinely cannot serve returns a structured
result rather than an exception or, worse, plausible-looking data:

.. code-block:: json

   {
     "unsupported": true,
     "op": "get_poe",
     "detail": "model 'gs110emx': the default backend NSDP cannot serve this operation: NSDP has no PoE status tag ..."
   }

Any other library error becomes ``{"error": "...", "op": "..."}``, so the client
sees a clean message rather than a stack trace. Both carry the library's rule
through: nothing is fabricated, and nothing is quietly answered over a different
protocol.

Implementation
--------------

See :doc:`api/mcp`. The server is built on FastMCP; its tool surface is tested
in ``tests/test_mcp_server.py``.
