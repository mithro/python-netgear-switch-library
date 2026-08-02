Protocols
=========

Four backends, one operation surface. Each page below covers what a protocol
amounts to on these devices, what the library does with it, and the quirks worth
weighing when you pick one.

.. toctree::
   :maxdepth: 2

   snmp
   nsdp
   http
   cli

Shape of the code
-----------------

Each protocol is split the same way, which is worth knowing before you read the
source:

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - Layer
     - Responsibility
   * - ``protocols/<name>/``
     - Pure protocol knowledge: OIDs, packet formats, page URLs, command
       strings, and parsers. No I/O, no sockets — which is why almost all of it
       can be tested against captured bytes.
   * - ``transport/``
     - Getting bytes to and from a device: ``transport/sync/`` and
       ``transport/aio/`` for SNMP and NSDP, ``transport/http/`` for the web UI,
       ``transport/cli/`` for SSH, telnet and the serial console.
   * - ``<name>_read.py`` / ``<name>_write.py``
     - The model-driven operations, mapping a facade call to this protocol's
       mechanism for this model.
   * - ``virtual/faces/``
     - The other side of the same wire: a mock switch answering the protocol
       for real. See :doc:`../fake/index`.

The facades in ``src/netgear_switch/sync_api.py`` and
``src/netgear_switch/aio_api.py`` sit on top and choose exactly one backend per
operation — see :doc:`../guide/concepts`.

Choosing a backend
------------------

.. list-table::
   :header-rows: 1
   :widths: 14 34 52

   * - Backend
     - Best for
     - Watch out for
   * - SNMP
     - Bulk reads, monitoring, anything scripted. The richest data source on
       managed switches.
     - Write access is often restricted, and an unauthorised request is
       *silently dropped* rather than refused.
   * - NSDP
     - Plus switches, where it is one of only two options. Also discovery.
     - Broadcast-based, so the sending interface matters. No PoE, MAC table,
       LLDP or sensors.
   * - HTTP
     - Reaching a switch through a firewall that only allows the web port, and
       PoE control on Plus switches.
     - Sessions expire; page sets vary widely between models.
       |dialect-count| distinct page dialects across this fleet.
   * - CLI
     - FASTPATH switches when you want the switch's own view, and the only
       route for ``copy scp://`` certificate deployment.
     - One TCP round trip per command; per-port statistics need one command
       per port.
