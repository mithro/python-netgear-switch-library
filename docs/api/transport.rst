Transports
==========

Getting bytes to and from a device. Each transport satisfies a client protocol
defined in the protocol layer, so a reader or writer works unchanged across
them — and equally against a mock.

These are also the classes you construct by hand to point the library at a
:doc:`virtual switch <../fake/testing>`.

.. automodule:: netgear_switch.transport
   :no-members:

Synchronous
-----------

.. automodule:: netgear_switch.transport.sync

.. automodule:: netgear_switch.transport.sync.snmp_netsnmp_cli

.. automodule:: netgear_switch.transport.sync.nsdp_udp

Asynchronous
------------

.. automodule:: netgear_switch.transport.aio

.. automodule:: netgear_switch.transport.aio.snmp_pysnmp

.. automodule:: netgear_switch.transport.aio.nsdp_udp

HTTP
----

.. automodule:: netgear_switch.transport.http

.. automodule:: netgear_switch.transport.http.client

CLI
---

Three transports for one command surface. All three satisfy the ``CliSession``
protocol — and so does the mock's in-process CLI face.

.. automodule:: netgear_switch.transport.cli

.. automodule:: netgear_switch.transport.cli.session

.. automodule:: netgear_switch.transport.cli.ssh

.. automodule:: netgear_switch.transport.cli.telnet

.. automodule:: netgear_switch.transport.cli.console
