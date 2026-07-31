Protocol layer
==============

Pure protocol knowledge: OIDs, packet formats, endpoint specs, command strings,
and the parsers over their output. No sockets and no I/O — which is why almost
all of it is testable against captured bytes, and why the measurement notes for
each device behaviour live here in the source.

SNMP
----

.. automodule:: netgear_switch.protocols.snmp

.. automodule:: netgear_switch.protocols.snmp.oids

.. automodule:: netgear_switch.protocols.snmp.parse

.. automodule:: netgear_switch.protocols.snmp.client

.. automodule:: netgear_switch.protocols.snmp.write

NSDP
----

.. automodule:: netgear_switch.protocols.nsdp
   :no-members:

.. automodule:: netgear_switch.protocols.nsdp.protocol

.. automodule:: netgear_switch.protocols.nsdp.types

.. automodule:: netgear_switch.protocols.nsdp.auth

.. automodule:: netgear_switch.protocols.nsdp.parsers

.. automodule:: netgear_switch.protocols.nsdp.client

.. automodule:: netgear_switch.protocols.nsdp.write

HTTP web UI
-----------

.. automodule:: netgear_switch.protocols.http

.. automodule:: netgear_switch.protocols.http.endpoints

.. automodule:: netgear_switch.protocols.http.parse

.. automodule:: netgear_switch.protocols.http.forms

.. automodule:: netgear_switch.protocols.http.crypt

.. automodule:: netgear_switch.protocols.http.session

.. automodule:: netgear_switch.protocols.http.types

FASTPATH CLI
------------

.. automodule:: netgear_switch.protocols.cli

.. automodule:: netgear_switch.protocols.cli.commands

.. automodule:: netgear_switch.protocols.cli.parse
