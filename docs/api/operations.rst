Backend operations
==================

The model-driven readers and writers: one pair per backend, each mapping a
facade call to that protocol's mechanism for that model. Every one can be
constructed directly and pointed at a client of your choosing — including one
aimed at the :doc:`virtual switch <../fake/index>`.

SNMP
----

.. automodule:: netgear_switch.snmp_read

.. automodule:: netgear_switch.snmp_write

NSDP
----

.. automodule:: netgear_switch.nsdp_read

.. automodule:: netgear_switch.nsdp_write

HTTP web UI
-----------

.. automodule:: netgear_switch.http_read

.. automodule:: netgear_switch.http_write

FASTPATH CLI
------------

.. automodule:: netgear_switch.cli_read

.. automodule:: netgear_switch.cli_write
