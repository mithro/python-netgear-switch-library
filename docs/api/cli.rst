Command-line implementation
===========================

The modules behind the ``ngsw`` entry point. The user-facing reference is
:doc:`../cli`; this documents the implementation, which is worth reading if you
are embedding ``ngsw``'s switch resolution or its write gates in your own tool.

Entry point
-----------

.. automodule:: netgear_switch.cli.main

Switch and credential resolution
--------------------------------

The shared path the CLI *and* the MCP server both use to turn arguments,
environment variables and an inventory into a ready `SyncSwitch`.

.. automodule:: netgear_switch.cli.resolve

.. automodule:: netgear_switch.cli.context

Write safety
------------

The single gate every disruptive subcommand passes through: dry-run, confirm,
execute, report.

.. automodule:: netgear_switch.cli.safety

Output and capture
------------------

.. automodule:: netgear_switch.cli.format

.. automodule:: netgear_switch.cli.capture
