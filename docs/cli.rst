``ngsw`` command line
=====================

``ngsw`` exposes the whole library from a shell: reads, writes, model discovery,
state capture, and the mock switch daemons.

.. code-block:: sh

   ngsw models                                              # no switch needed
   ngsw --host 10.1.5.22 --model gsm7252ps --community public ports
   ngsw --switch core vlans --json
   ngsw --switch core --backend http vlans

Selecting a switch
------------------

Two ways; pick exactly one:

**From an inventory** — ``--switch NAME`` together with ``--config
<inventory.toml>``; ``--switch`` without ``--config`` is an error. Credentials
and protected ports come with the entry. See :doc:`guide/configuration`.

**Ad hoc** — ``--host HOST --model KEY`` together, with credentials from flags,
environment variables, or an interactive prompt.

Credential precedence is **flag → environment variable → inventory → prompt**,
and the prompt is only reached for a credential the chosen backend actually
needs: a Plus switch reached over NSDP is never asked for an SNMP community.

Choosing the protocol
---------------------

``--backend snmp|nsdp|http|ssh|telnet|console`` runs the operation over exactly
that protocol. If it cannot serve the operation, the command fails saying so; it
is never re-routed. Without the flag, the model's default backend is used — see
:doc:`guide/concepts`.

Output
------

Human-readable tables by default; ``--json`` emits machine-readable JSON.
``-v``/``--verbose`` prints tracebacks instead of one-line error messages.

Write safety
------------

Every disruptive subcommand carries the same three gates:

``--dry-run``
    Print the operation that would be sent, and send nothing. The description is
    at facade granularity — method, arguments, host — rather than a re-encoded
    SNMP SET or HTTP form, so it cannot drift from what would really happen.

``-y`` / ``--yes``
    Skip the interactive confirmation.

``--force``
    Override ``protected_ports`` and the other force gates.

.. code-block:: sh

   ngsw --switch core port 7 down --dry-run
   ngsw --switch core vlan create 4001 throwaway --yes
   ngsw --switch core vlan set 4001 7 tagged --force

Exit status is ``0`` on success and non-zero on error; a refused operation is an
error, not a silent no-op.

Complete reference
------------------

Generated from the parser in ``src/netgear_switch/cli/main.py``, so it lists
every command and option the installed version actually accepts.

.. argparse::
   :module: netgear_switch.cli.main
   :func: build_parser
   :prog: ngsw

Recipes
-------

**Sweep an inventory for link state**

.. code-block:: sh

   for name in core edge lab; do
     echo "== $name"
     ngsw --switch "$name" ports --json | jq -r '.[] | select(.link_up) | .port'
   done

**Compare two protocols on the same switch**

.. code-block:: sh

   ngsw --switch core --backend snmp vlans --json > snmp.json
   ngsw --switch core --backend http vlans --json > http.json
   diff <(jq -S . snmp.json) <(jq -S . http.json)

Any difference is a real difference between what the two interfaces report —
neither answer is a fallback from the other.

**Identify an unknown switch**

.. code-block:: sh

   ngsw --host 10.1.5.99 --model gsm7252ps --community public identify

The ``--model`` is only a placeholder to carry the host and credentials;
``identify`` ignores it and asks the switch.

**Capture a switch's full state**

.. code-block:: sh

   ngsw --switch core capture core-2026-07-31.json

This is how the project's fixtures and mock seeds are produced — see
:doc:`fake/internals`.

**Run mock switches for another tool to talk to**

.. code-block:: sh

   ngsw serve --model gsm7228ps --model gs305ep

See :doc:`fake/serving`.
