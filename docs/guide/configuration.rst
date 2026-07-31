Inventories and credentials
===========================

Hosts, models and credentials belong in an inventory file, not in your code or
your shell history. `load_inventory` reads a TOML file into
``{name: SwitchConfig}``; the ``ngsw`` CLI and the MCP server both use it, via
the same resolver.

The inventory file
------------------

.. code-block:: toml

   [switches.core]
   model = "gsm7252ps"
   host = "10.1.5.22"
   protected_ports = [1, 2, 49, 50, 51, 52]

   [switches.core.snmp]
   community = "public"
   write_community = "!pass show netgear/core"

   [switches.core.http]
   password = "${CORE_WEB_PASSWORD}"

   [switches.edge]
   model = "gs305ep"
   host = "10.1.5.28"

   [switches.edge.nsdp]
   interface = "eth0"

   [switches.edge.http]
   password = "${EDGE_PASSWORD}"

Per switch:

.. list-table::
   :header-rows: 1
   :widths: 26 12 62

   * - Key
     - Required
     - Meaning
   * - ``model``
     - yes
     - A registry key or alias; see ``ngsw models``.
   * - ``host``
     - yes
     - Address or hostname of the switch.
   * - ``protected_ports``
     - no
     - Ports a write refuses to touch without ``force=True``. Put your uplinks
       and your management port here.
   * - ``snmp.community``
     - no
     - SNMP **read** community.
   * - ``snmp.write_community``
     - no
     - SNMP **write** community — a *secret spec* (below).
   * - ``http.password``
     - no
     - Web-UI admin password — a secret spec. On Plus switches this same secret
       is also the NSDP v1 admin password.
   * - ``nsdp.interface``
     - no
     - Interface to send NSDP from, e.g. ``eth0``. NSDP is broadcast-based, so
       on a multi-homed host this matters.

Secret specs
------------

Any value marked "secret spec" above is resolved by `resolve_secret`, which
accepts three forms:

.. list-table::
   :header-rows: 1
   :widths: 24 76

   * - Form
     - Behaviour
   * - ``${NAME}``
     - Read environment variable ``NAME``. `CredentialError` if unset.
   * - ``!command args``
     - Run the command (split with ``shlex``, no shell) and take its stdout,
       stripped. A 10-second timeout; a non-zero exit raises `CredentialError`
       with the command's stderr.
   * - anything else
     - The literal secret.

Prefer the first two. **If any secret in the file is a literal, the file's
permissions are checked** and `load_inventory` raises `ConfigError` unless the
file is unreadable by group and other:

.. code-block:: text

   ConfigError: inventory.toml has insecure permissions 0o644; chmod 600 it
   (contains a literal secret)

That check is `ensure_secure_file`, and it only fires when a literal is present
— a file containing only ``${VAR}`` and ``!command`` specs needs no special
mode.

Secrets are resolved **lazily**, at the moment an operation needs them. Reading
port status over SNMP never runs your password command.

Using an inventory
------------------

.. code-block:: python

   from netgear_switch import SyncSwitch, load_inventory

   inventory = load_inventory("/etc/ngsw/inventory.toml")
   switch = SyncSwitch.from_config(inventory["core"])

   print(switch.get_ports())

`SwitchConfig.snmp_write_community` and `SwitchConfig.http_password` resolve
their specs on demand and take an explicit ``env=`` mapping, which makes them
straightforward to test.

From the CLI
------------

.. code-block:: sh

   ngsw --config /etc/ngsw/inventory.toml --switch core ports
   export NGSW_INVENTORY=/etc/ngsw/inventory.toml
   ngsw --switch core ports

Credential precedence is **command-line flag → environment variable → inventory
→ interactive prompt**, implemented in ``src/netgear_switch/cli/resolve.py``:

.. list-table::
   :header-rows: 1
   :widths: 30 30 40

   * - Credential
     - Flag
     - Environment variable
   * - SNMP read community
     - ``--community``
     - ``NGSW_COMMUNITY``
   * - SNMP write community
     - ``--write-community``
     - ``NGSW_WRITE_COMMUNITY``
   * - Web UI / NSDP password
     - ``--http-password``
     - —
   * - Inventory path
     - ``--config``
     - ``NGSW_INVENTORY``

The prompt is only reached for a backend that actually needs the secret: a
Plus switch reached over NSDP is never asked for an SNMP community.

Protected ports
---------------

``protected_ports`` is enforced by the library, not just the CLI. Every write
that names a port checks it and raises `ProtectedPortError` unless
``force=True``:

.. code-block:: python

   switch = SyncSwitch(
       get_model("gsm7252ps"), host="10.1.5.22",
       protected_ports=frozenset({49, 50, 51, 52}),
   )
   switch.set_port_enabled(49, False)               # ProtectedPortError
   switch.set_port_enabled(49, False, force=True)   # proceeds

It is the cheapest possible guard against disabling the uplink you are
connected through.
