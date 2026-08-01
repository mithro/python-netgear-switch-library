FASTPATH CLI
============

The switch's own command line, as an ordinary backend: ``show`` commands for
reads, configuration-mode sequences for writes.

Switches that speak it
----------------------

.. ngsw-backend-models:: CLI

Note the transport column: three of these offer SSH, and the S3300 is telnet
only, on a non-standard port.

What it can do, per switch
--------------------------

.. ngsw-backend-operations:: CLI

Three transports, one command surface
-------------------------------------

.. list-table::
   :header-rows: 1
   :widths: 16 30 54

   * - Transport
     - Class
     - Notes
   * - SSH
     - ``SshCliTransport``
     - The default for a model that has it. Needs :pypi:`paramiko` from the
       ``[ssh]`` extra.
   * - Telnet
     - ``TelnetCliTransport``
     - Used automatically for a model with telnet but no SSH. The port comes
       from the model's spec.
   * - Serial console
     - ``ConsoleCliTransport``
     - The same CLI over a serial line, via :pypi:`pyserial`. Never selected
       automatically — it needs a device path, not a host — so construct it and
       pass it as ``cli_client=``.

All three satisfy the ``CliSession`` protocol, so `CliReader` and `CliWriter`
work unchanged across them, and equally against the mock CLI face.

.. note::

   ``Backend.CONSOLE`` is therefore not registered on any model: it is a
   transport for the CLI backend, not a network-reachable backend of its own.
   Asking for it via ``backend=`` raises, and the support tables say why.

Two transport facts learned the hard way
-----------------------------------------

**The S3300 listens on telnet port 60000**, not 23, and runs no SSH listener on
any port — its own ``tcpConnTable`` shows only 80, 443 and 60000. Its CLI
backend is telnet only, and the transport dials the port from its spec rather
than the default.

**Old FASTPATH needs legacy SSH algorithms.** The GSM7252PS and M4300 offer only
``diffie-hellman-group14-sha1`` key exchange and an ``ssh-rsa`` (SHA-1) host key,
both dropped from paramiko 3.0's defaults. The dependency is pinned below 3.0
*and* the transport re-inserts those algorithms explicitly.

Commands per model
------------------

Every command is a field on a ``CliModelSpec`` — the ``show`` command for each
read, the configuration sequence for each write, and the interface-name template
(``1/0/{port}``, with a separate template for uplink ports where a model needs
one). Overriding one field is how a model that words a command differently is
supported, without forking the reader.

Reads map to ``show`` commands: port status, VLAN brief and per-VLAN detail,
PVIDs, MAC address table, LLDP remote devices, PoE port info, environment, and
network. Writes drive the real configuration sequences — ``vlan database``,
``configure`` / ``interface`` / ``vlan participation`` / ``vlan tagging`` /
``vlan pvid``, ``poe`` and ``no poe``, ``shutdown`` and ``no shutdown``.

.. warning::

   ``get_stats`` costs **one round trip per port**: FASTPATH has no "all ports"
   counter command, so counters come from a per-port
   ``show interface ethernet 1/0/<n>``. On a 52-port switch that is 52 commands.
   Prefer SNMP for statistics where the model has it.

   The port list is taken from the switch's own ``show port all``, not from the
   registry's ``port_count`` — which is a nominal value that can exceed the
   physical port count. Iterating the nominal range issued doomed queries for
   ports that do not exist and fabricated empty counters for them.

Verification gates
------------------

``CliModelSpec.reads_verified`` and ``writes_verified`` gate live dispatch
exactly as the HTTP flags do. ``writes_verified`` requires ``reads_verified``,
and not incidentally: every CLI write confirms itself by reading back through
`CliReader`, so a model whose CLI reads are not trusted cannot honestly verify a
CLI write either.

The readers themselves are *not* gated — they can always be constructed
directly, which is what the mock tests do. It is the facade that refuses.

Certificate deployment
----------------------

The Fully Managed FASTPATH line takes an HTTPS certificate over SCP rather than
an HTTP form. `SyncSwitch.upload_certificate_scp` runs the real sequence:
disable HTTPS, ``copy scp://<source> nvram:sslpem-server``, optionally the root
chain, re-enable HTTPS to load it, save the configuration. No reboot.

The certificate files must be staged on the SCP source first; the switch pulls
them. See :doc:`../guide/writing`.

Using the CLI backend
---------------------

.. code-block:: python

   from netgear_switch import Backend, SyncSwitch, get_model

   switch = SyncSwitch(
       get_model("gsm7252ps"), host="10.1.5.22", http_password="...",
   )
   vlans = switch.get_vlans(backend=Backend.SSH)

The CLI password defaults to the web-admin password and the username to
``admin``. The session is **lazy**: it is not opened until a command is actually
needed, so an operation the reader refuses outright — PoE on a switch with no
PSE ports — raises `UnsupportedCapabilityError` without ever dialling, rather
than a spurious `CredentialError` for a password it was never going to use.

Pass your own session with ``cli_client=`` to use the serial console, to reuse a
connection, or to point at the mock:

.. code-block:: python

   from netgear_switch.virtual.server import VirtualSwitch

   with VirtualSwitch(model="gsm7252ps") as mock:
       switch = SyncSwitch(
           get_model("gsm7252ps"), host="127.0.0.1",
           cli_client=mock.cli_session(),
       )
       print(switch.get_vlans(backend=Backend.SSH))

API
---

* `netgear_switch.cli_read` — `CliReader`.
* `netgear_switch.cli_write` — `CliWriter` and the SCP certificate flow.
* `netgear_switch.protocols.cli.commands` — the per-model command specs.
* `netgear_switch.protocols.cli.parse` — pure parsers over command output.
* `netgear_switch.transport.cli.session` — the ``CliSession`` protocol.
