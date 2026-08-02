Running mock switches
=====================

``ngsw serve`` runs the mocks as long-lived daemons on real sockets, so any
tool — in any language — can talk to one when hardware is unavailable.

.. code-block:: sh

   ngsw serve --model gsm7228ps                     # one model
   ngsw serve --model gsm7228ps --model gs305ep     # several
   ngsw serve --all                                 # every registered model

Each switch that comes up prints its model, bind address, the port it actually
bound for each protocol, and the credentials it accepts. The command then blocks
until interrupted, stopping every switch cleanly.

.. code-block:: text

   [m4300-24x] host=127.0.0.1
       SNMP udp/46382
       HTTP tcp/41507
       community='public' http_password='password'
   [gs110emx] host=127.0.0.1
       NSDP udp/54443
       HTTP tcp/40875
       community='public' http_password='password'
   [m7300] host=127.0.0.1
       SNMP udp/55530
       community='public' http_password='password'
   serving 10 mock switch(es); press Ctrl-C to stop

The model's registry entry decides which faces bind, which is why the GS110EMX
above offers NSDP and HTTP while the M7300 offers only SNMP — the mocks have
exactly the backends the real switches have.

Options
-------

.. list-table::
   :header-rows: 1
   :widths: 26 74

   * - Option
     - Meaning
   * - ``--model KEY``
     - Model to serve; repeatable. ``ngsw models`` lists the keys.
   * - ``--all``
     - Serve every registered model.
   * - ``--host IP``
     - Bind address, default ``127.0.0.1``. Use ``0.0.0.0`` to expose the mock
       to other hosts.
   * - ``--community STR``
     - SNMP community the mock accepts, default ``public``.
   * - ``--http-password STR``
     - Web-UI password the mock accepts, default ``password``.
   * - ``--port N`` / ``--http-port N``
     - Pin the UDP (SNMP or NSDP) and TCP (HTTP) ports instead of using
       ephemeral ones.

.. note::

   A pinned port is a single listener, so ``--port``/``--http-port`` are only
   accepted when serving exactly one model. When serving several, leave them
   unset and read the printed ports.

One bad model never takes the fleet down: a switch that cannot bind is reported
and skipped, and the rest keep serving.

Pointing tools at it
--------------------

SNMP
~~~~

Any SNMP client works, because the face is a real agent on a real UDP socket:

.. code-block:: sh

   ngsw serve --model gsm7228ps --port 16161 &

   snmpget -v2c -c public 127.0.0.1:16161 1.3.6.1.2.1.1.1.0
   snmpwalk -v2c -c public 127.0.0.1:16161 1.3.6.1.2.1.1
   snmpbulkwalk -v2c -c public 127.0.0.1:16161 1.3.6.1.2.1.2.2.1.8

.. code-block:: text

   iso.3.6.1.2.1.1.1.0 = STRING: "S3300-52X-PoE+ ProSAFE 48-Port Gigabit
   Stackable Smart Switch with PoE+ and 4 10G uplinks"
   iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.4526.100.10.19

That ``sysDescr`` is the real switch's, from a capture — which is what makes the
mock useful for testing model detection, not just data parsing.

SNMP writes work too, and so do the refusals:

.. code-block:: sh

   snmpset -v2c -c public 127.0.0.1:16161 1.3.6.1.2.1.2.2.1.7.1 i 2

NSDP
~~~~

The NSDP face answers on the printed UDP port. Because NSDP is normally
broadcast to port 63322, a client usually needs to be told where to send;
this library's own transport takes the port directly, and third-party tools have
been driven against it over a veth pair in a network namespace.

HTTP
~~~~

The HTTP face serves the model's real page set, so ``curl`` reaches it directly:

.. code-block:: sh

   ngsw serve --model gs305ep --http-port 18080 &
   curl -s http://127.0.0.1:18080/dashboard.cgi

.. code-block:: text

   <html><body><input type="hidden" name="hash" value="virtualhash"><table>
   <tr class="portID"><td><input type="checkbox"></td><td>1</td><td>Up 1000M</td>
   <td>Enabled</td><td>Port 1</td></tr>...

The login endpoint is served too, and the mock validates the posted password.
Login *paths and fields differ per model* — the GS305EP posts to ``/login.cgi``
while the S3300 uses ``/base/cheetah_login.html`` — so a tool that hard-codes one
model's flow will not work against another, exactly as with real switches.

.. warning::

   **Known deviation.** The HTTP face validates the login POST, and reproduces
   the M4300's ``Referer``-header CSRF check (answering 403 without it), but it
   does **not** require a prior session for ordinary page ``GET``\ s. Real
   firmware does. If what you are testing is your tool's session handling —
   login, expiry, re-login — the mock will be more permissive than the device.
   Everything else about the pages is faithful.

The FASTPATH CLI
~~~~~~~~~~~~~~~~

The CLI face is deliberately **in-process**: it implements the ``CliSession``
protocol rather than binding an SSH or telnet listener, so there is no key
exchange or terminal emulation to fight. Reach it through
:py:obj:`~netgear_switch.virtual.server.VirtualSwitch.cli_session`, not over a socket; ``ngsw serve`` therefore does
not expose it. See :doc:`testing`.

This library against a mock
---------------------------

``ngsw`` itself is a perfectly good external tool:

.. code-block:: sh

   ngsw serve --model gsm7228ps --port 16161 &
   ngsw --host '127.0.0.1:16161' --model gsm7228ps --community public ports

Running one in CI
-----------------

Start it in the background, wait for the port, run your tests, stop it:

.. code-block:: yaml

   # .github/workflows/test.yml
   - name: Start a mock Netgear switch
     run: |
       pip install python-netgear-switch-library
       ngsw serve --model gsm7228ps --port 16161 --http-port 18080 &
       for _ in $(seq 1 50); do
         nc -z -u 127.0.0.1 16161 && break
         sleep 0.2
       done

   - name: Test against it
     run: pytest
     env:
       SWITCH_HOST: 127.0.0.1:16161

For pytest specifically, an in-process fixture is simpler and faster than a
subprocess — see :doc:`testing`.
