Installation
============

Requires **Python 3.11 or newer**.

From PyPI
---------

.. code-block:: sh

   pip install python-netgear-switch-library
   # or
   uv add python-netgear-switch-library

The base install has one runtime dependency, :pypi:`cryptography`, used by the
HTTPS-certificate upload path to convert an RSA private key to the PKCS#1
"traditional" form the GS728TPP firmware requires — without shelling out to
``openssl``.

Extras
------

Each backend's *transport* is optional, so an SNMP-only deployment does not pull
in an HTTP stack, and vice versa.

.. list-table::
   :header-rows: 1
   :widths: 14 30 56

   * - Extra
     - Installs
     - Needed for
   * - ``[async]``
     - :pypi:`pysnmp`
     - The asynchronous SNMP transport used by :py:obj:`~netgear_switch.aio_api.AsyncSwitch`.
   * - ``[http]``
     - :pypi:`httpx`
     - Every web-UI backend, synchronous and asynchronous.
   * - ``[ssh]``
     - :pypi:`paramiko` (<3), :pypi:`pyserial`
     - The FASTPATH CLI over SSH and over a serial console.
   * - ``[mcp]``
     - :pypi:`mcp`
     - The ``ngsw-mcp`` server (see :doc:`../mcp`).
   * - ``[docs]``
     - Sphinx and every optional dependency
     - Building this documentation.

.. code-block:: sh

   pip install 'python-netgear-switch-library[async,http,ssh]'

.. note::

   ``paramiko`` is pinned below 3.0 deliberately. The FASTPATH firmware on the
   GSM7252PS and M4300 only offers ``diffie-hellman-group14-sha1`` key exchange
   and an ``ssh-rsa`` (SHA-1) host key, both of which paramiko 3.0 dropped from
   its defaults. The SSH transport also re-inserts those algorithms explicitly,
   so the pin is belt-and-braces — see ``src/netgear_switch/transport/cli/ssh.py``.

The net-snmp system dependency
------------------------------

The **synchronous** SNMP transport shells out to the net-snmp command-line
tools rather than binding a Python SNMP library. Those tools are a system
package, not a Python dependency:

.. code-block:: sh

   sudo apt install snmp     # provides snmpget, snmpbulkwalk, snmpset

Without them, synchronous SNMP operations fail; NSDP, HTTP and CLI backends are
unaffected, as is the asynchronous SNMP transport, which uses :pypi:`pysnmp`
from the ``[async]`` extra.

Debian and Ubuntu
-----------------

Signed ``.deb`` packages for Debian **trixie** and **sid** are published to a
GitHub Pages apt repository:

.. code-block:: sh

   sudo install -d -m0755 /etc/apt/keyrings
   curl -fsSL https://mith.ro/python-netgear-switch-library/netgear-switch.gpg \
     | sudo tee /etc/apt/keyrings/netgear-switch.gpg > /dev/null

   # trixie:
   echo "deb [signed-by=/etc/apt/keyrings/netgear-switch.gpg] https://mith.ro/python-netgear-switch-library/trixie/ ./" \
     | sudo tee /etc/apt/sources.list.d/netgear-switch.list
   # sid:
   echo "deb [signed-by=/etc/apt/keyrings/netgear-switch.gpg] https://mith.ro/python-netgear-switch-library/sid/ ./" \
     | sudo tee /etc/apt/sources.list.d/netgear-switch.list

   sudo apt update
   sudo apt install python3-netgear-switch-library

This installs the ``netgear_switch`` library and the ``ngsw`` CLI, and pulls in
the net-snmp tools automatically. The packaging lives in ``debian/`` and
``packaging/``.

Versioning
----------

A **rolling release**. The version is derived from ``git describe`` by
``hatch-vcs``: ``X.Y`` at a ``vX.Y`` tag, ``X.Y.postN`` N commits after it
(``0.1``, ``0.1.post1``, …). Every merge to ``main`` whose CI run is green
publishes to PyPI and to the apt repository — a red run publishes nothing. No
manual version bumps — see ``RELEASING.md``.

.. note::

   Because the version comes from git history, a *shallow* clone produces a
   wrong or failing version. Build systems that clone shallowly need
   ``git fetch --unshallow``; this documentation's own Read the Docs build does
   exactly that, in ``.readthedocs.yaml``.

Verifying the install
---------------------

.. code-block:: sh

   ngsw models        # lists every registered switch model
   ngsw --help

No switch is needed for either. To exercise a real protocol without hardware,
start a mock — see :doc:`../fake/serving`.
